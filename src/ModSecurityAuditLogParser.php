<?php

namespace Tualo\Office\ModSecurityLog;

/**
 * Parser für das serielle ModSecurity-Audit-Log (SecAuditLogType Serial).
 *
 * Ein Eintrag besteht aus Abschnitten, die durch Boundaries der Form
 *   --<id>-<SECTION>--
 * getrennt sind. Ausgewertet werden:
 *   A = Audit-Header (Zeitstempel, Unique-ID, Client-IP)
 *   B = Request-Header (Request-Zeile, Host, Referer, User-Agent)
 *   F = Response-Header (HTTP-Status)
 *   H = Audit-Trailer (Message-Zeilen mit Regel-Treffern, Action)
 */
class ModSecurityAuditLogParser
{
    private const SEVERITIES = [
        '0' => 'EMERGENCY',
        '1' => 'ALERT',
        '2' => 'CRITICAL',
        '3' => 'ERROR',
        '4' => 'WARNING',
        '5' => 'NOTICE',
        '6' => 'INFO',
        '7' => 'DEBUG',
    ];

    /**
     * Liest die letzten $maxBytes des Logs und liefert maximal $limit
     * Einträge, neueste zuerst.
     */
    public static function parseFile(string $path, int $limit = 500, int $maxBytes = 4194304): array
    {
        if (!is_file($path)) {
            throw new \Exception('audit log not found: ' . $path);
        }
        if (!is_readable($path)) {
            throw new \Exception('audit log not readable: ' . $path);
        }

        $size = filesize($path);
        $offset = max(0, $size - $maxBytes);
        $fp = fopen($path, 'r');
        if ($fp === false) {
            throw new \Exception('could not open audit log: ' . $path);
        }
        if ($offset > 0) {
            fseek($fp, $offset);
        }
        $content = stream_get_contents($fp);
        fclose($fp);
        if ($content === false) {
            throw new \Exception('could not read audit log: ' . $path);
        }

        $entries = self::parseString($content, $offset > 0);
        $entries = array_reverse($entries);
        if (count($entries) > $limit) {
            $entries = array_slice($entries, 0, $limit);
        }
        return $entries;
    }

    /**
     * Zerlegt den Log-Inhalt in Einträge.
     *
     * @param bool $skipFirstPartial true, wenn der Inhalt mitten in einem
     *                               Eintrag beginnen kann (Tail-Read)
     */
    public static function parseString(string $content, bool $skipFirstPartial = false): array
    {
        $entries = [];
        $current = null;   // boundary id des aktuellen Eintrags
        $section = null;
        $sections = [];

        $lines = preg_split("/\r\n|\n|\r/", $content);
        $firstBoundarySeen = false;

        foreach ($lines as $line) {
            if (preg_match('/^--([0-9a-fA-F@-]+)-([A-Z])--$/', $line, $m)) {
                $firstBoundarySeen = true;
                if ($m[2] === 'Z') {
                    if (!is_null($current)) {
                        $entry = self::buildEntry($current, $sections);
                        if (!is_null($entry)) {
                            $entries[] = $entry;
                        }
                    }
                    $current = null;
                    $section = null;
                    $sections = [];
                } else {
                    if ($current !== $m[1]) {
                        // neuer Eintrag beginnt (ggf. ohne Z des Vorgängers)
                        $current = $m[1];
                        $sections = [];
                    }
                    $section = $m[2];
                    $sections[$section] = [];
                }
                continue;
            }
            if ($skipFirstPartial && !$firstBoundarySeen) {
                continue; // angeschnittener Eintrag am Anfang des Tail-Reads
            }
            if (!is_null($current) && !is_null($section)) {
                $sections[$section][] = $line;
            }
        }
        return $entries;
    }

    private static function buildEntry(string $id, array $sections): ?array
    {
        if (!isset($sections['A'])) {
            return null;
        }

        $entry = [
            'unique_id' => '',
            'timestamp' => '',
            'client_ip' => '',
            'method' => '',
            'uri' => '',
            'host' => '',
            'referer' => '',
            'user_agent' => '',
            'status' => null,
            'intercepted' => false,
            'engine_mode' => '',
            'inbound_score' => null,
            'rule_ids' => [],
            'max_severity' => '',
            'messages' => [],
        ];

        // Abschnitt A: [07/Nov/2026:08:44:00.123456 +0000] uniqueid ip port ip port
        foreach ($sections['A'] as $line) {
            if (preg_match('/^\[([^\]]+)\]\s+(\S+)\s+(\S+)\s+(\d+)/', $line, $m)) {
                $entry['timestamp'] = self::normalizeTimestamp($m[1]);
                $entry['unique_id'] = $m[2];
                $entry['client_ip'] = $m[3];
                break;
            }
        }

        // Abschnitt B: Request-Zeile + Header
        if (isset($sections['B'])) {
            foreach ($sections['B'] as $i => $line) {
                if ($i === 0 && preg_match('/^(\S+)\s+(\S+)/', $line, $m)) {
                    $entry['method'] = $m[1];
                    $entry['uri'] = $m[2];
                    continue;
                }
                if (preg_match('/^Host:\s*(.+)$/i', $line, $m)) {
                    $entry['host'] = trim($m[1]);
                } elseif (preg_match('/^Referer:\s*(.+)$/i', $line, $m)) {
                    $entry['referer'] = trim($m[1]);
                } elseif (preg_match('/^User-Agent:\s*(.+)$/i', $line, $m)) {
                    $entry['user_agent'] = trim($m[1]);
                }
            }
        }

        // Abschnitt F: HTTP/1.1 403 Forbidden
        if (isset($sections['F'])) {
            foreach ($sections['F'] as $line) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                    $entry['status'] = (int)$m[1];
                    break;
                }
            }
        }

        // Abschnitt H: Message-Zeilen, Action, Engine-Mode
        $maxSeverity = 99;
        if (isset($sections['H'])) {
            foreach ($sections['H'] as $line) {
                if (preg_match('/^Message:\s*(.+)$/', $line, $m)) {
                    $msg = self::parseMessage($m[1]);
                    $entry['messages'][] = $msg;
                    if ($msg['id'] !== '') {
                        $entry['rule_ids'][] = $msg['id'];
                    }
                    if ($msg['severity_level'] !== null && $msg['severity_level'] < $maxSeverity) {
                        $maxSeverity = $msg['severity_level'];
                        $entry['max_severity'] = $msg['severity'];
                    }
                    if (
                        is_null($entry['inbound_score'])
                        && preg_match('/Total Inbound Score:\s*(\d+)/', $msg['msg'] . ' ' . $msg['data'], $s)
                    ) {
                        $entry['inbound_score'] = (int)$s[1];
                    }
                } elseif (preg_match('/^Action:\s*Intercepted/i', $line)) {
                    $entry['intercepted'] = true;
                } elseif (preg_match('/^Engine-Mode:\s*"?([^"]+)"?/', $line, $m)) {
                    $entry['engine_mode'] = trim($m[1]);
                }
            }
        }
        $entry['rule_ids'] = array_values(array_unique($entry['rule_ids']));
        return $entry;
    }

    /**
     * Zerlegt eine Message-Zeile in Freitext und die [key "value"]-Paare.
     */
    public static function parseMessage(string $raw): array
    {
        $msg = [
            'text' => '',
            'file' => '',
            'line' => '',
            'id' => '',
            'msg' => '',
            'data' => '',
            'severity' => '',
            'severity_level' => null,
            'ver' => '',
            'tags' => [],
            'raw' => $raw,
        ];

        $bracketPos = strpos($raw, ' [');
        $msg['text'] = $bracketPos === false ? $raw : substr($raw, 0, $bracketPos);

        if (preg_match_all('/\[(\w+)\s+"((?:[^"\\\\]|\\\\.)*)"\]/', $raw, $all, PREG_SET_ORDER)) {
            foreach ($all as $pair) {
                $key = $pair[1];
                $value = stripcslashes($pair[2]);
                if ($key === 'tag') {
                    $msg['tags'][] = $value;
                } elseif ($key === 'severity') {
                    if (isset(self::SEVERITIES[$value])) {
                        $msg['severity'] = self::SEVERITIES[$value];
                        $msg['severity_level'] = (int)$value;
                    } else {
                        $msg['severity'] = $value;
                        $lookup = array_search(strtoupper($value), self::SEVERITIES);
                        $msg['severity_level'] = $lookup === false ? null : (int)$lookup;
                    }
                } elseif (array_key_exists($key, $msg) && !is_array($msg[$key])) {
                    $msg[$key] = $value;
                }
            }
        }
        return $msg;
    }

    private static function normalizeTimestamp(string $ts): string
    {
        // Format: 07/Nov/2026:08:44:00.123456 +0000 oder ohne Mikrosekunden
        $formats = ['d/M/Y:H:i:s.u P', 'd/M/Y:H:i:s P'];
        foreach ($formats as $format) {
            $dt = \DateTime::createFromFormat($format, $ts);
            if ($dt !== false) {
                return $dt->format('Y-m-d H:i:s');
            }
        }
        return $ts;
    }
}
