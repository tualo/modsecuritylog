# tualo/modsecuritylog

ModSecurity Audit-Log Viewer für tualo office.

Stellt die Einträge des seriellen ModSecurity-Audit-Logs (`SecAuditLog`,
Format *Serial*) für Frontend-Benutzer mit dem Scope `modsecuritylog`
aufbereitet dar: Zeitpunkt, Client, Request, HTTP-Status, Anomaly-Score,
ausgelöste CRS-Regeln inkl. Meldungen, Severity und Tags.

## Scope

Der Zugriff ist über den Scope **`modsecuritylog`** geschützt. Der Scope wird
über `install-sql-bsc-scopes` registriert und muss dem Benutzer bzw. der
Gruppe zugewiesen werden.

## Routen

| Route | Methode | Beschreibung |
| --- | --- | --- |
| `/modsecuritylog/read` | GET/POST | Liefert die letzten Audit-Log-Einträge als JSON (`limit`, Default 500, max. 5000) |
| `/modsecuritylog/access` | GET | Scope-Check für das Frontend |
| `/js/modsecuritylog/lazy/...` | GET | Lazy-Loading der ExtJS-Views |

## Frontend

Panel über die Hash-Route `#modsecuritylog/panel` (Eintrag „ModSecurity Log").
Grid mit Filterung (URI, IP, Host, Regel-ID, Blockiert, Severity) und
Detailansicht aller Regel-Treffer des gewählten Eintrags.

## Konfiguration

Optional in der Anwendungs-Konfiguration:

```json
{
  "modsecuritylog": {
    "auditlog": "/var/log/apache2/modsec_audit.log",
    "maxbytes": 4194304
  }
}
```

- `auditlog`: Pfad zum seriellen Audit-Log (Default `/var/log/apache2/modsec_audit.log`)
- `maxbytes`: maximal gelesene Bytes vom Log-Ende (Default 4 MB)

## Voraussetzungen im Container

1. ModSecurity-Audit-Log aktiviert (`SecAuditEngine RelevantOnly`,
   `SecAuditLog /var/log/apache2/modsec_audit.log` — Teil der
   `modsecurity.conf` des tualo-server-Images).
2. Der PHP-FPM-User (`tualo`) braucht Leserechte auf das Log,
   z. B. über die Gruppe `adm`:

   ```dockerfile
   RUN usermod -aG adm tualo
   RUN touch /var/log/apache2/modsec_audit.log \
       && chown root:adm /var/log/apache2/modsec_audit.log \
       && chmod 640 /var/log/apache2/modsec_audit.log
   ```

   Die Debian-Logrotation für `/var/log/apache2/*.log` erzeugt rotierte
   Dateien ebenfalls mit `root:adm 640`.

