<?php

namespace Tualo\Office\ModSecurityLog\Routes;

use Tualo\Office\Basic\TualoApplication as App;
use Tualo\Office\Basic\Route as BasicRoute;
use Tualo\Office\ModSecurityLog\ModSecurityAuditLogParser;
use Tualo\Office\ModSecurityLog\Scopes\ModSecurityLogScope;

class Read extends \Tualo\Office\Basic\RouteWrapper
{
    public static function scope(): string
    {
        return ModSecurityLogScope::identifier();
    }

    public static function register()
    {
        BasicRoute::add('/modsecuritylog/read', function ($matches) {
            App::contenttype('application/json');
            try {
                $path = App::configuration(
                    'modsecuritylog',
                    'auditlog',
                    '/var/log/apache2/modsec_audit.log'
                );
                $limit = (int)($_REQUEST['limit'] ?? 500);
                if ($limit < 1) $limit = 1;
                if ($limit > 5000) $limit = 5000;

                $maxBytes = (int)App::configuration('modsecuritylog', 'maxbytes', 4194304);

                $entries = ModSecurityAuditLogParser::parseFile($path, $limit, $maxBytes);

                App::result('data', $entries);
                App::result('total', count($entries));
                App::result('logfile', $path);
                App::result('success', true);
            } catch (\Exception $e) {
                App::result('success', false);
                App::result('msg', $e->getMessage());
            }
        }, ['get', 'post'], true, [], self::scope());
    }
}
