<?php

namespace Tualo\Office\ModSecurityLog\Scopes;

use Tualo\Office\Basic\Scope;

class ModSecurityLogScope extends Scope
{
    protected static string $identifier = 'modsecuritylog';
    protected static array $name = [
        'EN' => 'ModSecurity Log',
        'DE' => 'ModSecurity Log',
    ];
    protected static array $description = [
        'EN' => 'View ModSecurity audit log entries (WAF events).',
        'DE' => 'ModSecurity Audit-Log Einträge (WAF-Ereignisse) anzeigen.',
    ];
}
