<?php

namespace Tualo\Office\ModSecurityLog\Routes;

use Tualo\Office\Basic\TualoApplication as App;
use Tualo\Office\Basic\Route as BasicRoute;
use Tualo\Office\ModSecurityLog\Scopes\ModSecurityLogScope;

class CheckAccess extends \Tualo\Office\Basic\RouteWrapper
{
    public static function scope(): string
    {
        return ModSecurityLogScope::identifier();
    }

    public static function register()
    {
        BasicRoute::add('/modsecuritylog/access', function () {
            App::contenttype('application/json');
            App::result('success', true);
        }, ['get'], true, [], self::scope());
    }
}
