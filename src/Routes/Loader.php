<?php

namespace Tualo\Office\ModSecurityLog\Routes;

use Tualo\Office\Basic\TualoApplication as App;
use Tualo\Office\Basic\Route as BasicRoute;
use Tualo\Office\Basic\RouteSecurityHelper;

class Loader extends \Tualo\Office\Basic\RouteWrapper
{
    public static function register()
    {
        BasicRoute::add('/js/modsecuritylog/(?P<lib>[\w.\-]+)/(?P<file>[\w.\/\-]+)', function ($matches) {
            $path = dirname(__DIR__, 1) . '/js/lazy';
            if (file_exists($path . '/' . $matches['file'])) {
                RouteSecurityHelper::serveSecureStaticFile(
                    $matches['file'],
                    $path . '/',
                    ['js', 'css'],
                    ['js' => 'application/javascript', 'css' => 'text/css']
                );
            }
        }, ['get'], true);
    }
}
