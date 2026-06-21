<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class CustomCors
{
    public function handle(Request $request, Closure $next): Response
    {
        $allowedOrigins = array_filter(
            array_map('trim', explode(',', config('app.frontend_url', 'http://localhost:5500')))
        );

        $origin = $request->headers->get('Origin');

        if ($origin && in_array($origin, $allowedOrigins)) {
            $allowOrigin = $origin;
        } elseif ($origin === 'null' || $origin === null) {
            // file:// protocol sends Origin: null – allow during development
            $allowOrigin = $allowedOrigins[0] ?? 'http://localhost:5500';
        } else {
            $allowOrigin = $allowedOrigins[0] ?? 'http://localhost:5500';
        }

        if ($request->isMethod('OPTIONS')) {
            return response('', 204)
                ->header('Access-Control-Allow-Origin', $allowOrigin)
                ->header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
                ->header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, X-XSRF-TOKEN')
                ->header('Access-Control-Allow-Credentials', 'true')
                ->header('Access-Control-Max-Age', '86400');
        }

        $response = $next($request);

        $response->headers->set('Access-Control-Allow-Origin', $allowOrigin);
        $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
        $response->headers->set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, X-XSRF-TOKEN');
        $response->headers->set('Access-Control-Allow-Credentials', 'true');
        $response->headers->set('Access-Control-Max-Age', '86400');

        return $response;
    }
}
