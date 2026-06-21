<?php

namespace App\Http\Middleware;

use App\Services\AccessTokenService;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateAgent
{
    public function handle(Request $request, Closure $next): Response
    {
        $bearerToken = $request->bearerToken();

        if (!$bearerToken) {
            return response()->json([
                'message' => 'Access token required. Provide it via Authorization: Bearer <token>',
            ], 401);
        }

        $accessToken = AccessTokenService::resolveFromBearer($bearerToken);

        if (!$accessToken) {
            return response()->json([
                'message' => 'Invalid or expired access token.',
            ], 401);
        }

        $request->attributes->set('access_token', $accessToken);

        return $next($request);
    }
}
