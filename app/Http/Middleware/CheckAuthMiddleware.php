<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Symfony\Component\HttpFoundation\Response;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class CheckAuthMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if ($request->header('Content-Type') === 'application/x-www-form-urlencoded') {
	        return $next($request);
	    }else{
	        try {
			    $user = JWTAuth::parseToken()->authenticate();
			} catch (TokenExpiredException $e) {
			    return response()->json(
                    [
                        'status' => 'Failed/Error',
                        'message' => 'Invalid access, token expired',
                    ],
			        Response::HTTP_UNAUTHORIZED
			    );
			} catch (TokenInvalidException $e) {
                return response()->json(
                    [
                        'status' => 'Failed/Error',
                        'message' => 'Invalid access token',
                    ],
			        Response::HTTP_UNAUTHORIZED
			    );
			} catch (\Exception $e) {
                return response()->json(
                    [
                        'status' => 'Failed/Error',
                        'message' => 'Bad request',
                    ],
			        Response::HTTP_BAD_REQUEST
			    );
			}

	    }

        return $next($request);
    }
}
