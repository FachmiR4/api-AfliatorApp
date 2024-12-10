<?php

namespace App\Http\Controllers;

use api;
use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;


class UserController extends Controller
{
    /**
     * Handle the incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request){
        $validator = Validator::make($request->headers->all(), [
            'name'      => 'required',
            'role'      => 'required',
            'email'     => 'required|unique:users',
            'password'  => 'required'
        ]);

        //if validation fails
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        //create user
        $user = User::create([
            'name'      => $request->header('name'),
            'role'      => $request->header('role'),
            'email'     => $request->header('email'),
            'password'  => bcrypt($request->header('password'))
        ]);

        //return response JSON user is created
        if($user) {
            return response()->json([
                'success' => true,
                'user'    => $user,  
            ], 201);
        }

        //return JSON process insert failed 
        return response()->json([
            'success' => false,
        ], 409);
    }
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
	        'email'      => 'required',
	        'password'      => 'required'
	    ]);

	    if ($validator->fails()) {
	        return response()->json($validator->errors(), 422);
	    }

	    $credentials = [
	        'email' => $request->email,
	        'password' => $request->password
	    ];

	    $user = User::where('email', $credentials['email'])->first();
	    if (!$user || !password_verify($credentials['password'], $user->password)) {
            return response()->json([
                'success' => 'Failed/Error',
                'message' => 'Invalid credential access token'
            ], 401);
        }

        if (!$token = auth()->guard('api')->login($user)) {
            return response()->json([
                'success' => 'Failed/Error',
                'message' => 'Invalid credential access token'
            ], 401);
        }

	    return response()->json([
	        'status' => 'Success',
	        'message' => 'Success',
	        'token'   => $token,
	        'expires_in' => Auth::guard('api')->factory()->getTTL() * 60   
	    ], 200);
    }
    public function me(){
        return response()->json(Auth::user());
    }
}

