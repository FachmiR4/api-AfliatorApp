<?php

use App\Http\Controllers\userController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::group([

    'middleware' => 'api',
    'prefix' => 'auth'

], function ($router) {
    Route::post('register', [userController::class, 'register']);
    Route::post('login', [userController::class, 'login']);
    Route::post('logout', [userController::class, 'logout']);
    Route::post('refresh', [userController::class, 'refresh']);
    Route::post('me', [userController::class, 'me']);

});
