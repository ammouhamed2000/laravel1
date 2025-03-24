<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\LoginApiController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/
Route::group(['prefix' => 'auth'], function () {

    Route::post('/login', action: [LoginApiController::class, 'login'])->name('login.store');

    Route::post('/register', action: [LoginApiController::class, 'register'])->name('register.store');

    Route::post('/forgot_password', action: [LoginApiController::class, 'forgot'])->name('forgot_password.store');

});
Route::group(['middleware' => 'auth:sanctum','prefix' => 'auth'], function () {

    Route::get('/', action: [LoginApiController::class, 'user'])->name('user.index');;

    Route::post('/complete_profile', action: [LoginApiController::class, 'complete_profile'])->name('complete_profile.store');

    Route::post('/logout', action: [LoginApiController::class, 'logout'])->name('logout');

});
