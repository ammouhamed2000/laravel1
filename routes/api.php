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

    Route::post('/login',  [LoginApiController::class, 'login'])->name('login.store');
    Route::get('/login',  [LoginApiController::class, 'loginIndex'])->name('login');

    Route::post('/register',  [LoginApiController::class, 'register'])->name('register.store');

    Route::post('/forgot_password',  [LoginApiController::class, 'forgot'])->name('forgot_password.store');

});
Route::group(['middleware' => 'auth:sanctum','prefix' => 'auth'], function () {

    Route::get('/',  [LoginApiController::class, 'user'])->name('user.index');;

    Route::post('/complete_profile',  [LoginApiController::class, 'complete_profile'])->name('complete_profile.store');

    Route::post('/logout',  [LoginApiController::class, 'logout'])->name('logout');

});
