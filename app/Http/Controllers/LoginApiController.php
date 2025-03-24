<?php

namespace App\Http\Controllers;

use Illuminate\Auth\AuthenticationException;
use Rules\Password;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Validation\Rules;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class LoginApiController extends Controller
{
    public function user(Request $request)
    {
        $user = Auth::user();
        return response()->json(['status' => true,"data" => $user],200);
    }
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => ['required', 'string', 'email', 'max:255'],
            'password' => ['required'],
        ]);

        // Login & validation 
        if (!Auth()->attempt($credentials)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid email or password',
            ], 401);
        }

        // Token get
        $user = auth()->user();
        $token = $user->createToken('web')->plainTextToken;

        return response()->json([
            'status' => true,
            'data' => [
                "username"=> $user->username,
                "token"=> $token
            ]
        ],200);
    }
    public function register(Request $request)
    {
        $validator = \Validator::make($request->all(),[
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:'.User::class],
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
        ]);
        if ($validator->fails()) {
            $msg['status'] = 'error';
            $msg['msg']  = $validator->errors()->first();
            return response()->json($msg);
        }

        // Create user name 
        $username = explode('@', $request->email)[0];
        $username = preg_replace('/[^a-zA-Z0-9]/', '', $username);
        $originalUsername = $username;
        $counter = 1;

        while (User::where('username', $username)->exists()) {
            $username = $originalUsername . $counter;
            $counter++;
        }
        $user = User::create([
            'name' => $request->name,
            'username' => $username,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);
        Auth::login($user);
        $token = $request->user()->createToken('web')->plainTextToken;
        return response()->json([
            'status' => true,
            'data' => [
                "username"=> "example_user",
                "token"=> $token
            ]
        ],200);
    }
   
    
    public function complete_profile(Request $request)
    {
        $validator = \Validator::make($request->all(),[
            'name' => ['required', 'string', 'max:255'],
            'phone' => ['max:255','size:10'],
            'profile_image' => ['mimes:jpeg,png,jpg,webp|max:5048'],
        ]);
        if ($validator->fails()) {
            $msg['status'] = 'error';
            $msg['msg']  = $validator->errors()->first();
            return response()->json($msg);
        }
        $user = Auth::user();
        $user->name           = $request->name;
        $user->email          = $request->email;
        $user->gender         = $request->gender;
        $user->phone          = $request->phone;
        $user->latitude       = $request->latitude;
        $user->longitude      = $request->longitude;
        $user->profile_image  = $request->profile_image;
        $user->save();
        return response()->json([
            'status' => true,
        ],200);
    }

    public function logout(Request $request)
    {
        auth()->user()->currentAccessToken()->delete();
        return response()->json([
            'status' => true,
        ],200);
    }

    public function forgot(Request $request)
    {
        $credentials = $request->validate([
            'email' => ['required', 'string', 'email', 'max:255'],
        ]);

        $user = User::where('email',$request->email)->first();

        if ($user) {
            return response()->json([
                'status' => true,
                'data' => [
                    "message"=> "Password reset code sent to your email",
                ]
            ],200);
        }

        return response()->json([
            'status' => true,
            'data' => [
                "message"=> "Email address not found",
            ]
        ],404);
    }
}
