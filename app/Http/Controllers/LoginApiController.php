<?php

namespace App\Http\Controllers;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\Collection;
use Rules\Password;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Validation\Rules;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Image;
use Illuminate\Support\Facades\File;
class LoginApiController extends Controller
{
    public function user(Request $request)
    {
        $user = Auth::user();
        $user->profile_image = url('/uploads/cover_image/').'/'.$user->profile_image;
        return response()->json([$user],200);
    }
    public function loginIndex(Request $request)
    {
        return response()->json([
            "message" => 'You are not authenticated to access this resource'
        ],500);
    }
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => ['required', 'string', 'email', 'max:255'],
            'password' => ['required'],
        ]);


        // Login & validation 
        if (!Auth()->attempt($credentials)) {
            return response()->json([], 401);
        }

        // Token get
        $user = auth()->user();
        $dataToken = $user->username;
        if ($request->device_info) {
            $dataToken .= "|" . $request->device_info;
        }

        $token = $user->createToken($dataToken)->plainTextToken;

        return response()->json([
            "username"=> $user->username,
            "token"=> $token
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
            $errors = $validator->errors();
        
            if ($errors->has('email')) {
                if ($errors->first('email') == 'The email has already been taken.') {
                    $code = 409; // Conflict
                } else {
                    $code = 422; // Unprocessable
                }
                $msg['message'] = $errors->first('email');
            } else {
                $code = 422; // Unprocessable
                $msg['message'] = $errors->first();
            }
    
            return response()->json($msg, $code);
        }


        // Create user name 
        $username = explode('@', $request->email)[0];
        $username = preg_replace('/[^a-zA-Z0-9]/', '', $username);
        $originalUsername = $username;
        $counter = 1;
        $dataToken = $username;
        if ($request->device_info) {
            $dataToken .= "|" . $request->device_info;
        }

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
        $token = $request->user()->createToken($dataToken)->plainTextToken;
        return response()->json([
            "username"=> $username,
            "token"=> $token
        ],200);
    }
   
    
    public function complete_profile(Request $request)
    {
        $validator = \Validator::make($request->all(),[
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255'],
            'phone' => ['max:255'],
            'profile_image' => ['mimes:jpeg,png,jpg,webp|max:5048'],
        ]);
        if ($validator->fails()) {
            $msg['message']  = $validator->errors()->first();
            return response()->json($msg,422);
        }
        $name_cover = null;


        if ($request->hasFile('profile_image')) {
            $file = $request->file('profile_image');
            $name_cover = time() . '_' . $file->getClientOriginalName();
            $destinationPath = public_path('uploads/cover_image/');

            if (!File::exists($destinationPath)) {
                File::makeDirectory($destinationPath, 0755, true);
            }

            $file->move($destinationPath, $name_cover); 

            $url = asset('uploads/cover_image/' . $name_cover); 

        }


        $user = Auth::user();
        $user->name           = $request->name;
        $user->email          = $request->email;
        $user->gender         = (bool) $request->gender;
        $user->phone          = $request->phone;
        $user->latitude       = $request->latitude;
        $user->longitude      = $request->longitude;
        $user->profile_image  = $name_cover;
        $user->save();
        return response()->json([],200);
    }

    public function logout(Request $request)
    {
        auth()->user()->currentAccessToken()->delete();
        return response()->json([],200);
    }

    public function forgot(Request $request)
    {
        $credentials = $request->validate([
            'email' => ['required', 'string', 'email', 'max:255'],
        ]);

        $user = User::where('email',$request->email)->first();

        if ($user) {
            return response()->json([],200);
        }

        return response()->json([],404);
    }
}
