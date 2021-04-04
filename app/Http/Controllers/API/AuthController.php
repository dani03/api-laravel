<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {
        $validatedData = $request->validate([
            'name' => 'required|max:55',
            'email' => 'email|required|unique:users',
            'password' => 'required'
        ]);

        $validatedData['password'] = Hash::make($request->password);

        $user = User::create($validatedData);

        $accessToken = $user->createToken('authToken')->accessToken;

        return response(['message' => 'user created...succefully', 'access_token' => $accessToken], 201);
    }

    public function login(Request $request){
        $loginData = $request->validate([
            'email' => 'email|required',
            'password' => 'required',
        ]);
        if (!Auth()->attempt($loginData)) {
            return response(['message' => 'This User does not exist, check your details'], 404);
        }
        $authenticated_user = auth()->user();
        $user = User::find($authenticated_user->id);
        $accessToken = $user->createToken('authToken')->accessToken;
    
        return response(['user' => auth()->user(), 'access_token' => $accessToken]);

    }
}
