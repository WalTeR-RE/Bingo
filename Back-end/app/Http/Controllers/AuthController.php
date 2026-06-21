<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\ForgotPasswordRequest;
use App\Http\Requests\ResetPasswordRequest;
use App\Http\Requests\UpdateProfileRequest;
use App\Http\Requests\UpdatePasswordRequest;
use App\Services\AuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function __construct(private AuthService $authService) {}

    public function login(LoginRequest $request): JsonResponse
    {
        $result = $this->authService->login(
            $request->email,
            $request->password
        );

        return response()->json([
            'message' => 'Login successful',
            'user' => $result['user'],
            'token' => $result['token'],
        ]);
    }

    public function logout(): JsonResponse
    {
        $this->authService->logout();

        return response()->json(['message' => 'Logged out successfully']);
    }

    public function me(): JsonResponse
    {
        return response()->json(['user' => $this->authService->me()]);
    }

    public function updateProfile(UpdateProfileRequest $request): JsonResponse
    {
        $data = $request->only(['name', 'email']);

        if ($request->hasFile('photo')) {
            $path = $request->file('photo')->store('photos', 'public');
            $data['photo'] = $path;
        }

        $user = $this->authService->updateProfile($data);

        return response()->json([
            'message' => 'Profile updated successfully',
            'user' => $user,
        ]);
    }

    public function updatePassword(UpdatePasswordRequest $request): JsonResponse
    {
        $this->authService->updatePassword(
            $request->current_password,
            $request->new_password
        );

        return response()->json(['message' => 'Password updated successfully']);
    }

    public function forgotPassword(ForgotPasswordRequest $request): JsonResponse
    {
        $status = $this->authService->forgotPassword($request->email);

        return response()->json(['message' => $status]);
    }

    public function resetPassword(ResetPasswordRequest $request): JsonResponse
    {
        $status = $this->authService->resetPassword($request->only(
            'email', 'password', 'password_confirmation', 'token'
        ));

        return response()->json(['message' => $status]);
    }
}
