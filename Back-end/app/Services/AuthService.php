<?php

namespace App\Services;

use App\Helpers\ActivityLogger;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class AuthService
{
    public function login(string $email, string $password): array
    {
        $user = User::where('email', $email)->first();

        if (!$user || !Hash::check($password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $token = $user->createToken('admin-session')->plainTextToken;

        ActivityLogger::log('login', 'User', $user->id);

        return [
            'user' => $user,
            'token' => $token,
        ];
    }

    public function logout(): void
    {
        $user = Auth::user();
        $user->currentAccessToken()->delete();
        ActivityLogger::log('logout', 'User', $user->id);
    }

    public function me(): User
    {
        return Auth::user();
    }

    public function updateProfile(array $data): User
    {
        $user = Auth::user();
        $user->update($data);

        ActivityLogger::log('profile_updated', 'User', $user->id, [
            'fields' => array_keys($data),
        ]);

        return $user->fresh();
    }

    public function updatePassword(string $currentPassword, string $newPassword): void
    {
        $user = Auth::user();

        if (!Hash::check($currentPassword, $user->password)) {
            throw ValidationException::withMessages([
                'current_password' => ['The current password is incorrect.'],
            ]);
        }

        $user->update(['password' => Hash::make($newPassword)]);

        ActivityLogger::log('password_changed', 'User', $user->id);
    }

    public function forgotPassword(string $email): string
    {
        $status = Password::sendResetLink(['email' => $email]);

        if ($status !== Password::RESET_LINK_SENT) {
            throw ValidationException::withMessages([
                'email' => [__($status)],
            ]);
        }

        return __($status);
    }

    public function resetPassword(array $data): string
    {
        $status = Password::reset($data, function (User $user, string $password) {
            $user->forceFill([
                'password' => Hash::make($password),
                'remember_token' => Str::random(60),
            ])->save();
        });

        if ($status !== Password::PASSWORD_RESET) {
            throw ValidationException::withMessages([
                'email' => [__($status)],
            ]);
        }

        return __($status);
    }
}
