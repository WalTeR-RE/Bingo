<?php

namespace App\Services;

use App\Helpers\ActivityLogger;
use App\Models\AccessToken;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

class AccessTokenService
{
    public function list()
    {
        return AccessToken::where('user_id', Auth::id())
            ->orderBy('created_at', 'desc')
            ->get()
            ->map(function ($token) {
                return [
                    'id' => $token->id,
                    'name' => $token->name,
                    'masked_token' => $token->masked_token,
                    'expires_at' => $token->expires_at->toISOString(),
                    'last_used_at' => $token->last_used_at?->toISOString(),
                    'is_expired' => $token->isExpired(),
                    'is_expiring_soon' => $token->isExpiringSoon(),
                    'created_at' => $token->created_at->toISOString(),
                ];
            });
    }

    public function generate(string $name, int $expirationDays): array
    {
        $this->validateExpiration($expirationDays);

        $plainToken = 'bingo_ak_' . Str::random(55);
        $tokenHash = hash('sha256', $plainToken);

        $accessToken = AccessToken::create([
            'user_id' => Auth::id(),
            'name' => $name,
            'token_hash' => $tokenHash,
            'expires_at' => now()->addDays($expirationDays),
        ]);

        ActivityLogger::log('access_token_created', 'AccessToken', $accessToken->id, [
            'name' => $name,
            'expires_in_days' => $expirationDays,
        ]);

        return [
            'token' => $accessToken,
            'plain_token' => $plainToken,
        ];
    }

    public function delete(string $id): void
    {
        $token = AccessToken::where('id', $id)
            ->where('user_id', Auth::id())
            ->firstOrFail();

        ActivityLogger::log('access_token_deleted', 'AccessToken', $token->id, [
            'name' => $token->name,
        ]);

        $token->delete();
    }

    public function regenerate(string $id): array
    {
        $token = AccessToken::where('id', $id)
            ->where('user_id', Auth::id())
            ->firstOrFail();

        $plainToken = 'bingo_ak_' . Str::random(55);
        $tokenHash = hash('sha256', $plainToken);

        $token->update([
            'token_hash' => $tokenHash,
            'last_used_at' => null,
        ]);

        ActivityLogger::log('access_token_regenerated', 'AccessToken', $token->id, [
            'name' => $token->name,
        ]);

        return [
            'token' => $token->fresh(),
            'plain_token' => $plainToken,
        ];
    }

    public function extend(string $id, int $days): AccessToken
    {
        $this->validateExpiration($days);

        $token = AccessToken::where('id', $id)
            ->where('user_id', Auth::id())
            ->firstOrFail();

        $newExpiry = now()->addDays($days);
        $maxExpiry = now()->addDays(30);

        if ($newExpiry->greaterThan($maxExpiry)) {
            $newExpiry = $maxExpiry;
        }

        $token->update(['expires_at' => $newExpiry]);

        ActivityLogger::log('access_token_extended', 'AccessToken', $token->id, [
            'name' => $token->name,
            'new_expiry' => $newExpiry->toISOString(),
        ]);

        return $token->fresh();
    }

    public static function resolveFromBearer(string $bearerToken): ?AccessToken
    {
        $hash = hash('sha256', $bearerToken);

        $token = AccessToken::where('token_hash', $hash)->first();

        if (!$token || $token->isExpired()) {
            return null;
        }

        $token->update(['last_used_at' => now()]);

        return $token;
    }

    private function validateExpiration(int $days): void
    {
        if (!in_array($days, [7, 14, 30])) {
            throw new \InvalidArgumentException('Expiration must be 7, 14, or 30 days.');
        }
    }
}
