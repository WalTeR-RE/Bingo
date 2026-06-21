<?php

namespace App\Console\Commands;

use App\Models\AccessToken;
use App\Services\NotificationService;
use Illuminate\Console\Command;

class WarnExpiringTokens extends Command
{
    protected $signature = 'tokens:warn-expiring';
    protected $description = 'Send notifications for tokens expiring within 48 hours';

    public function handle(): int
    {
        $tokens = AccessToken::whereBetween('expires_at', [now(), now()->addHours(48)])
            ->where('warned_expiring', false)
            ->get();

        foreach ($tokens as $token) {
            $hours = (int) now()->diffInHours($token->expires_at);

            NotificationService::notify(
                title: "Token expiring soon: {$token->name}",
                body: "Access token \"{$token->name}\" will expire in {$hours} hours.",
                type: 'token_expiring',
                link: '/settings#tokens',
            );

            $token->update(['warned_expiring' => true]);
        }

        $this->info("Warned about {$tokens->count()} expiring tokens.");
        return self::SUCCESS;
    }
}
