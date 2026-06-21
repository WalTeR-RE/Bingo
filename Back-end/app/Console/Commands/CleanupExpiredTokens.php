<?php

namespace App\Console\Commands;

use App\Models\AccessToken;
use Illuminate\Console\Command;

class CleanupExpiredTokens extends Command
{
    protected $signature = 'tokens:cleanup';
    protected $description = 'Delete access tokens that expired more than 7 days ago';

    public function handle(): int
    {
        $count = AccessToken::where('expires_at', '<', now()->subDays(7))->delete();
        $this->info("Cleaned up {$count} expired tokens.");
        return self::SUCCESS;
    }
}
