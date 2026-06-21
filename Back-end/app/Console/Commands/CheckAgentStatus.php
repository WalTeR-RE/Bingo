<?php

namespace App\Console\Commands;

use App\Models\AgentHeartbeat;
use App\Services\NotificationService;
use Illuminate\Console\Command;

class CheckAgentStatus extends Command
{
    protected $signature = 'agents:check-status';
    protected $description = 'Flag agents that have not sent a heartbeat in 5+ minutes and notify';

    public function handle(): int
    {
        $stale = AgentHeartbeat::where('last_seen_at', '<', now()->subMinutes(5))
            ->whereNull('went_offline_at')
            ->get();

        foreach ($stale as $hb) {
            $hb->update(['went_offline_at' => now()]);

            NotificationService::notify(
                title: "Agent offline: {$hb->agent_name}",
                body: "Agent {$hb->agent_name} ({$hb->ip_address}) went offline.",
                type: 'agent_offline',
                link: '/settings#tokens',
            );
        }

        $this->info("Marked {$stale->count()} agents as offline.");
        return self::SUCCESS;
    }
}
