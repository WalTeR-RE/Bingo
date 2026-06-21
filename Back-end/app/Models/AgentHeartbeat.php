<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AgentHeartbeat extends Model
{
    use HasUuids;

    protected $fillable = [
        'access_token_id',
        'agent_name',
        'agent_type',
        'status',
        'ip_address',
        'metadata',
        'last_seen_at',
    ];

    protected function casts(): array
    {
        return [
            'metadata' => 'array',
            'last_seen_at' => 'datetime',
        ];
    }

    public function accessToken(): BelongsTo
    {
        return $this->belongsTo(AccessToken::class);
    }

    public function isOnline(): bool
    {
        return $this->last_seen_at->diffInMinutes(now()) <= 5;
    }

    public function getStatusLabelAttribute(): string
    {
        if (!$this->isOnline()) {
            return 'offline';
        }
        return $this->status;
    }
}
