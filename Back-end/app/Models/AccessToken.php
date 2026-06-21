<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class AccessToken extends Model
{
    use HasUuids;

    protected $fillable = [
        'user_id',
        'name',
        'token_hash',
        'expires_at',
        'last_used_at',
    ];

    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'last_used_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function heartbeats(): HasMany
    {
        return $this->hasMany(AgentHeartbeat::class);
    }

    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    public function isExpiringSoon(): bool
    {
        return $this->expires_at->diffInHours(now()) <= 24 && !$this->isExpired();
    }

    public function getMaskedTokenAttribute(): string
    {
        return 'bingo_ak_' . str_repeat('*', 32);
    }
}
