<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Incident extends Model
{
    use HasUuids;

    protected $fillable = [
        'user_id',
        'title',
        'description',
        'severity',
        'status',
        'source_ip',
        'destination_ip',
        'affected_asset',
        'rule_triggered',
        'raw_log',
        'detected_at',
        'resolved_at',
        'action_taken',
    ];

    protected function casts(): array
    {
        return [
            'raw_log' => 'array',
            'detected_at' => 'datetime',
            'resolved_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function notes(): HasMany
    {
        return $this->hasMany(IncidentNote::class)->orderBy('created_at', 'desc');
    }
}
