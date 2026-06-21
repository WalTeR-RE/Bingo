<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

class Report extends Model
{
    use HasUuids, SoftDeletes;

    protected $fillable = [
        'user_id',
        'name',
        'target',
        'scan_type',
        'status',
        'created_by',
        'scan_date',
        'started_at',
        'completed_at',
        'notes',
    ];

    protected function casts(): array
    {
        return [
            'scan_date' => 'datetime',
            'started_at' => 'datetime',
            'completed_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function vulnerabilities(): HasMany
    {
        return $this->hasMany(Vulnerability::class);
    }

    public function getVulnCountAttribute(): int
    {
        return $this->vulnerabilities()->count();
    }

    public function getCriticalCountAttribute(): int
    {
        return $this->vulnerabilities()->where('severity', 'critical')->count();
    }
}
