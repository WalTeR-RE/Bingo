<?php

namespace App\Services;

use App\Helpers\ActivityLogger;
use App\Models\Incident;
use App\Models\IncidentNote;
use App\Models\Notification;
use Illuminate\Support\Facades\Auth;

class IncidentService
{
    public function list(array $filters = [])
    {
        $query = Incident::where('user_id', Auth::id());

        if (!empty($filters['severity'])) {
            $query->where('severity', $filters['severity']);
        }

        if (!empty($filters['status'])) {
            $query->where('status', $filters['status']);
        }

        if (!empty($filters['search'])) {
            $query->where(function ($q) use ($filters) {
                $q->where('title', 'like', "%{$filters['search']}%")
                  ->orWhere('source_ip', 'like', "%{$filters['search']}%")
                  ->orWhere('affected_asset', 'like', "%{$filters['search']}%")
                  ->orWhere('rule_triggered', 'like', "%{$filters['search']}%");
            });
        }

        if (!empty($filters['from'])) {
            $query->where('detected_at', '>=', $filters['from']);
        }

        if (!empty($filters['to'])) {
            $query->where('detected_at', '<=', $filters['to']);
        }

        return $query->orderBy('detected_at', 'desc')
            ->paginate($filters['per_page'] ?? 15);
    }

    public function create(array $data): Incident
    {
        $data['user_id'] = Auth::id();
        $incident = Incident::create($data);

        ActivityLogger::log('incident_created', 'Incident', $incident->id, [
            'title' => $incident->title,
            'severity' => $incident->severity,
        ]);

        if (in_array($incident->severity, ['critical', 'high'])) {
            Notification::create([
                'user_id' => $incident->user_id,
                'type' => 'new_incident',
                'title' => "New {$incident->severity} incident",
                'message' => $incident->title,
                'entity_type' => 'Incident',
                'entity_id' => $incident->id,
            ]);
        }

        return $incident;
    }

    public function show(string $id): Incident
    {
        return Incident::where('user_id', Auth::id())
            ->with(['notes.user'])
            ->findOrFail($id);
    }

    public function update(string $id, array $data): Incident
    {
        $incident = Incident::where('user_id', Auth::id())->findOrFail($id);
        $incident->update($data);

        ActivityLogger::log('incident_updated', 'Incident', $incident->id, [
            'fields' => array_keys($data),
        ]);

        return $incident->fresh();
    }

    public function delete(string $id): void
    {
        $incident = Incident::where('user_id', Auth::id())->findOrFail($id);

        ActivityLogger::log('incident_deleted', 'Incident', $incident->id, [
            'title' => $incident->title,
        ]);

        $incident->delete();
    }

    public function changeStatus(string $id, string $status): Incident
    {
        $incident = Incident::where('user_id', Auth::id())->findOrFail($id);
        $oldStatus = $incident->status;

        $updateData = ['status' => $status];
        if ($status === 'resolved') {
            $updateData['resolved_at'] = now();
        }

        $incident->update($updateData);

        ActivityLogger::log('incident_status_changed', 'Incident', $incident->id, [
            'old_status' => $oldStatus,
            'new_status' => $status,
        ]);

        return $incident->fresh();
    }

    public function addNote(string $id, string $content): IncidentNote
    {
        $incident = Incident::where('user_id', Auth::id())->findOrFail($id);

        $note = IncidentNote::create([
            'incident_id' => $incident->id,
            'user_id' => Auth::id(),
            'content' => $content,
        ]);

        ActivityLogger::log('incident_note_added', 'Incident', $incident->id);

        return $note->load('user');
    }

    public function stats(string $range = 'all')
    {
        $query = Incident::where('user_id', Auth::id());
        $query = $this->applyRange($query, $range);

        return [
            'total_incidents' => (clone $query)->count(),
            'new' => (clone $query)->where('status', 'new')->count(),
            'investigating' => (clone $query)->where('status', 'investigating')->count(),
            'resolved' => (clone $query)->where('status', 'resolved')->count(),
            'false_positive' => (clone $query)->where('status', 'false_positive')->count(),
            'escalated' => (clone $query)->where('status', 'escalated')->count(),
            'critical' => (clone $query)->where('severity', 'critical')->count(),
            'high' => (clone $query)->where('severity', 'high')->count(),
        ];
    }

    private function applyRange($query, string $range)
    {
        return match ($range) {
            '7d' => $query->where('created_at', '>=', now()->subDays(7)),
            '30d' => $query->where('created_at', '>=', now()->subDays(30)),
            '90d' => $query->where('created_at', '>=', now()->subDays(90)),
            default => $query,
        };
    }
}
