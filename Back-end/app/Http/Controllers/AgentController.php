<?php

namespace App\Http\Controllers;

use App\Helpers\ActivityLogger;
use App\Models\AgentHeartbeat;
use App\Models\Incident;
use App\Models\Notification;
use App\Models\Report;
use App\Models\Vulnerability;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AgentController extends Controller
{
    public function heartbeat(Request $request): JsonResponse
    {
        $request->validate([
            'agent_name' => 'required|string|max:100',
            'agent_type' => 'required|in:offensive,defensive',
            'status' => 'sometimes|in:idle,scanning,monitoring,error',
            'metadata' => 'sometimes|array',
        ]);

        $accessToken = $request->attributes->get('access_token');

        AgentHeartbeat::updateOrCreate(
            [
                'access_token_id' => $accessToken->id,
                'agent_name' => $request->agent_name,
            ],
            [
                'agent_type' => $request->agent_type,
                'status' => $request->status ?? 'idle',
                'ip_address' => $request->ip(),
                'metadata' => $request->metadata,
                'last_seen_at' => now(),
            ]
        );

        return response()->json(['message' => 'Heartbeat received', 'time' => now()->toISOString()]);
    }

    public function submitReport(Request $request): JsonResponse
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'target' => 'required|string|max:255',
            'scan_type' => 'sometimes|string|max:50',
            'scan_date' => 'sometimes|date',
            'started_at' => 'sometimes|date',
            'completed_at' => 'sometimes|date',
            'notes' => 'sometimes|string',
            'created_by' => 'sometimes|string|max:100',
            'vulnerabilities' => 'sometimes|array',
            'vulnerabilities.*.name' => 'required|string|max:255',
            'vulnerabilities.*.severity' => 'required|in:critical,high,medium,low,informational',
            'vulnerabilities.*.description' => 'sometimes|string',
            'vulnerabilities.*.affected_asset' => 'sometimes|string|max:255',
            'vulnerabilities.*.evidence' => 'sometimes|string',
            'vulnerabilities.*.payload' => 'sometimes|string',
            'vulnerabilities.*.remediation' => 'sometimes|string',
            'vulnerabilities.*.cvss_score' => 'sometimes|numeric|between:0,10',
            'vulnerabilities.*.cwe_id' => 'sometimes|string|max:20',
            'vulnerabilities.*.references' => 'sometimes|array',
        ]);

        $accessToken = $request->attributes->get('access_token');
        $userId = $accessToken->user_id;

        $report = Report::create([
            'user_id' => $userId,
            'name' => $request->name,
            'target' => $request->target,
            'scan_type' => $request->scan_type ?? 'Web Application',
            'scan_date' => $request->scan_date ?? now(),
            'started_at' => $request->started_at ?? $request->scan_date ?? now(),
            'completed_at' => $request->completed_at ?? now(),
            'notes' => $request->notes,
            'created_by' => $request->created_by ?? 'Bingo Agent (Offensive)',
            'status' => 'completed',
        ]);

        $vulnCount = 0;
        $criticalCount = 0;

        if ($request->has('vulnerabilities')) {
            foreach ($request->vulnerabilities as $vulnData) {
                $vulnData['report_id'] = $report->id;
                Vulnerability::create($vulnData);
                $vulnCount++;
                if (($vulnData['severity'] ?? '') === 'critical') {
                    $criticalCount++;
                }
            }
        }

        if ($criticalCount > 0) {
            Notification::create([
                'user_id' => $userId,
                'type' => 'critical_vuln',
                'title' => "Critical vulnerabilities found",
                'message' => "{$criticalCount} critical vulnerabilities found in scan of {$request->target}",
                'entity_type' => 'Report',
                'entity_id' => $report->id,
            ]);
        }

        ActivityLogger::log('agent_report_submitted', 'Report', $report->id, [
            'target' => $request->target,
            'vuln_count' => $vulnCount,
        ]);

        return response()->json([
            'message' => 'Report submitted successfully',
            'report_id' => $report->id,
            'vulnerabilities_count' => $vulnCount,
        ], 201);
    }

    public function submitIncident(Request $request): JsonResponse
    {
        $request->validate([
            'title' => 'required|string|max:255',
            'description' => 'sometimes|string',
            'severity' => 'required|in:critical,high,medium,low,informational',
            'source_ip' => 'sometimes|string|max:45',
            'destination_ip' => 'sometimes|string|max:45',
            'affected_asset' => 'sometimes|string|max:255',
            'rule_triggered' => 'sometimes|string|max:255',
            'raw_log' => 'sometimes|array',
            'detected_at' => 'sometimes|date',
        ]);

        $accessToken = $request->attributes->get('access_token');
        $userId = $accessToken->user_id;

        $incident = Incident::create([
            'user_id' => $userId,
            'title' => $request->title,
            'description' => $request->description,
            'severity' => $request->severity,
            'status' => 'new',
            'source_ip' => $request->source_ip,
            'destination_ip' => $request->destination_ip,
            'affected_asset' => $request->affected_asset,
            'rule_triggered' => $request->rule_triggered,
            'raw_log' => $request->raw_log,
            'detected_at' => $request->detected_at ?? now(),
        ]);

        if (in_array($incident->severity, ['critical', 'high'])) {
            Notification::create([
                'user_id' => $userId,
                'type' => 'new_incident',
                'title' => "New {$incident->severity} security incident",
                'message' => $incident->title,
                'entity_type' => 'Incident',
                'entity_id' => $incident->id,
            ]);
        }

        return response()->json([
            'message' => 'Incident submitted successfully',
            'incident_id' => $incident->id,
        ], 201);
    }
}
