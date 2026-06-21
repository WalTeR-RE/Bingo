<?php

namespace App\Services;

use App\Models\ActivityLog;
use App\Models\AgentHeartbeat;
use App\Models\Incident;
use App\Models\Report;
use App\Models\Vulnerability;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

class DashboardService
{
    public function stats(string $range = 'all'): array
    {
        $userId = Auth::id();

        $reportService = new ReportService();
        $vulnService = new VulnerabilityService();
        $incidentService = new IncidentService();

        $reportStats = $reportService->stats($range);
        $vulnStats = $vulnService->stats($range);
        $incidentStats = $incidentService->stats($range);

        $agents = AgentHeartbeat::with('accessToken')
            ->orderBy('last_seen_at', 'desc')
            ->get()
            ->unique('agent_name')
            ->values()
            ->map(function ($heartbeat) {
                return [
                    'id' => $heartbeat->id,
                    'agent_name' => $heartbeat->agent_name,
                    'agent_type' => $heartbeat->agent_type,
                    'status' => $heartbeat->status_label,
                    'ip_address' => $heartbeat->ip_address,
                    'last_seen_at' => $heartbeat->last_seen_at->toISOString(),
                    'is_online' => $heartbeat->isOnline(),
                    'metadata' => $heartbeat->metadata,
                ];
            });

        $severityDistribution = Vulnerability::whereHas('report', function ($q) use ($userId) {
            $q->where('user_id', $userId);
        })->select('severity', DB::raw('count(*) as count'))
          ->groupBy('severity')
          ->pluck('count', 'severity');

        $incidentsTimeline = Incident::where('user_id', $userId)
            ->where('created_at', '>=', now()->subDays(30))
            ->select(DB::raw('DATE(detected_at) as date'), DB::raw('count(*) as count'))
            ->groupBy('date')
            ->orderBy('date')
            ->pluck('count', 'date');

        $scansPerMonth = Report::where('user_id', $userId)
            ->where('created_at', '>=', now()->subMonths(6))
            ->select(DB::raw("DATE_FORMAT(created_at, '%Y-%m') as month"), DB::raw('count(*) as count'))
            ->groupBy('month')
            ->orderBy('month')
            ->pluck('count', 'month');

        $topAssets = Vulnerability::whereHas('report', function ($q) use ($userId) {
            $q->where('user_id', $userId);
        })->select('affected_asset', DB::raw('count(*) as count'))
          ->whereNotNull('affected_asset')
          ->groupBy('affected_asset')
          ->orderByDesc('count')
          ->limit(5)
          ->pluck('count', 'affected_asset');

        $recentActivity = ActivityLog::where('user_id', $userId)
            ->orderBy('created_at', 'desc')
            ->limit(10)
            ->get();

        return [
            'reports' => $reportStats,
            'vulnerabilities' => $vulnStats,
            'incidents' => $incidentStats,
            'agents' => $agents,
            'charts' => [
                'severity_distribution' => $severityDistribution,
                'incidents_timeline' => $incidentsTimeline,
                'scans_per_month' => $scansPerMonth,
                'top_assets' => $topAssets,
            ],
            'recent_activity' => $recentActivity,
        ];
    }
}
