<?php

namespace App\Services;

use App\Helpers\ActivityLogger;
use App\Models\Report;
use App\Models\Vulnerability;
use Illuminate\Support\Facades\Auth;
use Barryvdh\DomPDF\Facade\Pdf;

class ReportService
{
    public function list(array $filters = [])
    {
        $query = Report::where('user_id', Auth::id())
            ->withCount('vulnerabilities')
            ->withCount(['vulnerabilities as critical_count' => function ($q) {
                $q->where('severity', 'critical');
            }])
            ->withCount(['vulnerabilities as high_count' => function ($q) {
                $q->where('severity', 'high');
            }]);

        if (!empty($filters['status'])) {
            $query->where('status', $filters['status']);
        }

        if (!empty($filters['search'])) {
            $query->where(function ($q) use ($filters) {
                $q->where('name', 'like', "%{$filters['search']}%")
                  ->orWhere('target', 'like', "%{$filters['search']}%");
            });
        }

        return $query->orderBy('created_at', 'desc')->paginate($filters['per_page'] ?? 15);
    }

    public function create(array $data): Report
    {
        $data['user_id'] = Auth::id();
        $report = Report::create($data);

        ActivityLogger::log('report_created', 'Report', $report->id, [
            'name' => $report->name,
            'target' => $report->target,
        ]);

        return $report;
    }

    public function show(string $id): Report
    {
        return Report::where('user_id', Auth::id())
            ->with(['vulnerabilities' => function ($q) {
                $q->orderByRaw("FIELD(severity, 'critical', 'high', 'medium', 'low', 'informational')");
            }])
            ->withCount('vulnerabilities')
            ->findOrFail($id);
    }

    public function update(string $id, array $data): Report
    {
        $report = Report::where('user_id', Auth::id())->findOrFail($id);
        $report->update($data);

        ActivityLogger::log('report_updated', 'Report', $report->id, [
            'fields' => array_keys($data),
        ]);

        return $report->fresh();
    }

    public function delete(string $id): void
    {
        $report = Report::where('user_id', Auth::id())->findOrFail($id);

        ActivityLogger::log('report_deleted', 'Report', $report->id, [
            'name' => $report->name,
        ]);

        $report->delete();
    }

    public function export(string $id, string $format = 'json')
    {
        $report = $this->show($id);

        if ($format === 'pdf') {
            $pdf = Pdf::loadView('reports.export', ['report' => $report]);
            $safeName = preg_replace('/[^A-Za-z0-9_-]+/', '_', $report->name);
            $safeName = trim($safeName, '_') ?: 'report';
            return $pdf->download("report-{$safeName}.pdf");
        }

        return response()->json([
            'report' => $report->toArray(),
        ]);
    }

    public function stats(string $range = 'all')
    {
        $query = Report::where('user_id', Auth::id());
        $query = $this->applyRange($query, $range);

        return [
            'total_reports' => (clone $query)->count(),
            'open_reports' => (clone $query)->where('status', 'open')->count(),
            'completed_reports' => (clone $query)->where('status', 'completed')->count(),
            'in_progress_reports' => (clone $query)->where('status', 'in_progress')->count(),
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
