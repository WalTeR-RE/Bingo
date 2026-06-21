<?php

namespace App\Services;

use App\Models\Incident;
use App\Models\Report;
use App\Models\Vulnerability;
use Illuminate\Support\Facades\Auth;

class SearchService
{
    public function search(string $query): array
    {
        $userId = Auth::id();
        $term = "%{$query}%";

        $reports = Report::where('user_id', $userId)
            ->where(function ($q) use ($term) {
                $q->where('name', 'like', $term)
                  ->orWhere('target', 'like', $term);
            })
            ->limit(5)
            ->get(['id', 'name', 'target', 'status'])
            ->map(fn($r) => ['type' => 'report', 'id' => $r->id, 'title' => $r->name, 'subtitle' => $r->target, 'status' => $r->status]);

        $vulnerabilities = Vulnerability::whereHas('report', function ($q) use ($userId) {
            $q->where('user_id', $userId);
        })->where(function ($q) use ($term) {
            $q->where('name', 'like', $term)
              ->orWhere('affected_asset', 'like', $term)
              ->orWhere('cwe_id', 'like', $term);
        })->with('report:id,name')
          ->limit(5)
          ->get(['id', 'report_id', 'name', 'severity', 'affected_asset'])
          ->map(fn($v) => ['type' => 'vulnerability', 'id' => $v->id, 'title' => $v->name, 'subtitle' => $v->affected_asset, 'severity' => $v->severity, 'report_id' => $v->report_id, 'report_name' => $v->report?->name]);

        $incidents = Incident::where('user_id', $userId)
            ->where(function ($q) use ($term) {
                $q->where('title', 'like', $term)
                  ->orWhere('source_ip', 'like', $term)
                  ->orWhere('rule_triggered', 'like', $term)
                  ->orWhere('affected_asset', 'like', $term);
            })
            ->limit(5)
            ->get(['id', 'title', 'severity', 'status', 'source_ip'])
            ->map(fn($i) => ['type' => 'incident', 'id' => $i->id, 'title' => $i->title, 'subtitle' => $i->source_ip, 'severity' => $i->severity, 'status' => $i->status]);

        return [
            'reports' => $reports,
            'vulnerabilities' => $vulnerabilities,
            'incidents' => $incidents,
            'total' => $reports->count() + $vulnerabilities->count() + $incidents->count(),
        ];
    }
}
