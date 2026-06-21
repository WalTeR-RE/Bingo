<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Report Export – {{ $report->name }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: DejaVu Sans, sans-serif; font-size: 11px; color: #1e293b; line-height: 1.5; }
        .header { background: #0066ff; color: #fff; padding: 20px 30px; }
        .header h1 { font-size: 22px; margin-bottom: 4px; }
        .header p { opacity: .85; font-size: 10px; }
        .meta-table { width: 100%; border-collapse: collapse; margin: 20px 30px; }
        .meta-table td { padding: 4px 8px; font-size: 10px; }
        .meta-table td:first-child { font-weight: bold; width: 140px; color: #64748b; }
        .section { margin: 16px 30px; }
        .section h2 { font-size: 14px; color: #0066ff; border-bottom: 2px solid #0066ff; padding-bottom: 4px; margin-bottom: 10px; }
        .vuln-card { border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 12px; page-break-inside: avoid; }
        .vuln-header { background: #f8fafc; padding: 8px 12px; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; }
        .vuln-header h3 { font-size: 12px; }
        .vuln-body { padding: 10px 12px; }
        .vuln-body p { margin-bottom: 4px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 9px; font-weight: bold; color: #fff; }
        .badge-critical { background: #ef4444; }
        .badge-high { background: #f97316; }
        .badge-medium { background: #eab308; color: #1e293b; }
        .badge-low { background: #22c55e; }
        .badge-info { background: #3b82f6; }
        .stats-grid { display: table; width: 100%; margin-bottom: 16px; }
        .stat-box { display: table-cell; text-align: center; padding: 12px; border: 1px solid #e2e8f0; }
        .stat-box .num { font-size: 20px; font-weight: bold; color: #0066ff; }
        .stat-box .label { font-size: 9px; color: #64748b; text-transform: uppercase; }
        .footer { text-align: center; font-size: 9px; color: #94a3b8; margin-top: 20px; padding: 12px; border-top: 1px solid #e2e8f0; }
        .label-text { font-weight: bold; color: #64748b; font-size: 10px; }
        table.vuln-table { width: 100%; border-collapse: collapse; font-size: 10px; }
        table.vuln-table th { background: #f1f5f9; text-align: left; padding: 6px 8px; border: 1px solid #e2e8f0; }
        table.vuln-table td { padding: 6px 8px; border: 1px solid #e2e8f0; vertical-align: top; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ $report->name }}</h1>
        <p>Generated {{ now()->format('F j, Y \a\t g:i A') }} &bull; Bingo Security Agent</p>
    </div>

    @php
        $startedAt = $report->started_at ?? $report->scan_date;
        $completedAt = $report->completed_at ?? $report->created_at;
        $durationSecs = ($startedAt && $completedAt)
            ? max(0, $completedAt->getTimestamp() - $startedAt->getTimestamp())
            : null;
        $durationText = $durationSecs !== null
            ? sprintf('%dh %02dm %02ds', intdiv($durationSecs, 3600), intdiv($durationSecs % 3600, 60), $durationSecs % 60)
            : '—';
    @endphp

    <table class="meta-table">
        <tr><td>Target</td><td>{{ $report->target }}</td></tr>
        <tr><td>Scan Type</td><td>{{ ucfirst($report->scan_type) }}</td></tr>
        <tr><td>Status</td><td>{{ ucfirst($report->status) }}</td></tr>
        <tr><td>Started</td><td>{{ $startedAt?->format('M j, Y \a\t H:i:s') ?? '—' }}</td></tr>
        <tr><td>Completed</td><td>{{ $completedAt?->format('M j, Y \a\t H:i:s') ?? '—' }}</td></tr>
        <tr><td>Duration</td><td>{{ $durationText }}</td></tr>
        <tr><td>Report ID</td><td>{{ $report->id }}</td></tr>
    </table>

    <div class="section">
        <h2>Summary</h2>
        <div class="stats-grid">
            <div class="stat-box">
                <div class="num">{{ $report->vulnerabilities->count() }}</div>
                <div class="label">Total Vulnerabilities</div>
            </div>
            <div class="stat-box">
                <div class="num" style="color:#ef4444">{{ $report->vulnerabilities->where('severity','critical')->count() }}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-box">
                <div class="num" style="color:#f97316">{{ $report->vulnerabilities->where('severity','high')->count() }}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-box">
                <div class="num" style="color:#eab308">{{ $report->vulnerabilities->where('severity','medium')->count() }}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-box">
                <div class="num" style="color:#22c55e">{{ $report->vulnerabilities->where('severity','low')->count() }}</div>
                <div class="label">Low</div>
            </div>
        </div>

        @if($report->notes)
            <p style="margin-top:6px;color:#475569;">{{ $report->notes }}</p>
        @endif
    </div>

    @if($report->vulnerabilities->count())
    <div class="section">
        <h2>Vulnerabilities</h2>
        <table class="vuln-table">
            <thead>
                <tr>
                    <th style="width:5%">#</th>
                    <th style="width:25%">Name</th>
                    <th style="width:10%">Severity</th>
                    <th style="width:8%">CVSS</th>
                    <th style="width:12%">CWE</th>
                    <th style="width:20%">Affected Asset</th>
                    <th style="width:20%">Status</th>
                </tr>
            </thead>
            <tbody>
                @foreach($report->vulnerabilities as $i => $vuln)
                <tr>
                    <td>{{ $i + 1 }}</td>
                    <td><strong>{{ $vuln->name }}</strong></td>
                    <td>
                        <span class="badge badge-{{ $vuln->severity }}">{{ strtoupper($vuln->severity) }}</span>
                    </td>
                    <td>{{ $vuln->cvss_score ?? '—' }}</td>
                    <td>{{ $vuln->cwe_id ?? '—' }}</td>
                    <td>{{ $vuln->affected_asset ?? '—' }}</td>
                    <td>{{ $vuln->is_false_positive ? 'False Positive' : ucfirst($vuln->status) }}</td>
                </tr>
                @endforeach
            </tbody>
        </table>
    </div>

    <div class="section" style="page-break-before: always;">
        <h2>Vulnerability Details</h2>
        @foreach($report->vulnerabilities as $vuln)
        <div class="vuln-card">
            <div class="vuln-header">
                <h3>{{ $vuln->name }}</h3>
                <span class="badge badge-{{ $vuln->severity }}">{{ strtoupper($vuln->severity) }}</span>
            </div>
            <div class="vuln-body">
                @if($vuln->description)
                    <p><span class="label-text">Description:</span> {{ $vuln->description }}</p>
                @endif
                @if($vuln->affected_asset)
                    <p><span class="label-text">Affected Asset:</span> {{ $vuln->affected_asset }}</p>
                @endif
                @if($vuln->cwe_id)
                    <p><span class="label-text">CWE:</span> {{ $vuln->cwe_id }}{{ $vuln->cvss_score ? ' • CVSS '.$vuln->cvss_score : '' }}</p>
                @endif
                @if($vuln->payload)
                    <p style="margin-top:6px;"><span class="label-text">Payload:</span></p>
                    <pre style="background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:8px;border-radius:4px;font-size:9px;white-space:pre-wrap;word-wrap:break-word;">{{ $vuln->payload }}</pre>
                @endif
                @if($vuln->evidence)
                    <p style="margin-top:6px;"><span class="label-text">Proof / Evidence:</span></p>
                    <pre style="background:#f8fafc;border:1px solid #e2e8f0;padding:8px;border-radius:4px;font-size:9px;white-space:pre-wrap;word-wrap:break-word;">{{ $vuln->evidence }}</pre>
                @endif
                @if($vuln->remediation)
                    <p style="margin-top:6px;"><span class="label-text">Remediation:</span> {{ $vuln->remediation }}</p>
                @endif
                @if($vuln->references && count($vuln->references))
                    <p style="margin-top:6px;"><span class="label-text">References:</span></p>
                    <ul style="padding-left:16px;">
                        @foreach($vuln->references as $ref)
                            <li style="font-size:9px;"><a href="{{ $ref }}" style="color:#0066ff;text-decoration:none;">{{ $ref }}</a></li>
                        @endforeach
                    </ul>
                @endif
            </div>
        </div>
        @endforeach
    </div>
    @endif

    <div class="footer">
        &copy; {{ date('Y') }} Bingo Security Agent &bull; Confidential &bull; {{ $report->target }}
    </div>
</body>
</html>
