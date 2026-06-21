<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Report;
use App\Models\Vulnerability;
use App\Models\Incident;
use App\Models\Notification;
use App\Models\ActivityLog;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class TestDataSeeder extends Seeder
{
    public function run(): void
    {
        // Prefer admin so seeded data is visible in the default dashboard account.
        $user = User::where('email', 'admin@bingo.local')->first()
            ?? User::firstOrCreate(
                ['email' => 'test@bingo.local'],
                [
                    'name' => 'Test User',
                    'password' => Hash::make('password123'),
                ]
            );

        // Reports
        $report = Report::create([
            'user_id' => $user->id,
            'name' => 'Sample Security Report',
            'target' => 'https://example.com',
            'status' => 'completed',
            'created_by' => 'TestDataSeeder',
            'scan_date' => now()->subDays(2),
            'notes' => 'This is a seeded report for testing.',
        ]);

        // Vulnerabilities
        Vulnerability::create([
            'report_id' => $report->id,
            'name' => 'SQL Injection',
            'severity' => 'high',
            'status' => 'open',
            'description' => 'Sample SQLi vulnerability.',
            'affected_asset' => '/api/search',
            'cvss_score' => 8.2,
            'cwe_id' => 'CWE-89',
            'references' => ['https://cwe.mitre.org/data/definitions/89.html'],
        ]);
        Vulnerability::create([
            'report_id' => $report->id,
            'name' => 'Reflected XSS',
            'severity' => 'medium',
            'status' => 'open',
            'description' => 'Sample XSS vulnerability.',
            'affected_asset' => '/reports',
            'cvss_score' => 5.4,
            'cwe_id' => 'CWE-79',
            'references' => ['https://cwe.mitre.org/data/definitions/79.html'],
        ]);

        // Incidents
        $incident = Incident::create([
            'user_id' => $user->id,
            'title' => 'Unauthorized Access',
            'description' => 'Seeded incident for test.',
            'severity' => 'high',
            'status' => 'investigating',
            'source_ip' => '10.0.0.24',
            'destination_ip' => '10.0.0.5',
            'affected_asset' => 'api-gateway',
            'rule_triggered' => 'AUTH-FAILED-BURST',
            'detected_at' => now()->subHours(3),
            'action_taken' => 'Blocked source IP and opened investigation.',
        ]);

        // Notifications
        Notification::create([
            'user_id' => $user->id,
            'type' => 'critical_vuln',
            'title' => 'Test Notification',
            'message' => 'This is a seeded notification.',
            'entity_type' => 'Report',
            'entity_id' => $report->id,
        ]);

        // Activity Logs
        ActivityLog::create([
            'user_id' => $user->id,
            'action' => 'seeded_test',
            'entity_type' => 'Incident',
            'entity_id' => $incident->id,
            'details' => ['note' => 'Seeded log entry.'],
            'ip_address' => '127.0.0.1',
        ]);

        $this->command->info('Seeded test data for reports, vulnerabilities, incidents, notifications, and activity logs.');
    }
}
