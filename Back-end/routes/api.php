<?php

use App\Http\Controllers\AccessTokenController;
use App\Http\Controllers\ActivityLogController;
use App\Http\Controllers\AgentController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\IncidentController;
use App\Http\Controllers\NotificationController;
use App\Http\Controllers\ReportController;
use App\Http\Controllers\SearchController;
use App\Http\Controllers\VulnerabilityController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Public Auth Routes
|--------------------------------------------------------------------------
*/
Route::prefix('auth')->group(function () {
    Route::post('/login', [AuthController::class, 'login'])
        ->middleware('throttle:15,1');
    Route::post('/forgot-password', [AuthController::class, 'forgotPassword'])
        ->middleware('throttle:5,1');
    Route::post('/reset-password', [AuthController::class, 'resetPassword']);
});

/*
|--------------------------------------------------------------------------
| Protected Routes (Sanctum Auth)
|--------------------------------------------------------------------------
*/
Route::middleware('auth:sanctum')->group(function () {

    // Auth
    Route::post('/auth/logout', [AuthController::class, 'logout']);
    Route::get('/auth/me', [AuthController::class, 'me']);
    Route::put('/auth/profile', [AuthController::class, 'updateProfile']);
    Route::put('/auth/password', [AuthController::class, 'updatePassword']);

    // Access Tokens
    Route::get('/access-tokens', [AccessTokenController::class, 'index']);
    Route::post('/access-tokens', [AccessTokenController::class, 'store']);
    Route::delete('/access-tokens/{id}', [AccessTokenController::class, 'destroy']);
    Route::post('/access-tokens/{id}/regenerate', [AccessTokenController::class, 'regenerate']);
    Route::put('/access-tokens/{id}/extend', [AccessTokenController::class, 'extend']);

    // Reports
    Route::get('/reports', [ReportController::class, 'index']);
    Route::post('/reports', [ReportController::class, 'store']);
    Route::get('/reports/{id}', [ReportController::class, 'show']);
    Route::put('/reports/{id}', [ReportController::class, 'update']);
    Route::delete('/reports/{id}', [ReportController::class, 'destroy']);
    Route::get('/reports/{id}/export', [ReportController::class, 'export']);

    // Vulnerabilities
    Route::get('/reports/{reportId}/vulnerabilities', [VulnerabilityController::class, 'index']);
    Route::post('/reports/{reportId}/vulnerabilities', [VulnerabilityController::class, 'store']);
    Route::get('/vulnerabilities/{id}', [VulnerabilityController::class, 'show']);
    Route::put('/vulnerabilities/{id}', [VulnerabilityController::class, 'update']);
    Route::delete('/vulnerabilities/{id}', [VulnerabilityController::class, 'destroy']);
    Route::patch('/vulnerabilities/{id}/severity', [VulnerabilityController::class, 'changeSeverity']);
    Route::patch('/vulnerabilities/{id}/false-positive', [VulnerabilityController::class, 'markFalsePositive']);

    // Incidents (SIEM)
    Route::get('/incidents', [IncidentController::class, 'index']);
    Route::post('/incidents', [IncidentController::class, 'store']);
    Route::get('/incidents/{id}', [IncidentController::class, 'show']);
    Route::put('/incidents/{id}', [IncidentController::class, 'update']);
    Route::delete('/incidents/{id}', [IncidentController::class, 'destroy']);
    Route::patch('/incidents/{id}/status', [IncidentController::class, 'changeStatus']);
    Route::post('/incidents/{id}/notes', [IncidentController::class, 'addNote']);

    // Notifications
    Route::get('/notifications', [NotificationController::class, 'index']);
    Route::get('/notifications/count', [NotificationController::class, 'count']);
    Route::patch('/notifications/{id}/read', [NotificationController::class, 'markRead']);
    Route::post('/notifications/read-all', [NotificationController::class, 'markAllRead']);

    // Dashboard
    Route::get('/dashboard/stats', [DashboardController::class, 'stats']);

    // Search
    Route::get('/search', [SearchController::class, 'search']);

    // Activity Logs
    Route::get('/activity-logs', [ActivityLogController::class, 'index']);
});

/*
|--------------------------------------------------------------------------
| Agent Routes (Custom Token Auth)
|--------------------------------------------------------------------------
*/
Route::prefix('agent')->middleware('agent.auth')->group(function () {
    Route::post('/heartbeat', [AgentController::class, 'heartbeat']);
    Route::post('/reports', [AgentController::class, 'submitReport']);
    Route::post('/incidents', [AgentController::class, 'submitIncident']);
});
