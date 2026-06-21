<?php

namespace App\Http\Controllers;

use App\Services\DashboardService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class DashboardController extends Controller
{
    public function __construct(private DashboardService $dashboardService) {}

    public function stats(Request $request): JsonResponse
    {
        $range = $request->get('range', 'all');

        return response()->json($this->dashboardService->stats($range));
    }
}
