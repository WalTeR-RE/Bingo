<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreReportRequest;
use App\Http\Requests\UpdateReportRequest;
use App\Services\ReportService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ReportController extends Controller
{
    public function __construct(private ReportService $reportService) {}

    public function index(Request $request): JsonResponse
    {
        $reports = $this->reportService->list($request->only(['status', 'search', 'per_page']));

        return response()->json($reports);
    }

    public function store(StoreReportRequest $request): JsonResponse
    {
        $report = $this->reportService->create($request->validated());

        return response()->json([
            'message' => 'Report created successfully',
            'report' => $report,
        ], 201);
    }

    public function show(string $id): JsonResponse
    {
        $report = $this->reportService->show($id);

        return response()->json(['report' => $report]);
    }

    public function update(UpdateReportRequest $request, string $id): JsonResponse
    {
        $report = $this->reportService->update($id, $request->validated());

        return response()->json([
            'message' => 'Report updated successfully',
            'report' => $report,
        ]);
    }

    public function destroy(string $id): JsonResponse
    {
        $this->reportService->delete($id);

        return response()->json(['message' => 'Report deleted successfully']);
    }

    public function export(Request $request, string $id)
    {
        return $this->reportService->export($id, $request->get('format', 'json'));
    }
}
