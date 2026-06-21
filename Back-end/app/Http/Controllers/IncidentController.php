<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreIncidentRequest;
use App\Http\Requests\UpdateIncidentRequest;
use App\Services\IncidentService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class IncidentController extends Controller
{
    public function __construct(private IncidentService $incidentService) {}

    public function index(Request $request): JsonResponse
    {
        $incidents = $this->incidentService->list(
            $request->only(['severity', 'status', 'search', 'from', 'to', 'per_page'])
        );

        return response()->json($incidents);
    }

    public function store(StoreIncidentRequest $request): JsonResponse
    {
        $incident = $this->incidentService->create($request->validated());

        return response()->json([
            'message' => 'Incident created successfully',
            'incident' => $incident,
        ], 201);
    }

    public function show(string $id): JsonResponse
    {
        $incident = $this->incidentService->show($id);

        return response()->json(['incident' => $incident]);
    }

    public function update(UpdateIncidentRequest $request, string $id): JsonResponse
    {
        $incident = $this->incidentService->update($id, $request->validated());

        return response()->json([
            'message' => 'Incident updated successfully',
            'incident' => $incident,
        ]);
    }

    public function destroy(string $id): JsonResponse
    {
        $this->incidentService->delete($id);

        return response()->json(['message' => 'Incident deleted successfully']);
    }

    public function changeStatus(Request $request, string $id): JsonResponse
    {
        $request->validate([
            'status' => 'required|in:new,investigating,resolved,false_positive,escalated',
        ]);

        $incident = $this->incidentService->changeStatus($id, $request->status);

        return response()->json([
            'message' => 'Incident status updated',
            'incident' => $incident,
        ]);
    }

    public function addNote(Request $request, string $id): JsonResponse
    {
        $request->validate(['content' => 'required|string|max:2000']);

        $note = $this->incidentService->addNote($id, $request->content);

        return response()->json([
            'message' => 'Note added',
            'note' => $note,
        ], 201);
    }
}
