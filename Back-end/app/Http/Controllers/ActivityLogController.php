<?php

namespace App\Http\Controllers;

use App\Models\ActivityLog;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class ActivityLogController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $query = ActivityLog::where('user_id', Auth::id());

        if ($request->has('action')) {
            $query->where('action', $request->action);
        }

        if ($request->has('from')) {
            $query->where('created_at', '>=', $request->from);
        }

        if ($request->has('to')) {
            $query->where('created_at', '<=', $request->to);
        }

        $logs = $query->orderBy('created_at', 'desc')
            ->paginate($request->get('per_page', 25));

        return response()->json($logs);
    }
}
