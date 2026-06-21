<?php

namespace App\Http\Controllers;

use App\Services\SearchService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class SearchController extends Controller
{
    public function __construct(private SearchService $searchService) {}

    public function search(Request $request): JsonResponse
    {
        $request->validate(['q' => 'required|string|min:2|max:100']);

        return response()->json($this->searchService->search($request->q));
    }
}
