<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreAccessTokenRequest;
use App\Http\Requests\ExtendAccessTokenRequest;
use App\Services\AccessTokenService;
use Illuminate\Http\JsonResponse;

class AccessTokenController extends Controller
{
    public function __construct(private AccessTokenService $tokenService) {}

    public function index(): JsonResponse
    {
        return response()->json(['tokens' => $this->tokenService->list()]);
    }

    public function store(StoreAccessTokenRequest $request): JsonResponse
    {
        $result = $this->tokenService->generate(
            $request->name,
            $request->expiration_days
        );

        return response()->json([
            'message' => 'Access token created successfully. Copy it now — it won\'t be shown again.',
            'token' => [
                'id' => $result['token']->id,
                'name' => $result['token']->name,
                'expires_at' => $result['token']->expires_at->toISOString(),
            ],
            'plain_token' => $result['plain_token'],
        ], 201);
    }

    public function destroy(string $id): JsonResponse
    {
        $this->tokenService->delete($id);

        return response()->json(['message' => 'Access token deleted successfully']);
    }

    public function regenerate(string $id): JsonResponse
    {
        $result = $this->tokenService->regenerate($id);

        return response()->json([
            'message' => 'Access token regenerated. Copy the new token — it won\'t be shown again.',
            'token' => [
                'id' => $result['token']->id,
                'name' => $result['token']->name,
                'expires_at' => $result['token']->expires_at->toISOString(),
            ],
            'plain_token' => $result['plain_token'],
        ]);
    }

    public function extend(ExtendAccessTokenRequest $request, string $id): JsonResponse
    {
        $token = $this->tokenService->extend($id, $request->days);

        return response()->json([
            'message' => 'Access token expiration extended',
            'token' => [
                'id' => $token->id,
                'name' => $token->name,
                'expires_at' => $token->expires_at->toISOString(),
            ],
        ]);
    }
}
