<?php

namespace App\Http\Controllers;

use App\Services\NotificationService;
use Illuminate\Http\JsonResponse;

class NotificationController extends Controller
{
    public function __construct(private NotificationService $notificationService) {}

    public function index(): JsonResponse
    {
        return response()->json([
            'notifications' => $this->notificationService->listUnread(),
        ]);
    }

    public function count(): JsonResponse
    {
        return response()->json([
            'count' => $this->notificationService->unreadCount(),
        ]);
    }

    public function markRead(string $id): JsonResponse
    {
        $this->notificationService->markAsRead($id);

        return response()->json(['message' => 'Notification marked as read']);
    }

    public function markAllRead(): JsonResponse
    {
        $this->notificationService->markAllRead();

        return response()->json(['message' => 'All notifications marked as read']);
    }
}
