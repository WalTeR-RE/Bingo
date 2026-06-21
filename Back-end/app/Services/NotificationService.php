<?php

namespace App\Services;

use App\Models\Notification;
use Illuminate\Support\Facades\Auth;

class NotificationService
{
    public function listUnread()
    {
        return Notification::where('user_id', Auth::id())
            ->unread()
            ->orderBy('created_at', 'desc')
            ->limit(20)
            ->get();
    }

    public function unreadCount(): int
    {
        return Notification::where('user_id', Auth::id())
            ->unread()
            ->count();
    }

    public function markAsRead(string $id): void
    {
        $notification = Notification::where('user_id', Auth::id())->findOrFail($id);
        $notification->markAsRead();
    }

    public function markAllRead(): void
    {
        Notification::where('user_id', Auth::id())
            ->unread()
            ->update(['read_at' => now()]);
    }

    public static function notify(
        string $userId,
        string $type,
        string $title,
        ?string $message = null,
        ?string $entityType = null,
        ?string $entityId = null
    ): Notification {
        return Notification::create([
            'user_id' => $userId,
            'type' => $type,
            'title' => $title,
            'message' => $message,
            'entity_type' => $entityType,
            'entity_id' => $entityId,
        ]);
    }
}
