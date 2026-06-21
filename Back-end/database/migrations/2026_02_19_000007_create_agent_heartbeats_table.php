<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('agent_heartbeats', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('access_token_id')->constrained()->cascadeOnDelete();
            $table->string('agent_name');
            $table->enum('agent_type', ['offensive', 'defensive']);
            $table->enum('status', ['idle', 'scanning', 'monitoring', 'error'])->default('idle');
            $table->string('ip_address')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('last_seen_at');
            $table->timestamps();

            $table->index(['access_token_id', 'last_seen_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('agent_heartbeats');
    }
};
