<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('incidents', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('user_id')->constrained()->cascadeOnDelete();
            $table->string('title');
            $table->text('description')->nullable();
            $table->enum('severity', ['critical', 'high', 'medium', 'low', 'informational'])->default('medium');
            $table->enum('status', ['new', 'investigating', 'resolved', 'false_positive', 'escalated'])->default('new');
            $table->string('source_ip')->nullable();
            $table->string('destination_ip')->nullable();
            $table->string('affected_asset')->nullable();
            $table->string('rule_triggered')->nullable();
            $table->json('raw_log')->nullable();
            $table->timestamp('detected_at')->nullable();
            $table->timestamp('resolved_at')->nullable();
            $table->text('action_taken')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('incidents');
    }
};
