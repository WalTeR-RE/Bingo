<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('vulnerabilities', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('report_id')->constrained()->cascadeOnDelete();
            $table->string('name');
            $table->enum('severity', ['critical', 'high', 'medium', 'low', 'informational'])->default('medium');
            $table->enum('status', ['open', 'resolved', 'false_positive', 'accepted'])->default('open');
            $table->text('description')->nullable();
            $table->string('affected_asset')->nullable();
            $table->text('evidence')->nullable();
            $table->text('remediation')->nullable();
            $table->decimal('cvss_score', 3, 1)->nullable();
            $table->string('cwe_id')->nullable();
            $table->json('references')->nullable();
            $table->timestamps();
            $table->softDeletes();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('vulnerabilities');
    }
};
