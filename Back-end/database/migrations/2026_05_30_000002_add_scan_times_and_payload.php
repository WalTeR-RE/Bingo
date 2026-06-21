<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('reports', function (Blueprint $table) {
            $table->timestamp('started_at')->nullable()->after('scan_date');
            $table->timestamp('completed_at')->nullable()->after('started_at');
        });

        Schema::table('vulnerabilities', function (Blueprint $table) {
            $table->text('payload')->nullable()->after('evidence');
        });
    }

    public function down(): void
    {
        Schema::table('reports', function (Blueprint $table) {
            $table->dropColumn(['started_at', 'completed_at']);
        });

        Schema::table('vulnerabilities', function (Blueprint $table) {
            $table->dropColumn('payload');
        });
    }
};
