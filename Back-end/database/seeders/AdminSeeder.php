<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class AdminSeeder extends Seeder
{
    public function run(): void
    {
        User::updateOrCreate(
            ['email' => 'admin@bingo.local'],
            [
                'id' => Str::uuid(),
                'name' => 'Bingo Admin',
                'email' => 'admin@bingo.local',
                'password' => Hash::make('BingoAdmin2026!'),
                'email_verified_at' => now(),
            ]
        );

        $this->command->info('');
        $this->command->info('╔══════════════════════════════════════════╗');
        $this->command->info('║     BINGO AGENT - Admin Account         ║');
        $this->command->info('╠══════════════════════════════════════════╣');
        $this->command->info('║  Email:    admin@bingo.local             ║');
        $this->command->info('║  Password: BingoAdmin2026!               ║');
        $this->command->info('╚══════════════════════════════════════════╝');
        $this->command->info('');
    }
}
