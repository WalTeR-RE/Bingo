<?php

use Illuminate\Support\Facades\Schedule;

/*
|--------------------------------------------------------------------------
| Scheduled Tasks
|--------------------------------------------------------------------------
*/

Schedule::command('tokens:cleanup')->daily()->at('03:00');
Schedule::command('tokens:warn-expiring')->hourly();
Schedule::command('agents:check-status')->everyMinute();
