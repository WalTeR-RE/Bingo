<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreIncidentRequest extends FormRequest
{
    public function authorize(): bool { return true; }

    public function rules(): array
    {
        return [
            'title' => 'required|string|max:255',
            'description' => 'sometimes|string',
            'severity' => 'required|in:critical,high,medium,low,informational',
            'source_ip' => 'sometimes|string|max:45',
            'destination_ip' => 'sometimes|string|max:45',
            'affected_asset' => 'sometimes|string|max:255',
            'rule_triggered' => 'sometimes|string|max:255',
            'raw_log' => 'sometimes|array',
            'detected_at' => 'sometimes|date',
            'action_taken' => 'sometimes|string',
        ];
    }
}
