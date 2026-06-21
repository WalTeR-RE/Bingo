<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdateReportRequest extends FormRequest
{
    public function authorize(): bool { return true; }

    public function rules(): array
    {
        return [
            'name' => 'sometimes|string|max:255',
            'target' => 'sometimes|string|max:255',
            'scan_date' => 'sometimes|date',
            'notes' => 'sometimes|string|max:5000',
            'status' => 'sometimes|in:open,in_progress,completed',
        ];
    }
}
