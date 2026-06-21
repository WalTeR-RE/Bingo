<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdateIncidentRequest extends FormRequest
{
    public function authorize(): bool { return true; }

    public function rules(): array
    {
        return [
            'title' => 'sometimes|string|max:255',
            'description' => 'sometimes|string',
            'severity' => 'sometimes|in:critical,high,medium,low,informational',
            'status' => 'sometimes|in:new,investigating,resolved,false_positive,escalated',
            'action_taken' => 'sometimes|string',
        ];
    }
}
