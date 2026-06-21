<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class ExtendAccessTokenRequest extends FormRequest
{
    public function authorize(): bool { return true; }

    public function rules(): array
    {
        return [
            'days' => 'required|integer|in:7,14,30',
        ];
    }
}
