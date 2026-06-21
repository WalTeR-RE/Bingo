/*  ───────────────────────────────────────────────────────────
 *   Bingo Agent – API Client
 *   Centralised fetch wrapper for all back-end calls.
 *  ─────────────────────────────────────────────────────────── */

const API = (() => {
    const BASE = 'http://localhost:8000/api';

    /* ── Token helpers ─────────────────────────────────────── */
    const getToken  = () => localStorage.getItem('bingo_token');
    const setToken  = (t) => localStorage.setItem('bingo_token', t);
    const clearAuth = () => { localStorage.removeItem('bingo_token'); localStorage.removeItem('bingo_user'); };

    /* ── Core request ──────────────────────────────────────── */
    async function request(method, path, body = null, extra = {}) {
        const headers = { 'Accept': 'application/json' };
        const token = getToken();
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const opts = { method, headers, ...extra };

        if (body && !(body instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        } else if (body instanceof FormData) {
            opts.body = body;               // let browser set multipart boundary
        }

        const res = await fetch(`${BASE}${path}`, opts);

        if (res.status === 401) {
            clearAuth();
            if (!window.location.pathname.endsWith('Login.html')) {
                window.location.href = 'Login.html';
            }
            throw { status: 401, message: 'Unauthenticated' };
        }

        if (extra.responseType === 'blob') return res.blob();

        const json = await res.json().catch(() => ({}));
        if (!res.ok) throw { status: res.status, ...json };
        return json;
    }

    /* ── Convenience methods ───────────────────────────────── */
    const get    = (p, extra)    => request('GET',    p, null, extra);
    const post   = (p, b, extra) => request('POST',   p, b, extra);
    const put    = (p, b)        => request('PUT',    p, b);
    const patch  = (p, b)        => request('PATCH',  p, b);
    const del    = (p)           => request('DELETE', p);

    /* ─────────── Auth ─────────────────────────────────────── */
    const auth = {
        login:          (data) => post('/auth/login', data),
        logout:         ()     => post('/auth/logout'),
        me:             ()     => get('/auth/me'),
        updateProfile:  (data) => {
            const fd = new FormData();
            Object.entries(data).forEach(([k,v]) => { if (v !== undefined && v !== null) fd.append(k, v); });
            fd.append('_method', 'PUT');
            return request('POST', '/auth/profile', fd);
        },
        updatePassword: (data) => put('/auth/password', data),
        forgotPassword: (data) => post('/auth/forgot-password', data),
        resetPassword:  (data) => post('/auth/reset-password', data),
    };

    /* ─────────── Access Tokens ─────────────────────────────── */
    const tokens = {
        list:       ()         => get('/access-tokens'),
        create:     (data)     => post('/access-tokens', data),
        remove:     (id)       => del(`/access-tokens/${id}`),
        regenerate: (id)       => post(`/access-tokens/${id}/regenerate`),
        extend:     (id, data) => put(`/access-tokens/${id}/extend`, data),
    };

    /* ─────────── Reports ──────────────────────────────────── */
    const reports = {
        list:   (params = '') => get(`/reports${params ? '?' + params : ''}`),
        show:   (id)          => get(`/reports/${id}`),
        create: (data)        => post('/reports', data),
        update: (id, data)    => put(`/reports/${id}`, data),
        remove: (id)          => del(`/reports/${id}`),
        exportPdf: (id)       => get(`/reports/${id}/export?format=pdf`, { responseType: 'blob' }),
        exportJson: (id)      => get(`/reports/${id}/export?format=json`),
    };

    /* ─────────── Vulnerabilities ──────────────────────────── */
    const vulns = {
        listForReport: (rid, params = '') => get(`/reports/${rid}/vulnerabilities${params ? '?' + params : ''}`),
        show:          (id)               => get(`/vulnerabilities/${id}`),
        create:        (rid, data)        => post(`/reports/${rid}/vulnerabilities`, data),
        update:        (id, data)         => put(`/vulnerabilities/${id}`, data),
        remove:        (id)               => del(`/vulnerabilities/${id}`),
        changeSeverity:(id, data)         => patch(`/vulnerabilities/${id}/severity`, data),
        markFP:        (id)               => patch(`/vulnerabilities/${id}/false-positive`),
    };

    /* ─────────── Incidents (SIEM) ─────────────────────────── */
    const incidents = {
        list:         (params = '') => get(`/incidents${params ? '?' + params : ''}`),
        show:         (id)          => get(`/incidents/${id}`),
        create:       (data)        => post('/incidents', data),
        update:       (id, data)    => put(`/incidents/${id}`, data),
        remove:       (id)          => del(`/incidents/${id}`),
        changeStatus: (id, data)    => patch(`/incidents/${id}/status`, data),
        addNote:      (id, data)    => post(`/incidents/${id}/notes`, data),
    };

    /* ─────────── Notifications ────────────────────────────── */
    const notifications = {
        list:     ()   => get('/notifications'),
        count:    ()   => get('/notifications/count'),
        markRead: (id) => patch(`/notifications/${id}/read`),
        readAll:  ()   => post('/notifications/read-all'),
    };

    /* ─────────── Dashboard ────────────────────────────────── */
    const dashboard = {
        stats: (params = '') => get(`/dashboard/stats${params ? '?' + params : ''}`),
    };

    /* ─────────── Search ───────────────────────────────────── */
    const search = {
        query: (q) => get(`/search?q=${encodeURIComponent(q)}`),
    };

    /* ─────────── Activity Logs ────────────────────────────── */
    const activityLogs = {
        list: (params = '') => get(`/activity-logs${params ? '?' + params : ''}`),
    };

    return {
        getToken, setToken, clearAuth,
        auth, tokens, reports, vulns, incidents,
        notifications, dashboard, search, activityLogs,
    };
})();
