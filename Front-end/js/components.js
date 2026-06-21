/*  ───────────────────────────────────────────────────────────
 *   Bingo Agent – Shared UI Components
 *   Sidebar, Header, Toasts, Modals, Pagination, Dark-mode
 *  ─────────────────────────────────────────────────────────── */

/* ══════════════════════════════════════════════════════════════
   DARK MODE
   ══════════════════════════════════════════════════════════════ */
const DarkMode = (() => {
    const KEY = 'bingo_dark';
    const init = () => {
        if (localStorage.getItem(KEY) === 'true') document.documentElement.classList.add('dark');
        else document.documentElement.classList.remove('dark');
    };
    const toggle = () => {
        document.documentElement.classList.toggle('dark');
        localStorage.setItem(KEY, document.documentElement.classList.contains('dark'));
    };
    const isDark = () => document.documentElement.classList.contains('dark');
    return { init, toggle, isDark };
})();
DarkMode.init();

/* ══════════════════════════════════════════════════════════════
   TOAST NOTIFICATIONS
   ══════════════════════════════════════════════════════════════ */
function showToast(msg, type = 'success', duration = 4000) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'fixed top-6 right-6 z-[100] flex flex-col gap-3';
        document.body.appendChild(container);
    }
    const colors = {
        success: 'bg-emerald-500',
        error:   'bg-red-500',
        warning: 'bg-yellow-500',
        info:    'bg-brand-blue',
    };
    const icons = {
        success: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>',
        error:   '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>',
        warning: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>',
        info:    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>',
    };
    const el = document.createElement('div');
    el.className = `flex items-center gap-3 px-5 py-3.5 rounded-xl text-white text-sm font-semibold shadow-xl ${colors[type] || colors.info} animate-slide-up`;
    el.innerHTML = `<svg class="h-5 w-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">${icons[type] || icons.info}</svg><span>${msg}</span>`;
    container.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateX(40px)'; el.style.transition = 'all .3s'; setTimeout(() => el.remove(), 300); }, duration);
}

/* ══════════════════════════════════════════════════════════════
   MODAL
   ══════════════════════════════════════════════════════════════ */
function openModal(id)  { document.getElementById(id)?.classList.remove('hidden'); }
function closeModal(id) { document.getElementById(id)?.classList.add('hidden'); }

function createModal(id, title, bodyHtml, footerHtml = '') {
    const m = document.createElement('div');
    m.id = id;
    m.className = 'hidden fixed inset-0 z-50 flex items-center justify-center';
    m.innerHTML = `
        <div class="absolute inset-0 bg-black/40 backdrop-blur-sm" onclick="closeModal('${id}')"></div>
        <div class="relative bg-white dark:bg-slate-800 w-full max-w-lg mx-4 rounded-2xl shadow-2xl overflow-hidden animate-slide-up">
            <div class="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700">
                <h3 class="text-lg font-bold text-slate-900 dark:text-white">${title}</h3>
                <button onclick="closeModal('${id}')" class="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors">
                    <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                </button>
            </div>
            <div class="px-6 py-5 max-h-[60vh] overflow-y-auto modal-body">${bodyHtml}</div>
            ${footerHtml ? `<div class="px-6 py-4 border-t border-slate-200 dark:border-slate-700 flex justify-end gap-3">${footerHtml}</div>` : ''}
        </div>`;
    document.body.appendChild(m);
    return m;
}

/* ══════════════════════════════════════════════════════════════
   PAGINATION
   ══════════════════════════════════════════════════════════════ */
function renderPagination(container, meta, onChange) {
    if (!meta || meta.last_page <= 1) { container.innerHTML = ''; return; }
    let html = '<nav class="flex items-center gap-1">';
    const btn = (page, label, disabled, active = false) =>
        `<button ${disabled ? 'disabled' : ''} data-page="${page}" class="px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors
        ${active ? 'bg-brand-blue text-white shadow' : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700'}
        ${disabled ? 'opacity-40 cursor-not-allowed' : 'cursor-pointer'}">${label}</button>`;

    html += btn(meta.current_page - 1, '&laquo;', meta.current_page === 1);
    for (let p = 1; p <= meta.last_page; p++) {
        if (meta.last_page > 7 && p > 2 && p < meta.last_page - 1 && Math.abs(p - meta.current_page) > 1) {
            if (p === 3 || p === meta.last_page - 2) html += '<span class="px-1 text-slate-400">…</span>';
            continue;
        }
        html += btn(p, p, false, p === meta.current_page);
    }
    html += btn(meta.current_page + 1, '&raquo;', meta.current_page === meta.last_page);
    html += '</nav>';
    container.innerHTML = html;
    container.querySelectorAll('button[data-page]').forEach(b => b.addEventListener('click', () => {
        if (!b.disabled) onChange(parseInt(b.dataset.page));
    }));
}

/* ══════════════════════════════════════════════════════════════
   SIDEBAR
   ══════════════════════════════════════════════════════════════ */
function renderSidebar(activePage) {
    const links = [
        { name: 'Dashboard', icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/>', href: 'Dashboard.html' },
        { name: 'Reports',   icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>', href: 'Report.html' },
        { name: 'Settings',  icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>', href: 'Settings.html' },
    ];

    const active = (name) => name === activePage;
    const sidebarEl = document.getElementById('sidebar');
    if (!sidebarEl) return;

    sidebarEl.innerHTML = `
    <div class="p-8 pb-4">
        <div class="flex items-center gap-3 text-brand-blue mb-10">
            <div class="h-8 w-8 bg-brand-blue rounded-lg flex items-center justify-center text-white">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                </svg>
            </div>
            <span class="font-bold tracking-wider text-lg dark:text-white">Bingo Agent</span>
        </div>
        <nav class="space-y-2">
            ${links.map(l => `
            <a href="${l.href}" class="flex items-center gap-3 px-4 py-3 ${active(l.name)
                ? 'bg-blue-50 dark:bg-brand-blue/20 text-brand-blue rounded-xl font-bold shadow-sm ring-1 ring-blue-100 dark:ring-brand-blue/30'
                : 'text-slate-500 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-700/50 hover:text-brand-dark dark:hover:text-white rounded-xl font-bold'} transition-all duration-200 text-sm">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">${l.icon}</svg>
                ${l.name}
            </a>`).join('')}
        </nav>
    </div>
    <div class="mt-auto p-6 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50">
        <button id="btn-signout" class="flex items-center gap-3 text-red-500 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-500/10 px-4 py-3 rounded-xl transition-all font-bold text-sm w-full">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
            </svg>
            Sign Out
        </button>
    </div>`;

    document.getElementById('btn-signout')?.addEventListener('click', async () => {
        try { await API.auth.logout(); } catch {}
        API.clearAuth();
        window.location.href = 'Login.html';
    });
}

/* ══════════════════════════════════════════════════════════════
   HEADER  (Search + Notifications + Dark-mode + User)
   ══════════════════════════════════════════════════════════════ */
function renderHeader(titleHtml, subtitleHtml, rightSlot = '') {
    const headerEl = document.getElementById('page-header');
    if (!headerEl) return;

    headerEl.innerHTML = `
    <div class="flex flex-col md:flex-row md:items-end md:justify-between gap-4 mb-10">
        <div>
            <h2 class="text-3xl font-bold text-brand-dark dark:text-white tracking-tight mb-2">${titleHtml}</h2>
            <p class="text-slate-500 dark:text-slate-400 font-medium">${subtitleHtml}</p>
        </div>
        <div class="flex items-center gap-3">
            <!-- Search -->
            <div class="relative" id="search-wrapper">
                <input id="global-search" type="text" placeholder="Search…"
                    class="w-52 bg-slate-100 dark:bg-slate-700 border-0 rounded-xl py-2.5 pl-10 pr-4 text-sm focus:ring-2 focus:ring-brand-blue focus:bg-white dark:focus:bg-slate-600 dark:text-white transition-all outline-none placeholder-slate-400" />
                <svg class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
                <div id="search-results" class="hidden absolute top-full left-0 right-0 mt-2 bg-white dark:bg-slate-800 rounded-xl shadow-2xl border border-slate-200 dark:border-slate-700 max-h-80 overflow-y-auto z-50"></div>
            </div>

            <!-- Notifications -->
            <div class="relative" id="notif-wrapper">
                <button id="btn-notif" class="relative p-2.5 rounded-xl bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors">
                    <svg class="h-5 w-5 text-slate-600 dark:text-slate-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/>
                    </svg>
                    <span id="notif-badge" class="hidden absolute -top-1 -right-1 h-5 w-5 bg-red-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center">0</span>
                </button>
                <div id="notif-dropdown" class="hidden absolute right-0 top-full mt-2 w-80 bg-white dark:bg-slate-800 rounded-xl shadow-2xl border border-slate-200 dark:border-slate-700 z-50 overflow-hidden">
                    <div class="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-700">
                        <span class="font-bold text-sm text-slate-800 dark:text-white">Notifications</span>
                        <button id="btn-read-all" class="text-xs text-brand-blue font-semibold hover:underline">Mark all read</button>
                    </div>
                    <div id="notif-list" class="max-h-64 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-700"></div>
                </div>
            </div>

            <!-- Dark mode -->
            <button id="btn-dark" class="p-2.5 rounded-xl bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors" title="Toggle dark mode">
                <svg id="icon-sun" class="h-5 w-5 text-slate-600 hidden dark:block dark:text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/>
                </svg>
                <svg id="icon-moon" class="h-5 w-5 text-slate-600 block dark:hidden" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
                </svg>
            </button>

            ${rightSlot}
        </div>
    </div>`;

    document.getElementById('btn-dark')?.addEventListener('click', DarkMode.toggle);

    let searchTimer;
    const searchInput = document.getElementById('global-search');
    const searchResults = document.getElementById('search-results');
    searchInput?.addEventListener('input', () => {
        clearTimeout(searchTimer);
        const q = searchInput.value.trim();
        if (q.length < 2) { searchResults.classList.add('hidden'); return; }
        searchTimer = setTimeout(async () => {
            try {
                const data = await API.search.query(q);
                renderSearchResults(data, searchResults);
            } catch {}
        }, 350);
    });
    document.addEventListener('click', (e) => {
        if (!document.getElementById('search-wrapper')?.contains(e.target)) searchResults?.classList.add('hidden');
    });

    const notifBtn   = document.getElementById('btn-notif');
    const notifDrop  = document.getElementById('notif-dropdown');
    const notifBadge = document.getElementById('notif-badge');
    const notifList  = document.getElementById('notif-list');

    notifBtn?.addEventListener('click', () => notifDrop.classList.toggle('hidden'));
    document.addEventListener('click', (e) => {
        if (!document.getElementById('notif-wrapper')?.contains(e.target)) notifDrop?.classList.add('hidden');
    });

    document.getElementById('btn-read-all')?.addEventListener('click', async () => {
        try { await API.notifications.readAll(); refreshNotifications(); showToast('All notifications marked read'); } catch {}
    });

    refreshNotifications();
    setInterval(refreshNotifications, 30000);

    async function refreshNotifications() {
        try {
            const { count } = await API.notifications.count();
            if (count > 0) {
                notifBadge.textContent = count > 99 ? '99+' : count;
                notifBadge.classList.remove('hidden');
                notifBadge.classList.add('flex');
            } else {
                notifBadge.classList.add('hidden');
                notifBadge.classList.remove('flex');
            }

            const { notifications: list } = await API.notifications.list();
            if (!list || list.length === 0) {
                notifList.innerHTML = '<p class="text-center text-slate-400 text-sm py-6">No notifications</p>';
            } else {
                notifList.innerHTML = list.slice(0, 10).map(n => `
                    <div class="px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-700/50 cursor-pointer transition-colors ${n.read_at ? 'opacity-60' : ''}" data-nid="${n.id}">
                        <p class="text-sm font-semibold text-slate-800 dark:text-white">${escHtml(n.title)}</p>
                        <p class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">${escHtml(n.message || '')}</p>
                        <p class="text-[10px] text-slate-400 mt-1">${timeAgo(n.created_at)}</p>
                    </div>`).join('');
                notifList.querySelectorAll('[data-nid]').forEach(el => {
                    el.addEventListener('click', async () => {
                        try { await API.notifications.markRead(el.dataset.nid); refreshNotifications(); } catch {}
                    });
                });
            }
        } catch {}
    }
}

/* ══════════════════════════════════════════════════════════════
   SEARCH RESULTS RENDERER
   ══════════════════════════════════════════════════════════════ */
function renderSearchResults(data, container) {
    if (!data) { container.classList.add('hidden'); return; }
    const sections = [];

    if (data.reports?.length) {
        sections.push({ title: 'Reports', items: data.reports.map(r => ({ label: r.title || r.name, sub: r.subtitle || r.target, href: `ReportDetail.html?id=${r.id}` })) });
    }
    if (data.vulnerabilities?.length) {
        sections.push({ title: 'Vulnerabilities', items: data.vulnerabilities.map(v => ({ label: v.title || v.name, sub: `${v.severity} • ${v.subtitle || v.affected_asset || ''}`, href: `ReportDetail.html?id=${v.report_id}` })) });
    }
    if (data.incidents?.length) {
        sections.push({ title: 'Incidents', items: data.incidents.map(i => ({ label: i.title, sub: `${i.severity} • ${i.subtitle || i.source_ip || ''}`, href: `Report.html?tab=siem&incident=${i.id}` })) });
    }

    if (!sections.length) {
        container.innerHTML = '<p class="text-center text-slate-400 text-sm py-5">No results found</p>';
        container.classList.remove('hidden');
        return;
    }

    container.innerHTML = sections.map(s => `
        <div class="p-2">
            <p class="text-[10px] font-bold text-slate-400 uppercase tracking-widest px-2 py-1">${s.title}</p>
            ${s.items.slice(0, 5).map(i => `
                <a href="${i.href}" class="flex flex-col px-3 py-2 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors">
                    <span class="text-sm font-semibold text-slate-800 dark:text-white">${escHtml(i.label)}</span>
                    <span class="text-xs text-slate-400">${escHtml(i.sub)}</span>
                </a>`).join('')}
        </div>`).join('<hr class="border-slate-100 dark:border-slate-700"/>');
    container.classList.remove('hidden');
}

/* ══════════════════════════════════════════════════════════════
   UTILITIES
   ══════════════════════════════════════════════════════════════ */
function escHtml(str) {
    const d = document.createElement('div'); d.textContent = str || ''; return d.innerHTML;
}

function timeAgo(dateStr) {
    const diff = (Date.now() - new Date(dateStr).getTime()) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff/86400)}d ago`;
    return new Date(dateStr).toLocaleDateString();
}

function formatDate(str) {
    if (!str) return '—';
    return new Date(str).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function formatDateTime(str) {
    if (!str) return '—';
    return new Date(str).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function severityBadge(sev) {
    const map = {
        critical: 'bg-red-100 text-red-800 dark:bg-red-500/20 dark:text-red-400',
        high:     'bg-orange-100 text-orange-800 dark:bg-orange-500/20 dark:text-orange-400',
        medium:   'bg-yellow-100 text-yellow-800 dark:bg-yellow-500/20 dark:text-yellow-400',
        low:      'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/20 dark:text-emerald-400',
        informational: 'bg-blue-100 text-blue-800 dark:bg-blue-500/20 dark:text-blue-400',
        info:     'bg-blue-100 text-blue-800 dark:bg-blue-500/20 dark:text-blue-400',
    };
    return `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold uppercase ${map[sev] || map.info}">${sev || 'unknown'}</span>`;
}

function statusBadge(status) {
    const map = {
        open:          'bg-yellow-100 text-yellow-800 dark:bg-yellow-500/20 dark:text-yellow-400',
        completed:     'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/20 dark:text-emerald-400',
        in_progress:   'bg-blue-100 text-blue-800 dark:bg-blue-500/20 dark:text-blue-400',
        new:           'bg-purple-100 text-purple-800 dark:bg-purple-500/20 dark:text-purple-400',
        investigating: 'bg-blue-100 text-blue-800 dark:bg-blue-500/20 dark:text-blue-400',
        resolved:      'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/20 dark:text-emerald-400',
        false_positive:'bg-slate-100 text-slate-600 dark:bg-slate-500/20 dark:text-slate-400',
        escalated:     'bg-red-100 text-red-800 dark:bg-red-500/20 dark:text-red-400',
        accepted:      'bg-indigo-100 text-indigo-800 dark:bg-indigo-500/20 dark:text-indigo-400',
    };
    const label = (status || 'unknown').replace(/_/g, ' ');
    return `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold capitalize ${map[status] || 'bg-slate-100 text-slate-600'}">${label}</span>`;
}

function showLoading(el) {
    el.innerHTML = `
    <div class="flex items-center justify-center py-20">
        <svg class="animate-spin h-8 w-8 text-brand-blue" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
        </svg>
    </div>`;
}

function requireAuth() {
    if (!API.getToken()) { window.location.href = 'Login.html'; return false; }
    return true;
}
