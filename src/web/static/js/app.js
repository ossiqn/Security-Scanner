/**
 * ScanLine — OSINT Security Scanner
 * Module  : Web Dashboard Frontend
 * Author  : OSSiqn Team
 * GitHub  : https://github.com/ossiqn
 * License : MIT © 2024 OSSiqn
 *
 * Açıklama (TR): ScanLine web dashboard'unun canlı veri,
 * WebSocket bağlantısı ve kullanıcı arayüzü mantığını
 * yöneten JavaScript modülü. OSSiqn tarafından üretilmiştir.
 *
 * Description (EN): JavaScript module managing live data,
 * WebSocket connection and UI logic for the ScanLine
 * web dashboard. Produced by OSSiqn.
 *
 * Produced by OSSiqn — github.com/ossiqn
 */

const PRODUCER = "OSSiqn";
const TOOL_VERSION = "1.0.0";

const state = {
    socket: null,
    currentPage: 1,
    pageSize: 50,
    totalFindings: 0,
    currentSeverityFilter: null,
    currentSourceFilter: null,
    selectedFinding: null,
    findings: [],
    connected: false
};

function initSocket() {
    state.socket = io({
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: Infinity
    });

    state.socket.on('connect', () => {
        state.connected = true;
        updateConnectionStatus('online');
        addTerminalLog('SYS', `WebSocket connected | ScanLine by ${PRODUCER}`);
        refreshFindings();
        refreshStats();
    });

    state.socket.on('disconnect', () => {
        state.connected = false;
        updateConnectionStatus('offline');
        addTerminalLog('WARN', `WebSocket disconnected | ${PRODUCER} Scanner`);
    });

    state.socket.on('reconnect', () => {
        updateConnectionStatus('online');
        addTerminalLog('SYS', `Reconnected | ScanLine by ${PRODUCER}`);
    });

    state.socket.on('new_finding', (finding) => {
        addTerminalLog(
            'FIND',
            `[${PRODUCER}] ${finding.severity?.toUpperCase()} — ${finding.title?.substring(0, 60)}`
        );
        prependFinding(finding);
        refreshStats();
    });

    state.socket.on('status_update', updateScannerStatus);
    state.socket.on('status', updateScannerStatus);
}

function updateConnectionStatus(status) {
    const indicator = document.getElementById('statusIndicator');
    const text      = document.getElementById('statusText');
    indicator.className = `status-indicator ${status}`;
    text.textContent = { online: 'ONLINE', offline: 'OFFLINE', scanning: 'SCANNING' }[status] || status.toUpperCase();
}

function updateScannerStatus(status) {
    const scanStatus  = document.getElementById('scanStatus');
    const currentTask = document.getElementById('currentTask');

    if (status.running) {
        scanStatus.textContent = 'SCANNING';
        scanStatus.style.color = 'var(--accent-cyan)';
        updateConnectionStatus('scanning');
    } else {
        scanStatus.textContent = 'IDLE';
        scanStatus.style.color = 'var(--text-secondary)';
        if (state.connected) updateConnectionStatus('online');
    }

    currentTask.textContent = status.current_task || '---';
    currentTask.title       = status.current_task || '';
}

async function refreshFindings() {
    try {
        const params = new URLSearchParams({
            limit:  state.pageSize,
            offset: (state.currentPage - 1) * state.pageSize
        });

        if (state.currentSeverityFilter) params.append('severity', state.currentSeverityFilter);
        if (state.currentSourceFilter)   params.append('source',   state.currentSourceFilter);

        const response = await fetch(`/api/findings?${params}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        state.findings = data.findings || [];
        renderFindings(state.findings);

        document.getElementById('loadingState').style.display = 'none';

    } catch (error) {
        addTerminalLog('ERR', `[${PRODUCER}] Failed to load findings: ${error.message}`);
    }
}

async function refreshStats() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) return;

        const stats    = await response.json();
        const severity = stats.severity_counts || {};

        state.totalFindings = stats.total || 0;

        document.getElementById('totalFindings').textContent = stats.total || 0;
        document.getElementById('recent24h').textContent     = stats.recent_24h || 0;
        document.getElementById('criticalCount').textContent = severity.critical || 0;
        document.getElementById('highCount').textContent     = severity.high     || 0;
        document.getElementById('mediumCount').textContent   = severity.medium   || 0;
        document.getElementById('lowCount').textContent      = severity.low      || 0;
        document.getElementById('allCount').textContent      = stats.total       || 0;
        document.getElementById('feedCount').textContent     = `${stats.total || 0} findings`;

        if (stats.scanner_status) updateScannerStatus(stats.scanner_status);

    } catch (error) {
        console.error(`[${PRODUCER}] Stats refresh failed:`, error);
    }
}

function renderFindings(findings) {
    const list       = document.getElementById('findingsList');
    const emptyState = document.getElementById('emptyState');

    list.innerHTML = '';

    if (!findings || findings.length === 0) {
        emptyState.style.display = 'flex';
        updatePagination(0);
        return;
    }

    emptyState.style.display = 'none';
    findings.forEach(finding => list.appendChild(createFindingCard(finding)));
    updatePagination(findings.length);
}

function createFindingCard(finding) {
    const card      = document.createElement('div');
    card.className  = `finding-card ${finding.severity || 'low'}`;
    card.dataset.id = finding.id;

    const ts      = new Date(finding.timestamp);
    const timeStr = ts.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const dateStr = ts.toLocaleDateString('en-US', { month: '2-digit', day: '2-digit' });

    card.innerHTML = `
        <div class="finding-header">
            <span class="finding-severity ${finding.severity || 'low'}">${(finding.severity || 'low').toUpperCase()}</span>
            <span class="finding-title">${escapeHtml(finding.title || 'Unknown Finding')}</span>
            <span class="finding-source">${(finding.source || 'unknown').toUpperCase()}</span>
        </div>
        <div class="finding-meta">
            <span>📁 ${escapeHtml(finding.category || 'unknown')}</span>
            <span>🕐 ${dateStr} ${timeStr}</span>
        </div>
        ${finding.url
            ? `<div class="finding-url">↗ ${escapeHtml(finding.url.substring(0, 120))}${finding.url.length > 120 ? '...' : ''}</div>`
            : ''}
    `;

    card.addEventListener('click', () => showFindingDetail(finding));
    return card;
}

function prependFinding(finding) {
    const list       = document.getElementById('findingsList');
    const emptyState = document.getElementById('emptyState');

    emptyState.style.display = 'none';

    const card = createFindingCard(finding);
    card.classList.add('new-finding');
    list.insertBefore(card, list.firstChild);

    const cards = list.querySelectorAll('.finding-card');
    if (cards.length > state.pageSize) list.removeChild(cards[cards.length - 1]);
}

function showFindingDetail(finding) {
    state.selectedFinding = finding;

    const detailContent   = document.getElementById('detailContent');
    const severityClass   = `severity-${finding.severity || 'low'}`;

    let rawDataHtml = '';
    if (finding.raw_data) {
        try {
            const raw = typeof finding.raw_data === 'string' ? JSON.parse(finding.raw_data) : finding.raw_data;
            rawDataHtml = `
                <div class="detail-field">
                    <div class="detail-field-label">RAW DATA</div>
                    <div class="detail-field-value">${escapeHtml(JSON.stringify(raw, null, 2))}</div>
                </div>`;
        } catch (_) {}
    }

    detailContent.innerHTML = `
        <div class="detail-field">
            <div class="detail-field-label">SEVERITY</div>
            <div class="detail-field-value ${severityClass}">${(finding.severity || 'unknown').toUpperCase()}</div>
        </div>
        <div class="detail-field">
            <div class="detail-field-label">TITLE</div>
            <div class="detail-field-value">${escapeHtml(finding.title || '')}</div>
        </div>
        <div class="detail-field">
            <div class="detail-field-label">CATEGORY</div>
            <div class="detail-field-value">${escapeHtml(finding.category || 'unknown')}</div>
        </div>
        <div class="detail-field">
            <div class="detail-field-label">SOURCE</div>
            <div class="detail-field-value">${escapeHtml(finding.source || 'unknown')}</div>
        </div>
        <div class="detail-field">
            <div class="detail-field-label">TIMESTAMP</div>
            <div class="detail-field-value">${new Date(finding.timestamp).toLocaleString()}</div>
        </div>
        ${finding.description ? `
        <div class="detail-field">
            <div class="detail-field-label">DESCRIPTION</div>
            <div class="detail-field-value">${escapeHtml(finding.description)}</div>
        </div>` : ''}
        ${finding.url ? `
        <div class="detail-field">
            <div class="detail-field-label">SOURCE URL</div>
            <div class="detail-field-value">
                <a href="${escapeHtml(finding.url)}" target="_blank" rel="noopener noreferrer" class="detail-url">${escapeHtml(finding.url)}</a>
            </div>
        </div>` : ''}
        ${rawDataHtml}
        <div class="detail-field" style="margin-top:12px; padding: 8px; border: 1px solid rgba(170,68,255,0.2); border-radius:2px; background:rgba(170,68,255,0.03);">
            <div class="detail-field-label" style="color:rgba(170,68,255,0.6);">PRODUCED BY</div>
            <div style="font-size:11px; color:rgba(170,68,255,0.8); letter-spacing:2px;">OSSiqn · github.com/ossiqn</div>
        </div>
        <div class="detail-action">
            <button class="btn-false-positive" onclick="markFalsePositive(${finding.id})">
                ⚑ MARK AS FALSE POSITIVE
            </button>
        </div>
    `;
}

function closeDetail() {
    document.getElementById('detailContent').innerHTML =
        '<div class="detail-empty">Select a finding to view details</div>';
    state.selectedFinding = null;
}

async function markFalsePositive(findingId) {
    try {
        const response = await fetch(`/api/findings/${findingId}/false_positive`, { method: 'POST' });

        if (response.ok) {
            const card = document.querySelector(`[data-id="${findingId}"]`);
            if (card) {
                card.style.transition  = 'all 0.3s';
                card.style.opacity     = '0';
                card.style.transform   = 'translateX(-20px)';
                setTimeout(() => card.remove(), 300);
            }
            closeDetail();
            addTerminalLog('SYS', `[${PRODUCER}] Finding ${findingId} marked as false positive`);
            refreshStats();
        }

    } catch (error) {
        addTerminalLog('ERR', `[${PRODUCER}] False positive marking failed: ${error.message}`);
    }
}

function filterBySeverity(severity) {
    state.currentSeverityFilter = severity;
    state.currentPage = 1;

    document.querySelectorAll('.severity-item').forEach(el => el.classList.remove('active'));

    const target = severity
        ? document.querySelector(`.severity-item.${severity}`)
        : document.querySelector('.severity-item.all');
    if (target) target.classList.add('active');

    addTerminalLog('FILTER', `[${PRODUCER}] Severity filter: ${severity ? severity.toUpperCase() : 'ALL'}`);
    refreshFindings();
}

function filterBySource(source) {
    state.currentSourceFilter = source;
    state.currentPage = 1;
    addTerminalLog('FILTER', `[${PRODUCER}] Source filter: ${source ? source.toUpperCase() : 'ALL'}`);
    refreshFindings();
}

function changePage(direction) {
    const newPage = state.currentPage + direction;
    if (newPage < 1) return;

    state.currentPage = newPage;
    refreshFindings();

    document.getElementById('pageInfo').textContent = `Page ${state.currentPage}`;
    document.getElementById('prevBtn').disabled     = state.currentPage === 1;
    document.querySelector('.findings-container').scrollTop = 0;
}

function updatePagination(resultCount) {
    document.getElementById('pageInfo').textContent = `Page ${state.currentPage}`;
    document.getElementById('prevBtn').disabled     = state.currentPage === 1;
    document.getElementById('nextBtn').disabled     = resultCount < state.pageSize;
}

function exportFindings() {
    const exportData = {
        exported_at:   new Date().toISOString(),
        produced_by:   PRODUCER,
        tool:          `ScanLine v${TOOL_VERSION}`,
        github:        "https://github.com/ossiqn",
        total_findings: state.findings.length,
        filters: {
            severity: state.currentSeverityFilter,
            source:   state.currentSourceFilter
        },
        findings: state.findings
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `scanline-ossiqn-${new Date().toISOString().split('T')[0]}.json`;
    a.click();

    URL.revokeObjectURL(url);
    addTerminalLog('SYS', `[${PRODUCER}] Exported ${state.findings.length} findings`);
}

function addTerminalLog(prefix, message) {
    const terminalLog = document.getElementById('terminalLog');
    const colors = {
        'SYS':    'var(--text-secondary)',
        'FIND':   'var(--medium)',
        'WARN':   'var(--high)',
        'ERR':    'var(--critical)',
        'FILTER': 'var(--info)'
    };
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false });

    terminalLog.innerHTML = `
        <span class="log-prefix" style="color:${colors[prefix] || 'var(--text-muted)'}">[${prefix}]</span>
        <span style="color:var(--text-muted);margin-right:8px;">${ts}</span>
        ${escapeHtml(message)}
    `;
}

function updateClock() {
    const clock = document.getElementById('headerTime');
    if (clock) clock.textContent = new Date().toUTCString().replace('GMT', 'UTC');
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

document.addEventListener('DOMContentLoaded', () => {
    console.log(`%cScanLine v${TOOL_VERSION} — Produced by ${PRODUCER}`, 'color:#aa44ff;font-size:14px;font-weight:bold;');
    console.log(`%cgithub.com/ossiqn`, 'color:#00ffcc;font-size:11px;');

    initSocket();
    setInterval(updateClock, 1000);
    updateClock();
    setInterval(refreshStats, 30000);
    addTerminalLog('SYS', `ScanLine v${TOOL_VERSION} initialized · Produced by ${PRODUCER} · github.com/ossiqn`);
});