/**
 * Farad Ai Benchmark — Dashboard Frontend Logic
 * WebSocket real-time progress + REST API integration
 */

// ─── State ──────────────────────────────────────────────────────────────────

const state = {
    ws: null,
    currentPage: 'dashboard',
    activeRunId: null,
    datasets: [],
    models: [],
    runs: [],
    reconnectAttempts: 0,
    maxReconnect: 10,
    modelsAdmin: {
        providers: [],
        cloudModels: [],
    },
    history: {
        page: 1,
        limit: 25,
        total: 0,
        totalPages: 1,
        dataset: '',
        model: '',
        status: 'all',
        items: [],
        selectedRunIds: new Set(),
        filterDebounceTimer: null,
    },
    reports: {
        list: [],
        activeReportId: null,
        activeReport: null,
    },
    testCases: {
        page: 1,
        limit: 50,
        dataset: 'all',
        threat_domain: 'all',
        tier: 'all',
        status: 'all',
        search: '',
        sortBy: 'id',
        sortOrder: 'asc',
        searchDebounceTimer: null,
        total: 0,
        totalPages: 1,
        cases: [],
        filtersLoaded: false,
        eventsBound: false,
        activeCaseId: null,
        activeCasePayload: null,
    },
};

// ─── DOM Helpers ────────────────────────────────────────────────────────────

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ─── WebSocket ──────────────────────────────────────────────────────────────

function connectWS() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    state.ws = new WebSocket(`${protocol}//${location.host}/ws`);

    state.ws.onopen = () => {
        state.reconnectAttempts = 0;
        updateConnectionBadge(true);
        console.log('[WS] Connected');
    };

    state.ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        handleWSMessage(msg);
    };

    state.ws.onclose = () => {
        updateConnectionBadge(false);
        if (state.reconnectAttempts < state.maxReconnect) {
            state.reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, state.reconnectAttempts), 15000);
            setTimeout(connectWS, delay);
        }
    };

    state.ws.onerror = () => {
        state.ws.close();
    };
}

function updateConnectionBadge(connected) {
    const dot = $('#connection-dot');
    const text = $('#connection-text');
    if (dot) {
        dot.classList.toggle('connected', connected);
    }
    if (text) {
        text.textContent = connected ? 'Live' : 'Disconnected';
    }
}

// ─── WebSocket Message Handler ──────────────────────────────────────────────

function handleWSMessage(msg) {
    switch (msg.type) {
        case 'progress':
            updateProgress(msg);
            break;
        case 'run_started':
            showToast(`Benchmark started: ${msg.total_cases} cases`, 'info');
            resetLiveMetrics();
            break;
        case 'run_completed':
            handleRunCompleted(msg);
            break;
        case 'error':
            showToast(`Error: ${msg.message}`, 'error');
            resetProgress();
            break;
        case 'pong':
            break;
    }
}

// ─── Progress Updates ───────────────────────────────────────────────────────

function updateProgress(data) {
    // Show progress section, hide idle
    const idle = $('#idle-state');
    const progress = $('#progress-section');
    if (idle) idle.style.display = 'none';
    if (progress) progress.style.display = 'flex';

    // Update ring
    const pct = data.pct || 0;
    const ring = $('#progress-ring-fill');
    if (ring) {
        const circumference = 2 * Math.PI * 90; // r=90
        const offset = circumference - (pct / 100) * circumference;
        ring.style.strokeDashoffset = offset;
    }

    // Update text
    setText('#progress-pct', `${Math.round(pct)}%`);
    setText('#progress-evaluated', `${data.evaluated}/${data.total}`);
    setText('#progress-throughput', `${data.throughput}`);
    setText('#progress-elapsed', `${data.elapsed_secs}s`);

    // Update live metrics (all 6 metrics real-time)
    if (data.accuracy !== undefined) updateMetric('accuracy', data.accuracy, '%');
    if (data.precision !== undefined) updateMetric('precision', data.precision, '%');
    if (data.recall !== undefined) updateMetric('recall', data.recall, '%');
    if (data.f1 !== undefined) updateMetric('f1', data.f1, '%');
    if (data.fpr !== undefined) updateMetric('fpr', data.fpr, '%');
    if (data.avg_latency_ms !== undefined) updateMetric('latency', data.avg_latency_ms, 'ms');

    // Update confusion matrix
    setText('#cm-tp', data.tp);
    setText('#cm-tn', data.tn);
    setText('#cm-fp', data.fp);
    setText('#cm-fn', data.fn);
}

function updateMetric(id, value, suffix) {
    const el = $(`#metric-${id}`);
    if (!el) return;

    if (value === null || value === undefined || isNaN(value)) {
        el.textContent = '—';
        el.className = 'metric-value neutral';
        return;
    }

    el.textContent = `${value}${suffix}`;

    // Color coding
    el.className = 'metric-value';
    if (id === 'fpr') {
        if (value <= 3) el.classList.add('good');
        else if (value <= 8) el.classList.add('warn');
        else el.classList.add('bad');
    } else if (suffix === '%') {
        if (value >= 85) el.classList.add('good');
        else if (value >= 60) el.classList.add('warn');
        else el.classList.add('bad');
    } else {
        el.classList.add('info');
    }
}

function resetLiveMetrics() {
    ['accuracy', 'precision', 'recall', 'f1', 'fpr', 'latency'].forEach(id => {
        const el = $(`#metric-${id}`);
        if (el) {
            el.textContent = '—';
            el.className = id === 'latency' ? 'metric-value info' : 'metric-value neutral';
        }
    });
    setText('#cm-tp', '0');
    setText('#cm-tn', '0');
    setText('#cm-fp', '0');
    setText('#cm-fn', '0');
    setText('#progress-pct', '0%');
    setText('#progress-evaluated', '0/0');
    setText('#progress-throughput', '0');
    setText('#progress-elapsed', '0s');
    const ring = $('#progress-ring-fill');
    if (ring) {
        const circumference = 2 * Math.PI * 90;
        ring.style.strokeDashoffset = circumference;
    }
    const actions = $('#progress-complete-actions');
    if (actions) actions.style.display = 'none';
}

function handleRunCompleted(data) {
    showToast(`✅ Benchmark completed! F1: ${data.f1}% — ${data.duration_secs}s`, 'success');

    // Update final metrics
    updateMetric('accuracy', data.accuracy, '%');
    updateMetric('precision', data.precision, '%');
    updateMetric('recall', data.recall, '%');
    updateMetric('f1', data.f1, '%');
    updateMetric('fpr', data.fpr, '%');
    updateMetric('latency', data.avg_latency_ms, 'ms');

    // Show button to view results
    const actions = $('#progress-complete-actions');
    const viewBtn = $('#btn-view-last-run');
    if (actions && viewBtn) {
        actions.style.display = 'block';
        viewBtn.onclick = () => viewRunDetail(data.run_id);
    }

    // Re-enable start button
    const btn = $('#btn-start');
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = '🚀 Start Benchmark';
    }

    state.activeRunId = null;

    // Refresh history
    loadRuns();
}

function resetProgress() {
    const idle = $('#idle-state');
    const progress = $('#progress-section');
    if (idle) idle.style.display = 'flex';
    if (progress) progress.style.display = 'none';

    resetLiveMetrics();

    const btn = $('#btn-start');
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = '🚀 Start Benchmark';
    }
    state.activeRunId = null;
}

// ─── API Calls ──────────────────────────────────────────────────────────────

async function loadDatasets() {
    try {
        const res = await fetch('/api/datasets');
        state.datasets = await res.json();
        renderDatasetSelect();
    } catch (e) {
        console.error('Failed to load datasets:', e);
    }
}

async function loadModels() {
    try {
        const res = await fetch('/api/models');
        state.models = await res.json();
        renderModelSelect();
    } catch (e) {
        console.error('Failed to load models:', e);
    }
}

async function loadRuns() {
    try {
        const res = await fetch('/api/runs');
        state.runs = await res.json();
        renderRunsTable();
    } catch (e) {
        console.error('Failed to load runs:', e);
    }
}

async function startBenchmark() {
    const datasetSelect = $('#dataset-select');
    const modelSelect = $('#model-select');

    if (!datasetSelect.value || !modelSelect.value) {
        showToast('Please select a dataset and model', 'error');
        return;
    }

    const dataset = state.datasets.find(d => d.id === datasetSelect.value);
    if (!dataset) return;

    // Read tier scope (all, static, semantic)
    const tierInput = document.querySelector('input[name="tier_scope"]:checked');
    const tierFilter = tierInput ? tierInput.value : 'all';

    // Read L1 toggle (true / false)
    const l1Input = document.querySelector('input[name="enable_l1"]:checked');
    const enableL1 = l1Input ? (l1Input.value === 'true') : true;

    const btn = $('#btn-start');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner">⏳</span> Running...';

    const actions = $('#progress-complete-actions');
    if (actions) actions.style.display = 'none';

    // Reset progress display & all live metrics to initial clean state
    resetLiveMetrics();

    try {
        const res = await fetch('/api/runs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                dataset_path: dataset.path,
                dataset_name: dataset.name || dataset.id,
                tier_filter: tierFilter,
                model_name: modelSelect.value,
                enable_l1: enableL1,
            })
        });
        const data = await res.json();

        if (data.error) {
            showToast(`Error: ${data.error}`, 'error');
            btn.disabled = false;
            btn.innerHTML = '🚀 Start Benchmark';
            return;
        }

        state.activeRunId = data.run_id;
        showToast(`Run started: ${data.run_id}`, 'info');
    } catch (e) {
        showToast(`Connection error: ${e.message}`, 'error');
        btn.disabled = false;
        btn.innerHTML = '🚀 Start Benchmark';
    }
}

async function viewRunDetail(runId) {
    try {
        const res = await fetch(`/api/runs/${runId}`);
        const data = await res.json();
        if (data.error) {
            showToast(data.error, 'error');
            return;
        }
        renderRunDetailModal(data);
    } catch (e) {
        showToast(`Failed to load details: ${e.message}`, 'error');
    }
}

async function deleteRun(runId, event) {
    event.stopPropagation();
    if (!confirm(`Are you sure you want to delete "${runId}"?`)) return;

    try {
        await fetch(`/api/runs/${runId}`, { method: 'DELETE' });
        showToast(`${runId} deleted`, 'info');
        loadRuns();
    } catch (e) {
        showToast(`Silinemedi: ${e.message}`, 'error');
    }
}

// ─── Renderers ──────────────────────────────────────────────────────────────

function updateTierCounts(ds) {
    if (!ds) {
        setText('#tier-count-all', '—');
        setText('#tier-count-static', '—');
        setText('#tier-count-semantic', '—');
        return;
    }
    setText('#tier-count-all', (ds.rows || 0).toLocaleString());
    setText('#tier-count-static', (ds.static_rows || 0).toLocaleString());
    setText('#tier-count-semantic', (ds.semantic_rows || 0).toLocaleString());
    updateTierDescription();
}

function updateTierDescription() {
    const tierInput = document.querySelector('input[name="tier_scope"]:checked');
    const tier = tierInput ? tierInput.value : 'all';
    const datasetSelect = $('#dataset-select');
    const ds = state.datasets.find(d => d.id === (datasetSelect ? datasetSelect.value : ''));

    const descEl = $('#tier-scope-desc');
    if (!descEl) return;

    if (tier === 'static') {
        const cnt = ds ? (ds.static_rows || 0).toLocaleString() : '1,000';
        descEl.textContent = `⚡ Static Scope: Rules detectable solely via microsecond regex/DLP (${cnt} cases - STATIC_CAPABLE).`;
    } else if (tier === 'semantic') {
        const cnt = ds ? (ds.semantic_rows || 0).toLocaleString() : '1,000';
        descEl.textContent = `🧠 Semantic Scope: Complex scenarios requiring L2 deep semantic analysis (${cnt} cases - SEMANTIC_REQUIRED).`;
    } else {
        const cnt = ds ? (ds.rows || 0).toLocaleString() : '2,000';
        descEl.textContent = `🌐 All: Complete set of static rule and semantic test cases (${cnt} cases).`;
    }
}

function onTierRadioChanged() {
    const tierInputs = document.querySelectorAll('input[name="tier_scope"]');
    tierInputs.forEach(input => {
        const label = input.closest('.tier-radio-btn');
        if (label) {
            label.classList.toggle('active', input.checked);
        }
    });
    updateTierDescription();
}

function onL1RadioChanged() {
    const l1Inputs = document.querySelectorAll('input[name="enable_l1"]');
    l1Inputs.forEach(input => {
        const card = input.closest('.l1-radio-card');
        if (card) {
            card.classList.toggle('active', input.checked);
        }
    });
}

function onModelChanged() {
    const modelSelect = $('#model-select');
    if (!modelSelect) return;
    const modelId = modelSelect.value;
    const model = state.models.find(m => m.id === modelId);

    const hint = $('#model-hint');
    if (hint && model) {
        hint.textContent = model.description || '';
    }

    const disableCard = $('#l1-card-disable');
    const disableInput = disableCard ? disableCard.querySelector('input') : null;
    const enableCard = $('#l1-card-enable');
    const enableInput = enableCard ? enableCard.querySelector('input') : null;

    if (modelId === 'l1-rules') {
        if (disableCard) disableCard.classList.add('disabled');
        if (disableInput) disableInput.disabled = true;
        if (enableInput) enableInput.checked = true;
        if (enableCard) enableCard.classList.add('active');
        if (disableCard) disableCard.classList.remove('active');
        if (hint) hint.textContent = 'L1 Declarative Static Rule Engine (<0.2ms regex/DLP).';
    } else {
        if (disableCard) disableCard.classList.remove('disabled');
        if (disableInput) disableInput.disabled = false;
    }
}

function renderDatasetSelect() {
    const select = $('#dataset-select');
    if (!select) return;
    select.innerHTML = '<option value="">Select dataset...</option>';

    const coreDatasets = state.datasets.filter(d => d.is_core);
    const domainDatasets = state.datasets.filter(d => !d.is_core);

    if (coreDatasets.length > 0) {
        const coreGroup = document.createElement('optgroup');
        coreGroup.label = '🌟 Core Benchmark Datasets';
        coreDatasets.forEach(ds => {
            const opt = document.createElement('option');
            opt.value = ds.id;
            opt.textContent = `${ds.name} (${ds.rows.toLocaleString()} rows, ${ds.size_kb} KB)`;
            coreGroup.appendChild(opt);
        });
        select.appendChild(coreGroup);
    }

    if (domainDatasets.length > 0) {
        const domainGroup = document.createElement('optgroup');
        domainGroup.label = '🔬 Specialized Threat & Vulnerability Suites';
        domainDatasets.forEach(ds => {
            const opt = document.createElement('option');
            opt.value = ds.id;
            opt.textContent = `${ds.name} (${ds.rows.toLocaleString()} rows, ${ds.size_kb} KB)`;
            domainGroup.appendChild(opt);
        });
        select.appendChild(domainGroup);
    }

    // Default to Farad-Decision-Bench-v1.0 (or legacy smoke_test_2k), fallback to first dataset
    const coreDs = state.datasets.find(d => d.id === 'farad_decision_bench_v1' || d.id === 'smoke_test_2k') || state.datasets[0];
    if (coreDs) {
        select.value = coreDs.id;
        const hint = $('#dataset-hint');
        if (hint) {
            hint.textContent = `${coreDs.rows.toLocaleString()} rows · ${coreDs.size_kb} KB · ${coreDs.filename}`;
        }
        updateTierCounts(coreDs);
    }
}

function renderModelSelect() {
    const select = $('#model-select');
    if (!select) return;
    select.innerHTML = '';
    state.models.forEach(m => {
        const opt = document.createElement('option');
        opt.value = m.id;
        opt.textContent = `${m.icon} ${m.name}`;
        if (m.status === 'unavailable') {
            opt.textContent += ' (N/A)';
            opt.disabled = true;
        }
        select.appendChild(opt);
    });

    if (state.models.length > 0) {
        select.selectedIndex = 0;
        onModelChanged();
    }
}

function renderRunsTable() {
    const tbody = $('#runs-tbody');
    if (!tbody) return;
    if (state.runs.length === 0) {
        tbody.innerHTML = `
            <tr><td colspan="9" style="text-align:center; padding: 40px; color: var(--text-tertiary);">
                No benchmarks have been run yet
            </td></tr>`;
        return;
    }

    tbody.innerHTML = state.runs.slice(0, 15).map(r => {
        const statusBadge = getStatusBadge(r.status);
        const startedAt = r.started_at ? new Date(r.started_at).toLocaleString('en-US') : '—';
        return `
            <tr onclick="viewRunDetail('${r.run_id}')">
                <td><span class="mono text-sm">${escapeHtml(r.run_id)}</span></td>
                <td>${escapeHtml(r.dataset_name)}</td>
                <td>${escapeHtml(r.model_name)}</td>
                <td class="mono">${r.total_cases || '—'}</td>
                <td class="mono ${getMetricClass(r.accuracy)}">${r.accuracy ? r.accuracy + '%' : '—'}</td>
                <td class="mono ${getMetricClass(r.f1)}">${r.f1 ? r.f1 + '%' : '—'}</td>
                <td class="mono">${r.avg_latency_ms ? r.avg_latency_ms + 'ms' : '—'}</td>
                <td>${statusBadge}</td>
                <td>
                    <span class="text-sm text-muted">${startedAt}</span>
                    <button class="btn btn-danger btn-sm" onclick="deleteRun('${r.run_id}', event)" title="Delete" style="margin-left:8px;">✕</button>
                </td>
            </tr>`;
    }).join('');
}

function getStatusBadge(status) {
    const map = {
        completed: '<span class="badge badge-completed">✓ Completed</span>',
        budget_stopped: '<span class="badge badge-budget">💰 Budget Cap</span>',
        running: '<span class="badge badge-running">⟳ Running</span>',
        error: '<span class="badge badge-error">✕ Error</span>',
        pending: '<span class="badge badge-pending">◌ Pending</span>',
    };
    return map[status] || `<span class="badge badge-pending">${escapeHtml(status || 'unknown')}</span>`;
}

function getMetricClass(value) {
    if (!value) return '';
    if (value >= 85) return 'case-correct';
    if (value >= 60) return '';
    return 'case-incorrect';
}

function renderRunDetailModal(data) {
    const modal = $('#run-detail-modal');
    if (!modal) return;

    // Header info
    setText('#modal-run-id', data.run_id);
    setText('#modal-dataset', `${data.dataset_name} · ${data.model_name}`);
    setText('#modal-status', data.status);

    // Metrics
    const l1Decided = (data.case_results || []).filter(c => c.decided_by === 'L1').length;
    const casesCount = (data.case_results || []).length;

    const metricsHtml = [
        { label: 'Accuracy', value: data.accuracy, suffix: '%' },
        { label: 'Precision', value: data.precision, suffix: '%' },
        { label: 'Recall', value: data.recall, suffix: '%' },
        { label: 'F1 Score', value: data.f1, suffix: '%' },
        { label: 'FPR', value: data.fpr, suffix: '%' },
        ...(l1Decided > 0 && casesCount > 0 ? [
            { label: '⚡ L1 Offload', value: Math.round((l1Decided / casesCount) * 100), suffix: '%' }
        ] : []),
        { label: 'Avg Latency', value: data.avg_latency_ms, suffix: 'ms' },
        { label: 'P95 Latency', value: data.p95_latency_ms, suffix: 'ms' },
        { label: 'Duration', value: data.duration_secs, suffix: 's' },
    ].map(m => {
        const cls = m.suffix === '%' ? (m.value >= 85 ? 'good' : m.value >= 60 ? 'warn' : 'bad') : 'info';
        return `<div class="metric-card">
            <div class="metric-label">${m.label}</div>
            <div class="metric-value ${cls}">${m.value ?? '—'}<span class="metric-suffix">${m.suffix}</span></div>
        </div>`;
    }).join('');
    $('#modal-metrics').innerHTML = metricsHtml;

    // Confusion matrix
    setText('#modal-tp', data.tp);
    setText('#modal-tn', data.tn);
    setText('#modal-fp', data.fp);
    setText('#modal-fn', data.fn);

    // Category breakdown
    const catContainer = $('#modal-categories');
    if (catContainer && data.category_stats) {
        const cats = Object.entries(data.category_stats);
        catContainer.innerHTML = cats.map(([name, stats]) => {
            const pct = stats.total > 0 ? Math.round((stats.correct / stats.total) * 100) : 0;
            const cls = pct >= 80 ? 'high' : pct >= 50 ? 'mid' : 'low';
            return `
                <div class="category-bar">
                    <span class="category-name">${name}</span>
                    <div class="category-fill-container">
                        <div class="category-fill ${cls}" style="width: ${pct}%"></div>
                    </div>
                    <span class="category-pct ${cls === 'high' ? 'case-correct' : cls === 'low' ? 'case-incorrect' : ''}">${pct}%</span>
                </div>`;
        }).join('');
    }

    // Case results — store for detail popup and filtering
    state.currentRunCases = data.case_results || [];
    state.caseFilter = 'all';
    state.caseSearch = '';

    const searchInput = $('#case-search-input');
    if (searchInput) searchInput.value = '';
    $$('.case-filter-chip').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === 'all');
    });

    const casesSection = $('#modal-cases-section');
    if (casesSection) {
        if (state.currentRunCases.length > 0) {
            casesSection.style.display = 'block';
            renderFilteredCases();
        } else {
            casesSection.style.display = 'none';
        }
    }

    modal.classList.add('open');
}

function renderFilteredCases() {
    const cases = state.currentRunCases || [];
    const search = (state.caseSearch || '').toLowerCase().trim();
    const filter = state.caseFilter || 'all';

    // Calculate filter counts
    const counts = {
        all: cases.length,
        mismatch: cases.filter(c => !c.correct).length,
        fp: cases.filter(c => !c.is_malicious && c.predicted_blocked).length,
        fn: cases.filter(c => c.is_malicious && !c.predicted_blocked).length,
        correct: cases.filter(c => c.correct).length,
    };

    setText('#count-all', counts.all);
    setText('#count-mismatch', counts.mismatch);
    setText('#count-fp', counts.fp);
    setText('#count-fn', counts.fn);
    setText('#count-correct', counts.correct);

    // Apply filtering
    const filtered = [];
    cases.forEach((c, idx) => {
        if (filter === 'mismatch' && c.correct) return;
        if (filter === 'fp' && (c.is_malicious || !c.predicted_blocked)) return;
        if (filter === 'fn' && (!c.is_malicious || c.predicted_blocked)) return;
        if (filter === 'correct' && !c.correct) return;

        if (search) {
            const haystack = `${c.id} ${c.domain} ${c.tool_name} ${c.cwe || ''} ${c.source || ''} ${c.context || ''} ${c.tool_arguments || ''}`.toLowerCase();
            if (!haystack.includes(search)) return;
        }

        filtered.push({ ...c, _originalIdx: idx });
    });

    const caseTbody = $('#modal-cases-tbody');
    if (!caseTbody) return;

    if (filtered.length === 0) {
        caseTbody.innerHTML = `<tr><td colspan="8" class="empty-state" style="padding: var(--space-6); text-align: center; color: var(--text-tertiary);">No test cases match the current criteria.</td></tr>`;
        return;
    }

    caseTbody.innerHTML = filtered.map(c => `
        <tr class="case-row" onclick="showCaseDetail(${c._originalIdx})" title="Click to view payload details">
            <td class="case-result-icon ${c.correct ? 'case-correct' : 'case-incorrect'}">${c.correct ? '✓' : '✕'}</td>
            <td class="mono font-semibold">${c.id}</td>
            <td><span class="badge-domain">${c.domain}</span></td>
            <td class="mono text-sm">${c.tool_name}</td>
            <td>${c.is_malicious ? '🔴 Malicious' : '🟢 Benign'}</td>
            <td>${c.predicted_blocked ? '🛑 Blocked' : '✅ Allowed'}${c.decided_by ? ` <span style="font-size:0.75rem; font-weight:600; padding:1px 5px; border-radius:4px; background:${c.decided_by==='L1'?'rgba(245,158,11,0.15)':'rgba(59,130,246,0.15)'}; color:${c.decided_by==='L1'?'#f59e0b':'#3b82f6'}">${c.decided_by}</span>` : ''}</td>
            <td class="mono">${c.latency_ms}ms</td>
            <td class="case-expand-icon">▸</td>
        </tr>
    `).join('');
}

function filterCasesBy(filterType) {
    state.caseFilter = filterType;
    $$('.case-filter-chip').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filterType);
    });
    renderFilteredCases();
}

function handleCaseSearch(val) {
    state.caseSearch = val;
    renderFilteredCases();
}

function copyPayload(btn) {
    const codeEl = btn.closest('.case-detail-section').querySelector('code');
    if (!codeEl) return;
    const text = codeEl.innerText;
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = '✅ Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
            btn.innerHTML = orig;
            btn.classList.remove('copied');
        }, 1500);
    }).catch(err => {
        console.error('Copy failed:', err);
    });
}

function showCaseDetail(idx) {
    const c = state.currentRunCases[idx];
    if (!c) return;

    const detail = $('#case-detail-drawer');
    if (!detail) return;

    // Populate detail drawer
    const correctClass = c.correct ? 'case-correct' : 'case-incorrect';
    const verdictIcon = c.correct ? '✅' : '❌';

    detail.innerHTML = `
        <div class="case-detail-header">
            <div class="case-detail-title">
                <span class="case-result-icon ${correctClass}" style="font-size: 1.2rem;">${c.correct ? '✓' : '✕'}</span>
                <span>${c.id}</span>
            </div>
            <button class="modal-close" onclick="closeCaseDetail()">✕</button>
        </div>

        <div class="case-detail-meta">
            <div class="case-meta-chip">
                <span class="case-meta-label">Source</span>
                <span class="case-meta-value">${c.source || '—'}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Domain</span>
                <span class="case-meta-value">${c.domain}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Tier</span>
                <span class="case-meta-value mono" style="color: #6366f1; font-weight: 600;">${c.analysis_tier || 'STATIC_CAPABLE'}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">CWE</span>
                <span class="case-meta-value">${c.cwe || '—'}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Tool</span>
                <span class="case-meta-value mono">${c.tool_name}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Latency</span>
                <span class="case-meta-value mono">${c.latency_ms}ms</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Confidence</span>
                <span class="case-meta-value mono">${(c.confidence * 100).toFixed(1)}%</span>
            </div>
            ${c.decided_by ? `
            <div class="case-meta-chip">
                <span class="case-meta-label">Decided By</span>
                <span class="case-meta-value mono font-semibold" style="color: ${c.decided_by === 'L1' ? '#f59e0b' : '#3b82f6'};">
                    ${c.decided_by === 'L1' ? '⚡ L1 Static' : '🍎 L2 MLX'}
                </span>
            </div>` : ''}
            ${c.offload_saved_ms ? `
            <div class="case-meta-chip">
                <span class="case-meta-label">Offload Saved</span>
                <span class="case-meta-value mono" style="color: #10b981; font-weight: 600;">~${c.offload_saved_ms}ms</span>
            </div>` : ''}
        </div>

        <div class="case-detail-verdict">
            <div class="verdict-box ${c.is_malicious ? 'verdict-malicious' : 'verdict-benign'}">
                <span class="verdict-label">Expected</span>
                <span class="verdict-value">${c.is_malicious ? '🔴 Malicious (Block)' : '🟢 Benign (Allow)'}</span>
            </div>
            <div class="verdict-arrow">${c.correct ? '✅' : '❌'}</div>
            <div class="verdict-box ${c.predicted_blocked ? 'verdict-blocked' : 'verdict-allowed'}">
                <span class="verdict-label">Predicted</span>
                <span class="verdict-value">${c.predicted_blocked ? '🛑 Blocked' : '✅ Allowed'}</span>
            </div>
        </div>

        ${c.context ? `
        <div class="case-detail-section">
            <div class="case-section-title">📋 Context</div>
            <div class="case-context-box">${escapeHtml(c.context)}</div>
        </div>` : ''}

        <div class="case-detail-section">
            <div class="flex items-center justify-between" style="margin-bottom: var(--space-2);">
                <div class="case-section-title" style="margin-bottom: 0;">📦 Tool Arguments (Payload)</div>
                <button class="copy-payload-btn" onclick="copyPayload(this)" title="Copy payload to clipboard">📋 Copy</button>
            </div>
            <pre class="case-payload-box"><code>${syntaxHighlight(c.tool_arguments || '{}')}</code></pre>
        </div>
    `;

    const overlay = $('#drawer-overlay');
    if (overlay) overlay.classList.add('active');
    detail.classList.add('open');
}

function closeCaseDetail(updateHash = true) {
    const detail = $('#case-detail-drawer');
    const overlay = $('#drawer-overlay');
    if (detail) detail.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
    state.testCases.activeCaseId = null;
    state.testCases.activeCasePayload = null;

    if (updateHash && state.currentPage === 'test-cases') {
        updateUrlHash(false);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function syntaxHighlight(jsonStr) {
    // Simple JSON syntax highlighter
    const escaped = escapeHtml(jsonStr);
    return escaped
        .replace(/"([^"]+)":/g, '<span class="json-key">"$1"</span>:')
        .replace(/: "([^"]*)"/g, ': <span class="json-string">"$1"</span>')
        .replace(/: (\d+\.?\d*)/g, ': <span class="json-number">$1</span>')
        .replace(/: (true|false)/g, ': <span class="json-bool">$1</span>')
        .replace(/: (null)/g, ': <span class="json-null">$1</span>');
}

function closeModal() {
    const modal = $('#run-detail-modal');
    if (modal) modal.classList.remove('open');
}

// ─── Compare Runs Logic ───────────────────────────────────────────────────

state.compareData = null;
state.currentDiscrepancies = [];
state.compareFilter = 'all';

function populateCompareSelects() {
    const selA = $('#compare-run-a-select');
    const selB = $('#compare-run-b-select');
    if (!selA || !selB) return;

    const completed = (state.runs || []).filter(r => r.status === 'completed');
    if (completed.length === 0) {
        selA.innerHTML = '<option value="">No completed runs found</option>';
        selB.innerHTML = '<option value="">No completed runs found</option>';
        return;
    }

    // Group runs by dataset
    const datasets = {};
    completed.forEach(r => {
        const ds = r.dataset_name || 'Other';
        if (!datasets[ds]) datasets[ds] = [];
        datasets[ds].push(r);
    });

    let htmlA = '<option value="">Select Run A (Baseline)...</option>';
    for (const [dsName, runs] of Object.entries(datasets)) {
        htmlA += `<optgroup label="Dataset: ${dsName} (${runs.length} runs)">`;
        runs.forEach(r => {
            const dt = r.started_at ? new Date(r.started_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : '';
            htmlA += `<option value="${r.run_id}">${r.model_name} (${r.run_id}, F1: ${r.f1 || 0}%, ${dt})</option>`;
        });
        htmlA += `</optgroup>`;
    }
    selA.innerHTML = htmlA;

    // Pick a default dataset that has >= 2 runs for immediate comparison readiness
    let defaultRunA = null;
    for (const runs of Object.values(datasets)) {
        if (runs.length >= 2) {
            defaultRunA = runs[0].run_id;
            break;
        }
    }
    if (!defaultRunA && completed.length > 0) {
        defaultRunA = completed[0].run_id;
    }

    if (defaultRunA) {
        selA.value = defaultRunA;
    }

    onCompareRunAChanged();
}

function onCompareRunAChanged() {
    const selA = $('#compare-run-a-select');
    const selB = $('#compare-run-b-select');
    const btn = $('#btn-compare-execute');
    if (!selA || !selB) return;

    const runAId = selA.value;
    if (!runAId) {
        selB.innerHTML = '<option value="">Select Run A first...</option>';
        selB.disabled = true;
        if (btn) btn.disabled = true;
        return;
    }

    const runA = (state.runs || []).find(r => r.run_id === runAId);
    if (!runA) return;

    const targetDataset = runA.dataset_name;

    // Filter candidates strictly to the SAME dataset and different run_id
    const candidates = (state.runs || []).filter(r =>
        r.status === 'completed' &&
        r.dataset_name === targetDataset &&
        r.run_id !== runAId
    );

    if (candidates.length === 0) {
        selB.innerHTML = `<option value="">No other models to compare for this dataset (${targetDataset})</option>`;
        selB.disabled = true;
        if (btn) btn.disabled = true;
        return;
    }

    selB.disabled = false;
    if (btn) btn.disabled = false;

    selB.innerHTML = candidates.map(r => {
        const dt = r.started_at ? new Date(r.started_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : '';
        return `<option value="${r.run_id}">${r.model_name} (${r.run_id}, F1: ${r.f1 || 0}%, ${dt})</option>`;
    }).join('');

    selB.selectedIndex = 0;
}

async function executeComparison() {
    const selA = $('#compare-run-a-select');
    const selB = $('#compare-run-b-select');
    const runA = selA ? selA.value : '';
    const runB = selB ? selB.value : '';

    if (!runA || !runB) {
        showToast('Please select two runs to compare.', 'warn');
        return;
    }

    const btn = $('#btn-compare-execute');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '⏳ Calculating...';
    }

    try {
        const res = await fetch(`/api/runs/${runA}/compare/${runB}?filter=all&limit=250`);
        const data = await res.json();
        if (data.error) {
            showToast(data.error, 'error');
            return;
        }

        state.compareData = data;
        state.compareFilter = 'all';
        renderComparisonResults(data);
        showToast(`Comparison complete: ${data.agreement_stats.discrepant_verdicts} divergent verdicts found.`, 'info');
    } catch (e) {
        showToast(`Comparison error: ${e.message}`, 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '⚡ Compare';
        }
    }
}

function renderComparisonResults(data) {
    const container = $('#compare-results-container');
    if (!container) return;
    container.style.display = 'block';

    const rA = data.run_a;
    const rB = data.run_b;
    const ast = data.agreement_stats;

    // Header info
    setText('#compare-model-a-title', rA.model_name);
    setText('#compare-run-a-id', rA.run_id);
    setText('#compare-model-b-title', rB.model_name);
    setText('#compare-run-b-id', rB.run_id);
    setText('#compare-dataset-badge', `Dataset: ${rA.dataset_name} (${ast.total_common} common cases)`);

    const thA = $('#th-model-a');
    const thB = $('#th-model-b');
    if (thA) thA.textContent = `${rA.model_name}`;
    if (thB) thB.textContent = `${rB.model_name}`;

    // Calculate deltas
    const f1Delta = (rB.f1 - rA.f1).toFixed(1);
    const f1DeltaPrefix = f1Delta > 0 ? '+' : '';
    const latDelta = (rB.avg_latency_ms - rA.avg_latency_ms).toFixed(2);
    const latDeltaPrefix = latDelta > 0 ? '+' : '';

    // Macro metric cards
    const metricsHtml = [
        { label: 'Agreement Rate', value: ast.agreement_rate_pct, suffix: '%', cls: ast.agreement_rate_pct >= 80 ? 'good' : 'warn' },
        { label: 'Discrepant Verdicts', value: ast.discrepant_verdicts, suffix: ' cases', cls: ast.discrepant_verdicts === 0 ? 'good' : 'info' },
        { label: 'F1 Score Delta (B - A)', value: `${f1DeltaPrefix}${f1Delta}`, suffix: '%', cls: f1Delta >= 0 ? 'good' : 'bad' },
        { label: 'Avg. Latency Delta (B - A)', value: `${latDeltaPrefix}${latDelta}`, suffix: 'ms', cls: latDelta <= 0 ? 'good' : 'warn' },
        { label: 'A Missed ➔ B Caught', value: ast.a_missed_b_caught, suffix: ' cases', cls: 'good' },
        { label: 'B Missed ➔ A Caught', value: ast.b_missed_a_caught, suffix: ' cases', cls: 'bad' },
    ].map(m => `
        <div class="metric-card">
            <div class="metric-label">${m.label}</div>
            <div class="metric-value ${m.cls}">${m.value}<span class="metric-suffix">${m.suffix}</span></div>
        </div>
    `).join('');

    $('#compare-metrics-grid').innerHTML = metricsHtml;

    // Filter counters
    setText('#count-disc-all', ast.discrepant_verdicts);
    setText('#count-disc-b-better', ast.a_missed_b_caught);
    setText('#count-disc-a-better', ast.b_missed_a_caught);
    setText('#count-disc-fp', (ast.discrepant_verdicts - ast.a_missed_b_caught - ast.b_missed_a_caught));

    // Render discrepancy rows
    renderDiscrepancyRows(data.discrepancies || []);
}

function renderDiscrepancyRows(discrepancies) {
    state.currentDiscrepancies = discrepancies;
    const tbody = $('#discrepancy-tbody');
    if (!tbody) return;

    if (discrepancies.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state" style="padding: 30px; text-align: center; color: var(--text-tertiary);">
            No discrepancies found for this filter. Both models agree completely on these cases!
        </td></tr>`;
        return;
    }

    tbody.innerHTML = discrepancies.map((d, idx) => {
        const aBlocked = d.run_a.predicted_blocked;
        const bBlocked = d.run_b.predicted_blocked;
        const aClass = d.run_a.correct ? 'case-correct' : 'case-incorrect';
        const bClass = d.run_b.correct ? 'case-correct' : 'case-incorrect';

        const latDiff = d.latency_diff_ms;
        const latDiffStr = (latDiff > 0 ? `+${latDiff}` : `${latDiff}`) + 'ms';
        const latClass = latDiff > 0 ? 'text-amber-400' : 'text-emerald-400';

        return `
            <tr class="case-row" onclick="showDiscrepancyDetail(${idx})" title="Click to view detailed comparison and payload">
                <td class="mono font-semibold">${d.case_id}</td>
                <td><span class="badge-domain">${d.domain}</span></td>
                <td><span class="mono text-xs" style="color: #818cf8;">${d.analysis_tier}</span></td>
                <td>${d.is_malicious ? '🔴 Malicious' : '🟢 Benign'}</td>
                <td>
                    <span class="${aClass}" style="font-weight: 600;">${aBlocked ? '🛑 Blocked' : '✅ Allowed'}</span>
                    <span class="mono text-xs" style="opacity: 0.7;">(${d.run_a.decided_by})</span>
                </td>
                <td>
                    <span class="${bClass}" style="font-weight: 600;">${bBlocked ? '🛑 Blocked' : '✅ Allowed'}</span>
                    <span class="mono text-xs" style="opacity: 0.7;">(${d.run_b.decided_by})</span>
                </td>
                <td class="mono text-sm ${latClass}">${latDiffStr}</td>
                <td class="case-expand-icon">▸</td>
            </tr>
        `;
    }).join('');
}

async function filterDiscrepancies(filterType) {
    if (!state.compareData) return;
    state.compareFilter = filterType;

    $$('.case-filters button[data-compare-filter]').forEach(b => {
        b.classList.toggle('active', b.dataset.compareFilter === filterType);
    });

    const runA = state.compareData.run_a.run_id;
    const runB = state.compareData.run_b.run_id;

    try {
        const res = await fetch(`/api/runs/${runA}/compare/${runB}?filter=${filterType}&limit=250`);
        const data = await res.json();
        renderDiscrepancyRows(data.discrepancies || []);
    } catch (e) {
        showToast(`Filter error: ${e.message}`, 'error');
    }
}

function showDiscrepancyDetail(idx) {
    const d = state.currentDiscrepancies[idx];
    if (!d || !state.compareData) return;

    const detail = $('#case-detail-drawer');
    if (!detail) return;

    const rA = state.compareData.run_a;
    const rB = state.compareData.run_b;

    detail.innerHTML = `
        <div class="case-detail-header">
            <div class="case-detail-title">
                <span style="font-size: 1.2rem;">⚖️</span>
                <span>${d.case_id}</span>
            </div>
            <button class="modal-close" onclick="closeCaseDetail()">✕</button>
        </div>

        <div class="case-detail-meta">
            <div class="case-meta-chip">
                <span class="case-meta-label">Source</span>
                <span class="case-meta-value">${d.source || '—'}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Domain</span>
                <span class="case-meta-value">${d.domain}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Tier</span>
                <span class="case-meta-value mono" style="color: #6366f1; font-weight: 600;">${d.analysis_tier}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">CWE</span>
                <span class="case-meta-value">${d.cwe || '—'}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Tool</span>
                <span class="case-meta-value mono">${d.tool_name}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Expected</span>
                <span class="case-meta-value font-semibold">${d.is_malicious ? '🔴 Malicious (Block)' : '🟢 Benign (Allow)'}</span>
            </div>
        </div>

        <!-- Side-by-Side Model Comparison -->
        <div style="margin-top: var(--space-4); margin-bottom: var(--space-4);">
            <div class="case-section-title" style="margin-bottom: var(--space-2);">⚔️ Model Comparison</div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-3);">
                <!-- Model A Card -->
                <div style="padding: 12px; border-radius: var(--radius-md); background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25);">
                    <div class="font-bold text-xs" style="color: #f59e0b; margin-bottom: 6px; text-transform: uppercase;">Run A: ${rA.model_name}</div>
                    <div style="font-size: 1.1rem; font-weight: bold; margin-bottom: 4px;">
                        ${d.run_a.predicted_blocked ? '🛑 BLOCKED' : '✅ ALLOWED'}
                        <span>${d.run_a.correct ? '✓' : '✕'}</span>
                    </div>
                    <div class="text-xs mono text-muted">Engine: ${d.run_a.decided_by}</div>
                    <div class="text-xs mono text-muted">Latency: ${d.run_a.latency_ms}ms</div>
                    ${d.run_a.verdict_detail ? `<div class="text-xs mono" style="margin-top: 4px; color: var(--text-secondary);">${escapeHtml(d.run_a.verdict_detail)}</div>` : ''}
                </div>

                <!-- Model B Card -->
                <div style="padding: 12px; border-radius: var(--radius-md); background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.25);">
                    <div class="font-bold text-xs" style="color: #3b82f6; margin-bottom: 6px; text-transform: uppercase;">Run B: ${rB.model_name}</div>
                    <div style="font-size: 1.1rem; font-weight: bold; margin-bottom: 4px;">
                        ${d.run_b.predicted_blocked ? '🛑 BLOCKED' : '✅ ALLOWED'}
                        <span>${d.run_b.correct ? '✓' : '✕'}</span>
                    </div>
                    <div class="text-xs mono text-muted">Engine: ${d.run_b.decided_by}</div>
                    <div class="text-xs mono text-muted">Latency: ${d.run_b.latency_ms}ms</div>
                    ${d.run_b.verdict_detail ? `<div class="text-xs mono" style="margin-top: 4px; color: var(--text-secondary);">${escapeHtml(d.run_b.verdict_detail)}</div>` : ''}
                </div>
            </div>
        </div>

        ${d.context ? `
        <div class="case-detail-section">
            <div class="case-section-title">📋 Context</div>
            <div class="case-context-box">${escapeHtml(d.context)}</div>
        </div>` : ''}

        <div class="case-detail-section">
            <div class="flex items-center justify-between" style="margin-bottom: var(--space-2);">
                <div class="case-section-title" style="margin-bottom: 0;">📦 Tool Arguments (Payload)</div>
                <button class="copy-payload-btn" onclick="copyPayload(this)" title="Copy payload to clipboard">📋 Copy</button>
            </div>
            <pre class="case-payload-box"><code>${syntaxHighlight(d.tool_arguments || '{}')}</code></pre>
        </div>
    `;

    detail.classList.add('open');
}

// ─── Navigation ─────────────────────────────────────────────────────────────

function activatePageUI(page) {
    state.currentPage = page;
    $$('.page').forEach(el => el.classList.remove('active'));
    $$('.nav-btn').forEach(el => el.classList.remove('active'));

    const pageEl = $(`#page-${page}`);
    if (pageEl) pageEl.classList.add('active');

    const navBtn = $(`.nav-btn[data-page="${page}"]`);
    if (navBtn) navBtn.classList.add('active');
}

function switchPage(page, updateHash = true) {
    activatePageUI(page);

    if (page === 'history') {
        loadHistoryPage();
    } else if (page === 'models') {
        loadModelsPage();
    } else if (page === 'reports') {
        loadReportsPage();
    } else if (page === 'compare') {
        loadRuns().then(() => populateCompareSelects());
    } else if (page === 'test-cases') {
        initTestCasesPage();
    }

    if (updateHash) {
        updateUrlHash(state.currentPage === 'test-cases' && !!state.testCases.activeCaseId);
    }
}

// ─── Test Cases Explorer (ISSUE-006 & ISSUE-007) ───────────────────────────

async function initTestCasesPage() {
    if (!state.testCases.filtersLoaded) {
        await loadTestCaseFilters();
    }
    if (!state.testCases.eventsBound) {
        bindTestCaseEvents();
    }
    syncTestCaseFilterControls();
    await loadTestCases();
}

async function loadTestCaseFilters() {
    try {
        const res = await fetch('/api/test-cases/filters');
        if (!res.ok) throw new Error('Failed to load test case filters');
        const data = await res.json();

        // Total cases
        const totalEl = $('#tc-total-count');
        if (totalEl) totalEl.textContent = data.total_pool_cases.toLocaleString();

        // Populate datasets
        const dsSelect = $('#tc-filter-dataset');
        if (dsSelect) {
            dsSelect.innerHTML = `<option value="all">All Datasets (${data.total_pool_cases.toLocaleString()})</option>`;
            data.datasets.forEach(d => {
                const opt = document.createElement('option');
                opt.value = d.name;
                opt.textContent = `${d.name} (${d.count.toLocaleString()})`;
                dsSelect.appendChild(opt);
            });
            if (state.testCases.dataset) dsSelect.value = state.testCases.dataset;
        }

        // Populate domains
        const domSelect = $('#tc-filter-domain');
        if (domSelect) {
            domSelect.innerHTML = '<option value="all">All Threat Domains</option>';
            data.threat_domains.forEach(d => {
                const opt = document.createElement('option');
                opt.value = d.name;
                opt.textContent = `${d.name} (${d.count.toLocaleString()})`;
                domSelect.appendChild(opt);
            });
            if (state.testCases.threat_domain) domSelect.value = state.testCases.threat_domain;
        }

        state.testCases.filtersLoaded = true;
    } catch (err) {
        console.error('[TestCases] Error loading filters:', err);
        showToast('Failed to load test case filters: ' + err.message, 'error');
    }
}

async function loadTestCases(updateHash = true) {
    const tbody = $('#tc-cases-tbody');
    if (tbody) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" style="text-align: center; padding: var(--space-8); color: var(--text-tertiary);">
                    <div style="display: flex; align-items: center; justify-content: center; gap: var(--space-2);">
                        <span class="inline-spinner" style="display: inline-block; width: 14px; height: 14px; border: 2px solid rgba(255,255,255,0.2); border-top-color: var(--accent-indigo); border-radius: 50%; animation: spin 0.6s linear infinite;"></span>
                        <span>Loading test scenarios from DuckDB...</span>
                    </div>
                </td>
            </tr>
        `;
    }

    const tc = state.testCases;
    const params = new URLSearchParams({
        page: tc.page,
        limit: tc.limit,
        sort_by: tc.sortBy || 'id',
        sort_order: tc.sortOrder || 'asc',
    });
    if (tc.search && tc.search.trim()) params.set('search', tc.search.trim());
    if (tc.dataset !== 'all') params.set('dataset', tc.dataset);
    if (tc.threat_domain !== 'all') params.set('threat_domain', tc.threat_domain);
    if (tc.tier !== 'all') params.set('tier', tc.tier);
    if (tc.status !== 'all') params.set('status', tc.status);

    try {
        const res = await fetch(`/api/test-cases?${params.toString()}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        tc.cases = data.cases || [];
        tc.total = data.pagination.total_records || 0;
        tc.totalPages = data.pagination.total_pages || 1;
        tc.page = data.pagination.page || 1;

        renderTestCasesTable();
        renderTestCasesPagination();
        updateTestCaseSortHeaders();

        const searchClear = $('#tc-search-clear');
        if (searchClear) {
            searchClear.style.display = tc.search ? 'block' : 'none';
        }

        if (updateHash) {
            updateUrlHash(state.currentPage === 'test-cases' && !!state.testCases.activeCaseId);
        }
    } catch (err) {
        console.error('[TestCases] Error loading cases:', err);
        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" style="text-align: center; padding: var(--space-8); color: var(--color-danger);">
                        ❌ Failed to load test cases: ${escapeHtml(err.message)}
                    </td>
                </tr>
            `;
        }
        showToast('Failed to load test cases: ' + err.message, 'error');
    }
}

function renderTestCasesTable() {
    const tbody = $('#tc-cases-tbody');
    if (!tbody) return;

    const filteredEl = $('#tc-filtered-count');
    if (filteredEl) filteredEl.textContent = state.testCases.total.toLocaleString();

    if (state.testCases.cases.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" style="text-align: center; padding: var(--space-8);">
                    <div style="display: flex; flex-direction: column; align-items: center; gap: var(--space-3);">
                        <span style="font-size: 2.2rem; opacity: 0.6;">🛡️</span>
                        <div class="font-bold" style="color: var(--text-primary); font-size: 1rem;">No test cases found</div>
                        <div class="text-sm text-muted">No test scenarios match the current filter selection.</div>
                        <button class="btn btn-secondary btn-sm" onclick="resetTestCaseFilters()" style="margin-top: var(--space-2);">
                            ✕ Clear Filters
                        </button>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = state.testCases.cases.map(c => {
        const statusBadge = c.is_malicious
            ? '<span class="tc-status-badge tc-status-threat">🚨 Threat</span>'
            : '<span class="tc-status-badge tc-status-safe">🛡️ Safe</span>';

        let tierClass = 'tc-tier-static';
        let tierLabel = '⚡ Static';
        if (c.analysis_tier === 'SEMANTIC_REQUIRED') {
            tierClass = 'tc-tier-semantic';
            tierLabel = '🧠 Semantic';
        } else if (c.analysis_tier === 'HYBRID') {
            tierClass = 'tc-tier-hybrid';
            tierLabel = '🔀 Hybrid';
        }

        const safeId = escapeHtml(c.id);
        const safeDataset = escapeHtml(c.source_dataset || '—');
        const safeDomain = escapeHtml(c.threat_domain || '—');
        const safeTool = escapeHtml(c.tool_name || '—');

        return `
            <tr class="case-row" onclick="showTestCaseDetail('${safeId}')">
                <td>
                    <span class="mono font-bold" style="color: var(--accent-cyan); font-size: 0.82rem;">${safeId}</span>
                </td>
                <td>
                    <span class="badge" style="background: rgba(255,255,255,0.06); font-size: 0.72rem; color: var(--text-secondary);">${safeDataset}</span>
                </td>
                <td>
                    <span class="badge badge-domain">${safeDomain}</span>
                </td>
                <td>
                    <span class="tc-tier-badge ${tierClass}">${tierLabel}</span>
                </td>
                <td>${statusBadge}</td>
                <td>
                    <span class="mono text-xs" style="color: var(--text-primary);">${safeTool}</span>
                </td>
                <td style="text-align: right;">
                    <button class="btn btn-sm btn-secondary copy-payload-btn" style="padding: 2px 8px;" onclick="event.stopPropagation(); showTestCaseDetail('${safeId}')">
                        👁️ View
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function renderTestCasesPagination() {
    const tc = state.testCases;
    const start = tc.total === 0 ? 0 : (tc.page - 1) * tc.limit + 1;
    const end = Math.min(tc.total, tc.page * tc.limit);

    setText('#tc-pagination-info', `Showing ${start.toLocaleString()} - ${end.toLocaleString()} of ${tc.total.toLocaleString()} cases`);
    setText('#tc-current-page', tc.page);
    setText('#tc-total-pages', tc.totalPages);

    const btnFirst = $('#tc-page-first');
    const btnPrev = $('#tc-page-prev');
    const btnNext = $('#tc-page-next');
    const btnLast = $('#tc-page-last');

    if (btnFirst) btnFirst.disabled = tc.page <= 1;
    if (btnPrev) btnPrev.disabled = tc.page <= 1;
    if (btnNext) btnNext.disabled = tc.page >= tc.totalPages;
    if (btnLast) btnLast.disabled = tc.page >= tc.totalPages;
}

function updateTestCaseSortHeaders() {
    const tc = state.testCases;
    const headers = $$('th.tc-sortable');
    headers.forEach(th => {
        const col = th.getAttribute('data-sort');
        const icon = th.querySelector('.tc-sort-icon');
        th.classList.remove('sorted-asc', 'sorted-desc');
        if (col === tc.sortBy) {
            if (tc.sortOrder === 'desc') {
                th.classList.add('sorted-desc');
                if (icon) icon.textContent = '▼';
            } else {
                th.classList.add('sorted-asc');
                if (icon) icon.textContent = '▲';
            }
        } else {
            if (icon) icon.textContent = '⇅';
        }
    });
}

function bindTestCaseEvents() {
    const tc = state.testCases;

    const searchInput = $('#tc-search-input');
    const searchClear = $('#tc-search-clear');

    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const val = e.target.value;
            tc.search = val;
            if (searchClear) searchClear.style.display = val ? 'block' : 'none';

            if (tc.searchDebounceTimer) clearTimeout(tc.searchDebounceTimer);
            tc.searchDebounceTimer = setTimeout(() => {
                tc.page = 1;
                loadTestCases(true);
            }, 300);
        });

        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                e.stopPropagation();
                if (searchInput.value) {
                    searchInput.value = '';
                    tc.search = '';
                    if (searchClear) searchClear.style.display = 'none';
                    tc.page = 1;
                    loadTestCases(true);
                }
            } else if (e.key === 'Enter') {
                e.preventDefault();
                if (tc.searchDebounceTimer) clearTimeout(tc.searchDebounceTimer);
                tc.page = 1;
                loadTestCases(true);
            }
        });
    }

    if (searchClear) {
        searchClear.addEventListener('click', () => {
            if (searchInput) searchInput.value = '';
            tc.search = '';
            searchClear.style.display = 'none';
            tc.page = 1;
            loadTestCases(true);
            if (searchInput) searchInput.focus();
        });
    }

    const sortHeaders = $$('th.tc-sortable');
    sortHeaders.forEach(th => {
        th.addEventListener('click', () => {
            const col = th.getAttribute('data-sort');
            if (!col) return;

            if (tc.sortBy === col) {
                tc.sortOrder = tc.sortOrder === 'asc' ? 'desc' : 'asc';
            } else {
                tc.sortBy = col;
                tc.sortOrder = 'asc';
            }
            tc.page = 1;
            loadTestCases(true);
        });
    });

    const dsSelect = $('#tc-filter-dataset');
    if (dsSelect) {
        dsSelect.addEventListener('change', () => {
            tc.dataset = dsSelect.value;
            tc.page = 1;
            loadTestCases(true);
        });
    }

    const domSelect = $('#tc-filter-domain');
    if (domSelect) {
        domSelect.addEventListener('change', () => {
            tc.threat_domain = domSelect.value;
            tc.page = 1;
            loadTestCases(true);
        });
    }

    const tierSelect = $('#tc-filter-tier');
    if (tierSelect) {
        tierSelect.addEventListener('change', () => {
            tc.tier = tierSelect.value;
            tc.page = 1;
            loadTestCases(true);
        });
    }

    const statusSelect = $('#tc-filter-status');
    if (statusSelect) {
        statusSelect.addEventListener('change', () => {
            tc.status = statusSelect.value;
            tc.page = 1;
            loadTestCases(true);
        });
    }

    const limitSelect = $('#tc-filter-limit');
    if (limitSelect) {
        limitSelect.addEventListener('change', () => {
            tc.limit = parseInt(limitSelect.value, 10) || 50;
            tc.page = 1;
            loadTestCases(true);
        });
    }

    const resetBtn = $('#tc-btn-reset');
    if (resetBtn) {
        resetBtn.addEventListener('click', resetTestCaseFilters);
    }

    const btnFirst = $('#tc-page-first');
    if (btnFirst) {
        btnFirst.addEventListener('click', () => {
            if (tc.page > 1) {
                tc.page = 1;
                loadTestCases(true);
            }
        });
    }

    const btnPrev = $('#tc-page-prev');
    if (btnPrev) {
        btnPrev.addEventListener('click', () => {
            if (tc.page > 1) {
                tc.page--;
                loadTestCases(true);
            }
        });
    }

    const btnNext = $('#tc-page-next');
    if (btnNext) {
        btnNext.addEventListener('click', () => {
            if (tc.page < tc.totalPages) {
                tc.page++;
                loadTestCases(true);
            }
        });
    }

    const btnLast = $('#tc-page-last');
    if (btnLast) {
        btnLast.addEventListener('click', () => {
            if (tc.page < tc.totalPages) {
                tc.page = tc.totalPages;
                loadTestCases(true);
            }
        });
    }

    state.testCases.eventsBound = true;
}

function resetTestCaseFilters() {
    const tc = state.testCases;
    tc.dataset = 'all';
    tc.threat_domain = 'all';
    tc.tier = 'all';
    tc.status = 'all';
    tc.search = '';
    tc.sortBy = 'id';
    tc.sortOrder = 'asc';
    tc.page = 1;

    const searchInput = $('#tc-search-input');
    if (searchInput) searchInput.value = '';

    const searchClear = $('#tc-search-clear');
    if (searchClear) searchClear.style.display = 'none';

    const dsSelect = $('#tc-filter-dataset');
    if (dsSelect) dsSelect.value = 'all';

    const domSelect = $('#tc-filter-domain');
    if (domSelect) domSelect.value = 'all';

    const tierSelect = $('#tc-filter-tier');
    if (tierSelect) tierSelect.value = 'all';

    const statusSelect = $('#tc-filter-status');
    if (statusSelect) statusSelect.value = 'all';

    loadTestCases(true);
}

async function showTestCaseDetail(caseId, updateHash = true) {
    if (!caseId) return;

    const detail = $('#case-detail-drawer');
    const overlay = $('#drawer-overlay');
    if (!detail) return;

    state.testCases.activeCaseId = caseId;
    if (updateHash) {
        updateUrlHash(true);
    }

    if (overlay) overlay.classList.add('active');
    detail.classList.add('open');

    let c = (state.testCases.cases || []).find(item => item.id === caseId);

    if (!c) {
        // Skeleton loader while fetching single case
        detail.innerHTML = `
            <div class="case-detail-header">
                <div class="case-detail-title">
                    <span class="mono" style="color: var(--accent-cyan); font-weight: 700;">${escapeHtml(caseId)}</span>
                </div>
                <button class="modal-close" onclick="closeCaseDetail()" title="Close (Esc)">✕</button>
            </div>
            <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding: var(--space-12); gap: var(--space-3); color: var(--text-tertiary);">
                <span class="inline-spinner" style="display: inline-block; width: 24px; height: 24px; border: 3px solid rgba(255,255,255,0.2); border-top-color: var(--accent-cyan); border-radius: 50%; animation: spin 0.6s linear infinite;"></span>
                <div style="font-size: 0.85rem;">Loading test scenario details...</div>
            </div>
        `;

        try {
            const res = await fetch(`/api/test-cases/${encodeURIComponent(caseId)}`);
            if (!res.ok) {
                throw new Error(res.status === 404 ? `Test case "${caseId}" not found in benchmark pool.` : `Server error (${res.status})`);
            }
            c = await res.json();
        } catch (err) {
            detail.innerHTML = `
                <div class="case-detail-header">
                    <div class="case-detail-title">
                        <span class="mono" style="color: var(--color-danger); font-weight: 700;">Not Found</span>
                    </div>
                    <button class="modal-close" onclick="closeCaseDetail()" title="Close (Esc)">✕</button>
                </div>
                <div style="padding: var(--space-8); text-align: center;">
                    <div style="font-size: 2.2rem; margin-bottom: var(--space-2);">⚠️</div>
                    <div style="color: var(--color-danger); font-weight: 600; margin-bottom: var(--space-2);">${escapeHtml(err.message)}</div>
                    <div class="text-sm text-muted" style="margin-bottom: var(--space-4);">The requested test case ID does not exist in master_benchmark.parquet.</div>
                    <button class="btn btn-secondary btn-sm" onclick="closeCaseDetail()">Close Drawer</button>
                </div>
            `;
            return;
        }
    }

    // Format tool arguments & pretty print JSON
    let prettyArgs = c.tool_arguments || '{}';
    let isJson = false;
    try {
        const parsed = typeof prettyArgs === 'string' ? JSON.parse(prettyArgs) : prettyArgs;
        prettyArgs = JSON.stringify(parsed, null, 2);
        isJson = true;
    } catch (_) {
        isJson = false;
    }
    state.testCases.activeCasePayload = prettyArgs;
    const highlightedPayload = isJson ? syntaxHighlight(prettyArgs) : escapeHtml(prettyArgs);

    const statusBadge = c.is_malicious
        ? '<span class="tc-status-badge tc-status-threat" style="font-size: 0.85rem; padding: 4px 10px;">🚨 Threat (Malicious)</span>'
        : '<span class="tc-status-badge tc-status-safe" style="font-size: 0.85rem; padding: 4px 10px;">🛡️ Safe (Benign)</span>';

    let tierBadgeColor = 'var(--color-success)';
    let tierIcon = '⚡';
    if (c.analysis_tier === 'SEMANTIC_REQUIRED') {
        tierBadgeColor = '#818cf8';
        tierIcon = '🧠';
    } else if (c.analysis_tier === 'HYBRID') {
        tierBadgeColor = '#fbbf24';
        tierIcon = '🔀';
    }

    detail.innerHTML = `
        <div class="case-detail-header">
            <div class="case-detail-title">
                <span class="mono" style="color: var(--accent-cyan); font-weight: 700; font-size: 1.05rem;">${escapeHtml(c.id)}</span>
            </div>
            <button class="modal-close" onclick="closeCaseDetail()" title="Close (Esc)">✕</button>
        </div>

        <div style="margin-bottom: var(--space-4); display: flex; align-items: center; justify-content: space-between;">
            ${statusBadge}
            <span class="mono text-xs text-muted">Direction: ${escapeHtml(c.traffic_direction || 'tools/call')}</span>
        </div>

        <div class="case-detail-meta" style="margin-bottom: var(--space-5);">
            <div class="case-meta-chip">
                <span class="case-meta-label">Dataset</span>
                <span class="case-meta-value">${escapeHtml(c.source_dataset || '—')}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Threat Domain</span>
                <span class="case-meta-value">${escapeHtml(c.threat_domain || '—')}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Analysis Tier</span>
                <span class="case-meta-value mono font-semibold" style="color: ${tierBadgeColor};">${tierIcon} ${escapeHtml(c.analysis_tier || 'STATIC_CAPABLE')}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">CWE ID</span>
                <span class="case-meta-value mono">${escapeHtml(c.cwe || '—')}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">OWASP LLM</span>
                <span class="case-meta-value mono">${escapeHtml(c.owasp_llm || '—')}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Target Tool</span>
                <span class="case-meta-value mono font-semibold" style="color: var(--accent-blue);">${escapeHtml(c.tool_name || '—')}</span>
            </div>
        </div>

        <!-- Prompt Context -->
        <div class="case-detail-section" style="margin-bottom: var(--space-5);">
            <div class="case-section-title">📋 Context / User Prompt</div>
            <div class="case-context-box" style="white-space: pre-wrap; font-size: 0.82rem; line-height: 1.6; max-height: 220px; overflow-y: auto;">${escapeHtml(c.context || 'No prompt context provided.')}</div>
        </div>

        <!-- Tool Arguments -->
        <div class="case-detail-section">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-2);">
                <div class="case-section-title" style="margin-bottom: 0;">📦 Tool Arguments (Payload)</div>
                <button class="copy-payload-btn" id="btn-copy-case-payload" onclick="copyTestCasePayload(this)" title="Copy payload to clipboard">📋 Copy</button>
            </div>
            <pre class="case-payload-box"><code id="tc-detail-payload-code">${highlightedPayload}</code></pre>
        </div>
    `;
}

function copyTestCasePayload(btn) {
    const payload = state.testCases.activeCasePayload || '';
    navigator.clipboard.writeText(payload).then(() => {
        btn.classList.add('copied');
        btn.textContent = '✓ Copied!';
        showToast('Payload copied to clipboard', 'info');
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.textContent = '📋 Copy';
        }, 1500);
    }).catch(err => {
        console.error('Clipboard copy failed:', err);
        showToast('Failed to copy to clipboard', 'error');
    });
}

// ─── URL Hash Deep-Linking (ISSUE-007) ──────────────────────────────────────

function updateUrlHash(includeCaseId = true) {
    if (state.currentPage !== 'test-cases') {
        const hash = `#${state.currentPage}`;
        if (window.location.hash !== hash) {
            history.replaceState(null, '', hash);
        }
        return;
    }

    const params = new URLSearchParams();
    const tc = state.testCases;

    if (tc.page && tc.page > 1) {
        params.set('page', tc.page);
    }
    if (tc.limit && tc.limit !== 50) {
        params.set('limit', tc.limit);
    }
    if (tc.dataset && tc.dataset !== 'all') {
        params.set('dataset', tc.dataset);
    }
    if (tc.threat_domain && tc.threat_domain !== 'all') {
        params.set('domain', tc.threat_domain);
    }
    if (tc.tier && tc.tier !== 'all') {
        params.set('tier', tc.tier);
    }
    if (tc.status && tc.status !== 'all') {
        params.set('status', tc.status);
    }
    if (tc.search && tc.search.trim()) {
        params.set('q', tc.search.trim());
    }
    if (tc.sortBy && tc.sortBy !== 'id') {
        params.set('sort_by', tc.sortBy);
    }
    if (tc.sortOrder && tc.sortOrder !== 'asc') {
        params.set('sort_order', tc.sortOrder);
    }
    if (includeCaseId && tc.activeCaseId) {
        params.set('id', tc.activeCaseId);
    }

    const qs = params.toString();
    const newHash = qs ? `#test-cases?${qs}` : '#test-cases';
    if (window.location.hash !== newHash) {
        history.replaceState(null, '', newHash);
    }
}

function parseHash() {
    const raw = window.location.hash.startsWith('#')
        ? window.location.hash.substring(1)
        : window.location.hash;

    if (!raw) return { page: 'dashboard', params: new URLSearchParams() };

    const qIdx = raw.indexOf('?');
    if (qIdx === -1) {
        return { page: raw, params: new URLSearchParams() };
    }

    const page = raw.substring(0, qIdx);
    const qs = raw.substring(qIdx + 1);
    return { page, params: new URLSearchParams(qs) };
}

let isNavigatingHash = false;
async function handleHashNavigation() {
    if (isNavigatingHash) return;
    isNavigatingHash = true;

    try {
        const { page, params } = parseHash();
        let targetPage = page;
        if (targetPage === 'benchmark') targetPage = 'dashboard';
        const validPages = ['dashboard', 'matrix', 'compare', 'test-cases', 'history'];
        if (!validPages.includes(targetPage)) {
            targetPage = 'dashboard';
        }

        if (targetPage === 'test-cases') {
            const pageNum = parseInt(params.get('page'), 10);
            state.testCases.page = (pageNum && pageNum > 0) ? pageNum : 1;

            const limitNum = parseInt(params.get('limit'), 10);
            state.testCases.limit = (limitNum && limitNum > 0) ? limitNum : 50;

            state.testCases.dataset = params.get('dataset') || 'all';
            state.testCases.threat_domain = params.get('domain') || params.get('threat_domain') || 'all';
            state.testCases.tier = params.get('tier') || 'all';
            state.testCases.status = params.get('status') || 'all';
            state.testCases.search = params.get('q') || params.get('search') || '';
            state.testCases.sortBy = params.get('sort_by') || 'id';
            state.testCases.sortOrder = (params.get('sort_order') || 'asc').toLowerCase() === 'desc' ? 'desc' : 'asc';

            const caseId = params.get('id');

            activatePageUI('test-cases');

            if (!state.testCases.filtersLoaded) {
                await loadTestCaseFilters();
            }
            if (!state.testCases.eventsBound) {
                bindTestCaseEvents();
            }
            syncTestCaseFilterControls();

            await loadTestCases(false);

            if (caseId) {
                await showTestCaseDetail(caseId, false);
            } else {
                closeCaseDetail(false);
            }
        } else {
            const normalizedPage = targetPage === 'matrix' ? 'reports' : targetPage;
            activatePageUI(normalizedPage);
            if (normalizedPage === 'history') {
                loadHistoryPage();
            } else if (normalizedPage === 'models') {
                loadModelsPage();
            } else if (normalizedPage === 'reports') {
                loadReportsPage();
            } else if (normalizedPage === 'compare') {
                loadRuns().then(() => populateCompareSelects());
            }
            closeCaseDetail(false);
        }
    } catch (err) {
        console.error('[HashNav] Error during hash navigation:', err);
    } finally {
        isNavigatingHash = false;
    }
}

function syncTestCaseFilterControls() {
    const searchInput = $('#tc-search-input');
    if (searchInput) searchInput.value = state.testCases.search || '';

    const searchClear = $('#tc-search-clear');
    if (searchClear) searchClear.style.display = state.testCases.search ? 'block' : 'none';

    const dsEl = $('#tc-filter-dataset');
    if (dsEl && state.testCases.dataset) dsEl.value = state.testCases.dataset;

    const domEl = $('#tc-filter-domain');
    if (domEl && state.testCases.threat_domain) domEl.value = state.testCases.threat_domain;

    const tierEl = $('#tc-filter-tier');
    if (tierEl && state.testCases.tier) tierEl.value = state.testCases.tier;

    const statusEl = $('#tc-filter-status');
    if (statusEl && state.testCases.status) statusEl.value = state.testCases.status;

    const limitEl = $('#tc-filter-limit');
    if (limitEl && state.testCases.limit) limitEl.value = String(state.testCases.limit);
}

// ─── Toast Notifications ────────────────────────────────────────────────────

function showToast(message, type = 'info') {
    const container = $('#toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(30px)';
        toast.style.transition = '300ms ease';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ─── Utilities ──────────────────────────────────────────────────────────────

function setText(selector, text) {
    const el = $(selector);
    if (el) el.textContent = text;
}

// ─── Initialize ─────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Load data
    loadDatasets();
    loadModels();
    loadRuns();

    // Connect WebSocket
    connectWS();

    // Navigation
    $$('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => switchPage(btn.dataset.page));
    });

    // Start benchmark button
    const startBtn = $('#btn-start');
    if (startBtn) {
        startBtn.addEventListener('click', startBenchmark);
    }

    // Modal close
    const modalOverlay = $('#run-detail-modal');
    if (modalOverlay) {
        modalOverlay.addEventListener('click', (e) => {
            if (e.target === modalOverlay) closeModal();
        });
    }

    // Dataset select hint and tier counts update
    const datasetSelect = $('#dataset-select');
    if (datasetSelect) {
        datasetSelect.addEventListener('change', () => {
            const ds = state.datasets.find(d => d.id === datasetSelect.value);
            const hint = $('#dataset-hint');
            if (hint && ds) {
                hint.textContent = `${ds.rows.toLocaleString()} rows · ${ds.size_kb} KB · ${ds.filename}`;
            } else if (hint) {
                hint.textContent = '';
            }
            updateTierCounts(ds);
        });
    }

    // Model select change handler
    const modelSelect = $('#model-select');
    if (modelSelect) {
        modelSelect.addEventListener('change', onModelChanged);
    }

    // Tier scope radio change listeners
    document.querySelectorAll('input[name="tier_scope"]').forEach(r => {
        r.addEventListener('change', onTierRadioChanged);
    });

    // L1 Fail-fast radio change listeners
    document.querySelectorAll('input[name="enable_l1"]').forEach(r => {
        r.addEventListener('change', onL1RadioChanged);
    });

    // Deep-linking hash routing (ISSUE-007)
    window.addEventListener('hashchange', () => handleHashNavigation());
    if (window.location.hash) {
        handleHashNavigation();
    }

    // Global keyboard shortcuts (Escape key closes drawer & modal)
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' || e.key === 'Esc') {
            const drawer = $('#case-detail-drawer');
            if (drawer && drawer.classList.contains('open')) {
                closeCaseDetail();
            }
            const modal = $('#run-detail-modal');
            if (modal && modal.classList.contains('open')) {
                closeModal();
            }
        }
    });

    // WebSocket keepalive
    setInterval(() => {
        if (state.ws && state.ws.readyState === WebSocket.OPEN) {
            state.ws.send(JSON.stringify({ type: 'ping' }));
        }
    }, 30000);
});

// ─── Runtime Tier Badges ────────────────────────────────────────────────────

function getRuntimeTierBadge(tier) {
    const t = (tier || 'UNKNOWN').toUpperCase();
    if (t.includes('CLOUD')) {
        return '<span class="badge" style="background: rgba(6, 182, 212, 0.16); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.35);">[Cloud API]</span>';
    }
    if (t.includes('MLX') || t.includes('METAL')) {
        return '<span class="badge" style="background: rgba(147, 51, 234, 0.15); color: #c084fc; border: 1px solid rgba(147, 51, 234, 0.3);">[MLX-Native]</span>';
    }
    if (t.includes('OLLAMA')) {
        return '<span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3);">[Ollama]</span>';
    }
    if (t.includes('MPS')) {
        return '<span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3);">[PyTorch MPS]</span>';
    }
    if (t.includes('STATIC') || t.includes('RULE')) {
        return '<span class="badge" style="background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3);">[L1 Static]</span>';
    }
    return `<span class="badge badge-pending">[${escapeHtml(tier || 'Unknown')}]</span>`;
}

// ─── Models & Adapters Dashboard (ADR 0012) ─────────────────────────────────

async function loadModelsPage() {
    try {
        const [provRes, cModelRes, allModelsRes] = await Promise.all([
            fetch('/api/cloud-providers'),
            fetch('/api/cloud-models'),
            fetch('/api/models'),
        ]);
        state.modelsAdmin.providers = provRes.ok ? await provRes.json() : [];
        state.modelsAdmin.cloudModels = cModelRes.ok ? await cModelRes.json() : [];
        const allModels = allModelsRes.ok ? await allModelsRes.json() : [];
        const localModels = allModels.filter(m => m.backend !== 'Cloud API');

        renderCloudModelsTable();
        renderCloudProvidersTable();
        renderLocalModelsTable(localModels);
    } catch (e) {
        console.error('Failed to load Models page:', e);
        showToast('Failed to load models registry', 'error');
    }
}

function renderCloudModelsTable() {
    const tbody = $('#cloud-models-tbody');
    const countEl = $('#cloud-models-count');
    const list = state.modelsAdmin.cloudModels || [];
    if (countEl) countEl.textContent = `${list.length} Model${list.length === 1 ? '' : 's'}`;
    if (!tbody) return;

    if (list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No cloud models registered yet. Click "Add Cloud Model" to register one.</td></tr>';
        return;
    }

    tbody.innerHTML = list.map(m => {
        const envBadge = m.api_key_configured
            ? `<span class="badge badge-env-ok">✓ ${escapeHtml(m.api_key_env)}</span>`
            : `<span class="badge badge-env-missing">✕ ${escapeHtml(m.api_key_env || 'Missing')}</span>`;
        const statusBadge = m.enabled
            ? '<span class="badge badge-completed">Enabled</span>'
            : '<span class="badge badge-pending">Disabled</span>';
        const priceTxt = m.input_price_per_1m_usd != null ? `$${Number(m.input_price_per_1m_usd).toFixed(4)}` : '—';
        const thTxt = `${m.exploit_threshold} / ${m.misalignment_threshold} / ${m.threat_threshold}`;

        return `
            <tr>
                <td class="mono font-semibold">${escapeHtml(m.model_id)}</td>
                <td>
                    <div>${escapeHtml(m.provider_display_name || m.provider_id)}</div>
                    <div class="text-xs text-muted mono">${escapeHtml(m.dialect)}</div>
                </td>
                <td class="mono text-sm">${escapeHtml(m.remote_model_slug)}</td>
                <td class="mono text-xs">${thTxt}</td>
                <td class="mono text-sm">${priceTxt}</td>
                <td>${envBadge}</td>
                <td>${statusBadge}</td>
                <td style="text-align: right; white-space: nowrap;">
                    <button class="btn btn-secondary btn-sm" onclick="toggleCloudModelEnabled('${escapeHtml(m.model_id)}')">${m.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-secondary btn-sm" onclick="openCloudModelModal('${escapeHtml(m.model_id)}')">Edit</button>
                    <button class="btn btn-danger btn-sm" onclick="deleteCloudModelUI('${escapeHtml(m.model_id)}')" title="Delete">🗑️</button>
                </td>
            </tr>`;
    }).join('');
}

function renderCloudProvidersTable() {
    const tbody = $('#cloud-providers-tbody');
    const countEl = $('#cloud-providers-count');
    const list = state.modelsAdmin.providers || [];
    if (countEl) countEl.textContent = `${list.length} Provider${list.length === 1 ? '' : 's'}`;
    if (!tbody) return;

    if (list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No cloud providers registered yet.</td></tr>';
        return;
    }

    tbody.innerHTML = list.map(p => {
        const envBadge = p.api_key_configured
            ? `<span class="badge badge-env-ok">✓ ${escapeHtml(p.api_key_env)}</span>`
            : `<span class="badge badge-env-missing">✕ ${escapeHtml(p.api_key_env)}</span>`;
        return `
            <tr>
                <td class="mono font-semibold">${escapeHtml(p.provider_id)}</td>
                <td>${escapeHtml(p.display_name)}</td>
                <td class="mono text-xs">${escapeHtml(p.dialect)}</td>
                <td class="mono text-xs">${escapeHtml(p.base_url + p.endpoint_path)}</td>
                <td>${envBadge}</td>
                <td class="mono">${p.model_count}</td>
                <td class="mono">${p.max_concurrency}</td>
                <td style="text-align: right; white-space: nowrap;">
                    <button class="btn btn-secondary btn-sm" onclick="openProviderModal('${escapeHtml(p.provider_id)}')">Edit</button>
                    <button class="btn btn-danger btn-sm" onclick="deleteCloudProviderUI('${escapeHtml(p.provider_id)}')" title="Delete">🗑️</button>
                </td>
            </tr>`;
    }).join('');
}

function renderLocalModelsTable(localModels) {
    const tbody = $('#local-models-tbody');
    const countEl = $('#local-models-count');
    if (countEl) countEl.textContent = `${localModels.length} Adapters`;
    if (!tbody) return;

    tbody.innerHTML = localModels.map(m => `
        <tr>
            <td class="mono font-semibold">${escapeHtml(m.id)}</td>
            <td>${escapeHtml(m.icon || '🛡️')} ${escapeHtml(m.name)}</td>
            <td><span class="badge badge-pending">${escapeHtml(m.backend)}</span></td>
            <td class="mono text-sm">${escapeHtml(m.quantization || '—')}</td>
            <td>${m.status === 'available'
                ? '<span class="badge badge-completed">Available</span>'
                : '<span class="badge badge-error">Unavailable</span>'}</td>
            <td class="text-sm text-muted">${escapeHtml(m.description || '')}</td>
        </tr>`).join('');
}

function openProviderModal(providerId = null) {
    const modal = $('#cloud-provider-modal');
    if (!modal) return;
    const existing = providerId
        ? state.modelsAdmin.providers.find(p => p.provider_id === providerId)
        : null;

    $('#prov-edit-mode').value = existing ? 'edit' : 'create';
    $('#prov-modal-title').textContent = existing ? `✏️ Edit Cloud Provider: ${existing.provider_id}` : '➕ Add Cloud Provider';
    const idInput = $('#prov-id');
    idInput.value = existing ? existing.provider_id : '';
    idInput.disabled = Boolean(existing);
    $('#prov-display-name').value = existing ? existing.display_name : '';
    $('#prov-dialect').value = existing ? existing.dialect : 'OPENROUTER_DECISIONS';
    $('#prov-api-key-env').value = existing ? existing.api_key_env : 'OPENROUTER_API_KEY';
    $('#prov-base-url').value = existing ? existing.base_url : 'https://openrouter.ai';
    $('#prov-endpoint-path').value = existing ? existing.endpoint_path : '/api/alpha/decisions';
    $('#prov-timeout').value = existing ? existing.timeout_seconds : 20;
    $('#prov-concurrency').value = existing ? existing.max_concurrency : 8;
    $('#prov-rpm').value = existing && existing.rpm_limit != null ? existing.rpm_limit : '';
    modal.classList.add('open');
}

function closeProviderModal() {
    const modal = $('#cloud-provider-modal');
    if (modal) modal.classList.remove('open');
}

async function submitProviderForm() {
    const mode = $('#prov-edit-mode').value;
    const providerId = $('#prov-id').value.trim().toLowerCase();
    const payload = {
        provider_id: providerId,
        display_name: $('#prov-display-name').value.trim(),
        dialect: $('#prov-dialect').value,
        base_url: $('#prov-base-url').value.trim(),
        endpoint_path: $('#prov-endpoint-path').value.trim(),
        api_key_env: $('#prov-api-key-env').value.trim(),
        timeout_seconds: parseFloat($('#prov-timeout').value) || 20.0,
        max_concurrency: parseInt($('#prov-concurrency').value, 10) || 8,
        rpm_limit: $('#prov-rpm').value ? parseInt($('#prov-rpm').value, 10) : null,
    };

    try {
        const url = mode === 'edit' ? `/api/cloud-providers/${encodeURIComponent(providerId)}` : '/api/cloud-providers';
        const res = await fetch(url, {
            method: mode === 'edit' ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Failed to save provider');
        }
        closeProviderModal();
        showToast(`Provider "${providerId}" saved`, 'success');
        await loadModelsPage();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function deleteCloudProviderUI(providerId) {
    if (!confirm(`Delete cloud provider "${providerId}"?`)) return;
    try {
        const res = await fetch(`/api/cloud-providers/${encodeURIComponent(providerId)}`, { method: 'DELETE' });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Failed to delete provider');
        }
        showToast(`Provider "${providerId}" deleted`, 'success');
        await loadModelsPage();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

function openCloudModelModal(modelId = null) {
    const modal = $('#cloud-model-modal');
    if (!modal) return;
    if (state.modelsAdmin.providers.length === 0) {
        showToast('Create a Cloud Provider first before adding a Cloud Model.', 'error');
        return;
    }

    const provSelect = $('#cmodel-provider-id');
    provSelect.innerHTML = state.modelsAdmin.providers
        .map(p => `<option value="${escapeHtml(p.provider_id)}">${escapeHtml(p.display_name)} (${escapeHtml(p.provider_id)})</option>`)
        .join('');

    const existing = modelId
        ? state.modelsAdmin.cloudModels.find(m => m.model_id === modelId)
        : null;

    $('#cmodel-edit-mode').value = existing ? 'edit' : 'create';
    $('#cmodel-modal-title').textContent = existing ? `✏️ Edit Cloud Model: ${existing.model_id}` : '➕ Add Cloud Model';
    const idInput = $('#cmodel-id');
    idInput.value = existing ? existing.model_id : '';
    idInput.disabled = Boolean(existing);
    provSelect.value = existing ? existing.provider_id : state.modelsAdmin.providers[0].provider_id;
    $('#cmodel-slug').value = existing ? existing.remote_model_slug : '';
    $('#cmodel-exploit-th').value = existing ? existing.exploit_threshold : 0.50;
    $('#cmodel-misalign-th').value = existing ? existing.misalignment_threshold : 0.65;
    $('#cmodel-threat-th').value = existing ? existing.threat_threshold : 0.50;
    $('#cmodel-price').value = existing && existing.input_price_per_1m_usd != null ? existing.input_price_per_1m_usd : '';
    $('#cmodel-ctx').value = existing && existing.max_context_tokens != null ? existing.max_context_tokens : '';
    $('#cmodel-state-format').value = existing ? existing.state_format : 'canonical_text';
    $('#cmodel-enabled').checked = existing ? Boolean(existing.enabled) : true;
    modal.classList.add('open');
}

function closeCloudModelModal() {
    const modal = $('#cloud-model-modal');
    if (modal) modal.classList.remove('open');
}

async function submitCloudModelForm() {
    const mode = $('#cmodel-edit-mode').value;
    const modelId = $('#cmodel-id').value.trim().toLowerCase();
    const payload = {
        model_id: modelId,
        provider_id: $('#cmodel-provider-id').value,
        remote_model_slug: $('#cmodel-slug').value.trim(),
        exploit_threshold: parseFloat($('#cmodel-exploit-th').value) || 0.50,
        misalignment_threshold: parseFloat($('#cmodel-misalign-th').value) || 0.65,
        threat_threshold: parseFloat($('#cmodel-threat-th').value) || 0.50,
        input_price_per_1m_usd: $('#cmodel-price').value !== '' ? parseFloat($('#cmodel-price').value) : null,
        max_context_tokens: $('#cmodel-ctx').value !== '' ? parseInt($('#cmodel-ctx').value, 10) : null,
        state_format: $('#cmodel-state-format').value,
        enabled: $('#cmodel-enabled').checked,
    };

    try {
        const url = mode === 'edit' ? `/api/cloud-models/${encodeURIComponent(modelId)}` : '/api/cloud-models';
        const res = await fetch(url, {
            method: mode === 'edit' ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Failed to save cloud model');
        }
        closeCloudModelModal();
        showToast(`Cloud model "${modelId}" saved`, 'success');
        await Promise.all([loadModelsPage(), loadModels()]);
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function toggleCloudModelEnabled(modelId) {
    const m = state.modelsAdmin.cloudModels.find(x => x.model_id === modelId);
    if (!m) return;
    const payload = {
        model_id: m.model_id,
        provider_id: m.provider_id,
        remote_model_slug: m.remote_model_slug,
        question_profile_id: m.question_profile_id,
        state_format: m.state_format,
        exploit_threshold: m.exploit_threshold,
        misalignment_threshold: m.misalignment_threshold,
        threat_threshold: m.threat_threshold,
        input_price_per_1m_usd: m.input_price_per_1m_usd,
        max_context_tokens: m.max_context_tokens,
        enabled: !m.enabled,
    };
    try {
        const res = await fetch(`/api/cloud-models/${encodeURIComponent(modelId)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!res.ok) throw new Error('Failed to toggle model status');
        showToast(`Model "${modelId}" ${payload.enabled ? 'enabled' : 'disabled'}`, 'info');
        await Promise.all([loadModelsPage(), loadModels()]);
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function deleteCloudModelUI(modelId) {
    if (!confirm(`Delete cloud model "${modelId}"?`)) return;
    try {
        const res = await fetch(`/api/cloud-models/${encodeURIComponent(modelId)}`, { method: 'DELETE' });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Failed to delete model');
        }
        showToast(`Cloud model "${modelId}" deleted`, 'success');
        await Promise.all([loadModelsPage(), loadModels()]);
    } catch (e) {
        showToast(e.message, 'error');
    }
}

// ─── Paginated & Multi-Select History (ADR 0012) ────────────────────────────

async function loadHistoryPage() {
    const h = state.history;
    const offset = (h.page - 1) * h.limit;
    const params = new URLSearchParams({ limit: String(h.limit), offset: String(offset) });
    if (h.dataset) params.set('dataset', h.dataset);
    if (h.model) params.set('model', h.model);
    if (h.status && h.status !== 'all') params.set('status', h.status);

    try {
        const res = await fetch(`/api/runs?${params.toString()}`);
        if (!res.ok) throw new Error('Failed to load history');
        const totalHeader = parseInt(res.headers.get('X-Total-Count') || '0', 10);
        const items = await res.json();
        h.items = items;
        h.total = Number.isNaN(totalHeader) ? items.length : totalHeader;
        h.totalPages = Math.max(1, Math.ceil(h.total / h.limit));
        if (h.page > h.totalPages) {
            h.page = h.totalPages;
        }
        renderHistoryTable();
        updateHistorySelectionBar();
    } catch (e) {
        console.error('Failed to load paginated history:', e);
    }
}

function renderHistoryTable() {
    const tbody = $('#history-tbody');
    const h = state.history;
    if (!tbody) return;

    if (h.items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" class="empty-state">No benchmark runs match the current filters.</td></tr>';
    } else {
        tbody.innerHTML = h.items.map(r => {
            const selectable = r.status === 'completed' || r.status === 'budget_stopped';
            const checked = h.selectedRunIds.has(r.run_id) ? 'checked' : '';
            const startedAt = r.started_at ? new Date(r.started_at).toLocaleString('en-US') : '—';
            return `
                <tr onclick="viewRunDetail('${escapeHtml(r.run_id)}')">
                    <td style="text-align: center;" onclick="event.stopPropagation()">
                        <input type="checkbox" ${checked} ${selectable ? '' : 'disabled title="Only completed or budget_stopped runs can be added to a report"'}
                            onchange="toggleHistoryRunSelection('${escapeHtml(r.run_id)}', this.checked)">
                    </td>
                    <td><span class="mono text-sm">${escapeHtml(r.run_id)}</span></td>
                    <td>${escapeHtml(r.dataset_name)}</td>
                    <td>${escapeHtml(r.model_name)}</td>
                    <td class="mono">${r.total_cases || '—'}</td>
                    <td class="mono ${getMetricClass(r.accuracy)}">${r.accuracy ? r.accuracy + '%' : '—'}</td>
                    <td class="mono ${getMetricClass(r.f1)}">${r.f1 ? r.f1 + '%' : '—'}</td>
                    <td class="mono">${r.avg_latency_ms ? r.avg_latency_ms + 'ms' : '—'}</td>
                    <td>${getStatusBadge(r.status)}</td>
                    <td>
                        <span class="text-sm text-muted">${startedAt}</span>
                        <button class="btn btn-danger btn-sm" onclick="deleteRunFromHistory('${escapeHtml(r.run_id)}', event)" title="Delete" style="margin-left:8px;">✕</button>
                    </td>
                </tr>`;
        }).join('');
    }

    const startIdx = h.total === 0 ? 0 : (h.page - 1) * h.limit + 1;
    const endIdx = Math.min(h.page * h.limit, h.total);
    setText('#history-pagination-info', `Showing ${startIdx} - ${endIdx} of ${h.total} runs`);
    setText('#history-current-page', String(h.page));
    setText('#history-total-pages', String(h.totalPages));
    const prevDisabled = h.page <= 1;
    const nextDisabled = h.page >= h.totalPages;
    if ($('#history-page-first')) $('#history-page-first').disabled = prevDisabled;
    if ($('#history-page-prev')) $('#history-page-prev').disabled = prevDisabled;
    if ($('#history-page-next')) $('#history-page-next').disabled = nextDisabled;
    if ($('#history-page-last')) $('#history-page-last').disabled = nextDisabled;
}

function toggleHistoryRunSelection(runId, checked) {
    if (checked) {
        state.history.selectedRunIds.add(runId);
    } else {
        state.history.selectedRunIds.delete(runId);
    }
    updateHistorySelectionBar();
}

function updateHistorySelectionBar() {
    const bar = $('#history-selection-bar');
    const count = state.history.selectedRunIds.size;
    if (!bar) return;
    bar.style.display = count > 0 ? 'flex' : 'none';
    setText('#history-selected-count', `${count} run${count === 1 ? '' : 's'} selected`);

    const addBtn = $('#btn-history-add-to-draft');
    if (addBtn) {
        const hasActiveDraft = Boolean(state.reports.activeReport && state.reports.activeReport.status === 'draft');
        addBtn.style.display = hasActiveDraft ? 'inline-flex' : 'none';
    }
}

function clearHistorySelection() {
    state.history.selectedRunIds.clear();
    renderHistoryTable();
    updateHistorySelectionBar();
}

function onHistoryFilterChanged() {
    clearTimeout(state.history.filterDebounceTimer);
    state.history.filterDebounceTimer = setTimeout(() => {
        state.history.dataset = ($('#history-filter-dataset')?.value || '').trim();
        state.history.model = ($('#history-filter-model')?.value || '').trim();
        state.history.status = $('#history-filter-status')?.value || 'all';
        state.history.page = 1;
        loadHistoryPage();
    }, 220);
}

function onHistoryPageSizeChanged() {
    state.history.limit = parseInt($('#history-page-size')?.value || '25', 10);
    state.history.page = 1;
    loadHistoryPage();
}

function resetHistoryFilters() {
    if ($('#history-filter-dataset')) $('#history-filter-dataset').value = '';
    if ($('#history-filter-model')) $('#history-filter-model').value = '';
    if ($('#history-filter-status')) $('#history-filter-status').value = 'all';
    state.history.dataset = '';
    state.history.model = '';
    state.history.status = 'all';
    state.history.page = 1;
    loadHistoryPage();
}

function goToHistoryPage(page) {
    const target = Math.max(1, Math.min(page, state.history.totalPages));
    if (target === state.history.page) return;
    state.history.page = target;
    loadHistoryPage();
}

async function deleteRunFromHistory(runId, event) {
    if (event) event.stopPropagation();
    await deleteRun(runId, event);
    state.history.selectedRunIds.delete(runId);
    await loadHistoryPage();
}

async function createReportFromHistorySelection() {
    const runIds = Array.from(state.history.selectedRunIds);
    if (runIds.length === 0) return;
    const today = new Date().toISOString().slice(0, 10);
    try {
        const res = await fetch('/api/reports', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                title: `Periodic Benchmark Report (${today})`,
                period_label: today.slice(0, 7),
                researcher_notes: '',
                selected_run_ids: runIds,
            }),
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Failed to create draft report');
        }
        const created = await res.json();
        state.history.selectedRunIds.clear();
        state.reports.activeReportId = created.report_id;
        state.reports.activeReport = created;
        showToast(`Draft report "${created.title}" created with ${runIds.length} run(s)`, 'success');
        switchPage('reports');
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function addHistorySelectionToActiveDraft() {
    const active = state.reports.activeReport;
    if (!active || active.status !== 'draft') {
        showToast('Open a draft report in Report Studio first.', 'error');
        return;
    }
    const merged = Array.from(new Set([...(active.selected_run_ids || []), ...state.history.selectedRunIds]));
    try {
        const res = await fetch(`/api/reports/${encodeURIComponent(active.report_id)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ selected_run_ids: merged }),
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Failed to add runs to draft');
        }
        state.reports.activeReport = await res.json();
        state.history.selectedRunIds.clear();
        showToast(`Added runs to draft "${active.title}"`, 'success');
        switchPage('reports');
    } catch (e) {
        showToast(e.message, 'error');
    }
}

// ─── Periodic Report Studio (ADR 0012) ──────────────────────────────────────

async function loadReportsPage() {
    try {
        const res = await fetch('/api/reports');
        if (!res.ok) throw new Error('Failed to load reports');
        state.reports.list = await res.json();
        renderReportsSidebar();

        if (state.reports.activeReportId) {
            const exists = state.reports.list.some(r => r.report_id === state.reports.activeReportId);
            if (exists) {
                await selectReport(state.reports.activeReportId);
                return;
            }
        }
        if (state.reports.list.length > 0) {
            await selectReport(state.reports.list[0].report_id);
        } else {
            state.reports.activeReportId = null;
            state.reports.activeReport = null;
            renderActiveReport();
        }
    } catch (e) {
        console.error('Failed to load reports:', e);
        showToast('Failed to load reports', 'error');
    }
}

function renderReportsSidebar() {
    const container = $('#reports-list-container');
    if (!container) return;
    const list = state.reports.list || [];
    if (list.length === 0) {
        container.innerHTML = '<div class="empty-state">No saved reports yet. Select runs in History or create a new draft.</div>';
        return;
    }

    container.innerHTML = list.map(r => {
        const isActive = r.report_id === state.reports.activeReportId;
        const badge = r.status === 'published'
            ? '<span class="badge badge-sealed">🔒 Sealed</span>'
            : '<span class="badge badge-draft">✏️ Draft</span>';
        return `
            <button type="button" class="report-list-item ${isActive ? 'active' : ''}" onclick="selectReport('${escapeHtml(r.report_id)}')">
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 4px;">
                    <span class="font-semibold text-sm">${escapeHtml(r.title)}</span>
                    ${badge}
                </div>
                <div class="text-xs text-muted mono">${escapeHtml(r.period_label || 'No period')} · ${r.run_count} run${r.run_count === 1 ? '' : 's'}</div>
            </button>`;
    }).join('');
}

async function selectReport(reportId) {
    try {
        const res = await fetch(`/api/reports/${encodeURIComponent(reportId)}`);
        if (!res.ok) throw new Error('Failed to load report details');
        state.reports.activeReportId = reportId;
        state.reports.activeReport = await res.json();
        renderReportsSidebar();
        renderActiveReport();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function createEmptyDraftReport() {
    const today = new Date().toISOString().slice(0, 10);
    try {
        const res = await fetch('/api/reports', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                title: `New Periodic Report (${today})`,
                period_label: today.slice(0, 7),
                researcher_notes: '',
                selected_run_ids: [],
            }),
        });
        if (!res.ok) throw new Error('Failed to create draft');
        const created = await res.json();
        state.reports.activeReportId = created.report_id;
        state.reports.activeReport = created;
        showToast('New draft report created', 'success');
        await loadReportsPage();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

function renderActiveReport() {
    const emptyEl = $('#report-empty-state');
    const editorEl = $('#report-editor-container');
    const r = state.reports.activeReport;
    if (!r) {
        if (emptyEl) emptyEl.style.display = 'flex';
        if (editorEl) editorEl.style.display = 'none';
        return;
    }
    if (emptyEl) emptyEl.style.display = 'none';
    if (editorEl) editorEl.style.display = 'block';

    const isPublished = r.status === 'published';
    setText('#rpt-active-id', r.report_id);
    const statusBadge = $('#rpt-status-badge');
    if (statusBadge) {
        statusBadge.innerHTML = isPublished
            ? '<span class="badge badge-sealed">🔒 Published (Sealed Snapshot — Immutable)</span>'
            : '<span class="badge badge-draft">✏️ Draft (Editable)</span>';
    }
    setText('#rpt-published-at', isPublished && r.published_at ? `Sealed at ${new Date(r.published_at).toLocaleString('en-US')}` : '');

    // Toggle editable controls based on lifecycle state
    const titleInput = $('#rpt-title-input');
    const periodInput = $('#rpt-period-input');
    const notesInput = $('#rpt-notes-input');
    if (titleInput) { titleInput.value = r.title || ''; titleInput.disabled = isPublished; }
    if (periodInput) { periodInput.value = r.period_label || ''; periodInput.disabled = isPublished; }
    if (notesInput) { notesInput.value = r.researcher_notes || ''; notesInput.disabled = isPublished; }

    if ($('#btn-rpt-save')) $('#btn-rpt-save').style.display = isPublished ? 'none' : 'inline-flex';
    if ($('#btn-rpt-publish')) $('#btn-rpt-publish').style.display = isPublished ? 'none' : 'inline-flex';
    if ($('#btn-rpt-add-from-history')) $('#btn-rpt-add-from-history').style.display = isPublished ? 'none' : 'inline-flex';

    // Pruned runs alert (draft only)
    const prunedEl = $('#rpt-pruned-alert');
    if (prunedEl) {
        if (r.pruned_run_ids && r.pruned_run_ids.length > 0) {
            prunedEl.style.display = 'block';
            prunedEl.innerHTML = `<strong>⚠️ Deleted Runs Removed from Draft:</strong> ${r.pruned_run_ids.map(escapeHtml).join(', ')}`;
        } else {
            prunedEl.style.display = 'none';
        }
    }

    // Parity Warnings
    const warnings = (r.dossier && r.dossier.parity_warnings) || [];
    const warnEl = $('#rpt-parity-warnings');
    if (warnEl) {
        if (warnings.length > 0) {
            warnEl.style.display = 'block';
            warnEl.innerHTML = `<strong>⚠️ Apples-to-Apples Parity Caveats (${warnings.length}):</strong><ul>${warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}</ul>`;
        } else {
            warnEl.style.display = 'none';
        }
    }

    // Included Runs Table
    const runs = (r.dossier && r.dossier.runs) || [];
    setText('#rpt-runs-count', String(runs.length));
    const tbody = $('#rpt-runs-tbody');
    if (tbody) {
        if (runs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="10" class="empty-state">No runs selected yet. Click "Add Runs from History".</td></tr>';
        } else {
            tbody.innerHTML = runs.map(run => `
                <tr>
                    <td class="mono text-xs">${escapeHtml(run.run_id)}</td>
                    <td class="font-semibold">${escapeHtml(run.model_name)}</td>
                    <td>${getRuntimeTierBadge(run.runtime_tier)}</td>
                    <td class="text-xs">${escapeHtml(run.dataset_base || run.dataset_name)}</td>
                    <td class="mono">${run.accuracy.toFixed(2)}%</td>
                    <td class="mono">${run.f1.toFixed(2)}%</td>
                    <td class="mono">${run.fpr.toFixed(2)}%</td>
                    <td class="mono text-xs">$${Number(run.total_cost_usd || 0).toFixed(4)}</td>
                    <td>${getStatusBadge(run.status)}</td>
                    <td>${isPublished ? '' : `<button class="btn btn-danger btn-sm" onclick="removeRunFromDraft('${escapeHtml(run.run_id)}')" title="Remove">✕</button>`}</td>
                </tr>`).join('');
        }
    }

    // AI-Ready Markdown Preview
    const pre = $('#rpt-markdown-preview');
    if (pre) pre.textContent = r.markdown_preview || '';
}

async function saveCurrentDraft() {
    const r = state.reports.activeReport;
    if (!r || r.status === 'published') return;
    try {
        const res = await fetch(`/api/reports/${encodeURIComponent(r.report_id)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                title: $('#rpt-title-input').value.trim(),
                period_label: $('#rpt-period-input').value.trim(),
                researcher_notes: $('#rpt-notes-input').value.trim(),
            }),
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Failed to save draft');
        }
        state.reports.activeReport = await res.json();
        showToast('Draft saved', 'success');
        await loadReportsPage();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function removeRunFromDraft(runId) {
    const r = state.reports.activeReport;
    if (!r || r.status === 'published') return;
    const remaining = (r.selected_run_ids || []).filter(id => id !== runId);
    try {
        const res = await fetch(`/api/reports/${encodeURIComponent(r.report_id)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ selected_run_ids: remaining }),
        });
        if (!res.ok) throw new Error('Failed to remove run');
        state.reports.activeReport = await res.json();
        renderActiveReport();
        showToast(`Removed ${runId} from draft`, 'info');
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function publishCurrentReport() {
    const r = state.reports.activeReport;
    if (!r || r.status === 'published') return;
    if (!confirm('Publish & seal this report? Once published, its snapshot is frozen permanently and cannot be edited.')) return;
    // Save latest title/period/notes before sealing
    await saveCurrentDraft();
    try {
        const res = await fetch(`/api/reports/${encodeURIComponent(r.report_id)}/publish`, { method: 'POST' });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Failed to publish report');
        }
        state.reports.activeReport = await res.json();
        showToast('🔒 Report published and sealed!', 'success');
        await loadReportsPage();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function duplicateCurrentReport() {
    const r = state.reports.activeReport;
    if (!r) return;
    try {
        const res = await fetch(`/api/reports/${encodeURIComponent(r.report_id)}/duplicate`, { method: 'POST' });
        if (!res.ok) throw new Error('Failed to duplicate report');
        const copy = await res.json();
        state.reports.activeReportId = copy.report_id;
        state.reports.activeReport = copy;
        showToast(`Duplicated as draft "${copy.title}"`, 'success');
        await loadReportsPage();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function deleteCurrentReport() {
    const r = state.reports.activeReport;
    if (!r) return;
    const msg = r.status === 'published'
        ? `Permanently delete sealed report "${r.title}"?`
        : `Delete draft report "${r.title}"?`;
    if (!confirm(msg)) return;
    try {
        const res = await fetch(`/api/reports/${encodeURIComponent(r.report_id)}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('Failed to delete report');
        state.reports.activeReportId = null;
        state.reports.activeReport = null;
        showToast('Report deleted', 'success');
        await loadReportsPage();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function copyReportMarkdown() {
    const r = state.reports.activeReport;
    if (!r || !r.markdown_preview) return;
    try {
        await navigator.clipboard.writeText(r.markdown_preview);
        showToast('📋 AI-Ready Markdown copied to clipboard!', 'success');
    } catch (e) {
        showToast('Clipboard copy failed — use Download .md instead', 'error');
    }
}

function downloadReportExport(format) {
    const r = state.reports.activeReport;
    if (!r) return;
    window.location.href = `/api/reports/${encodeURIComponent(r.report_id)}/export?format=${format}`;
}
