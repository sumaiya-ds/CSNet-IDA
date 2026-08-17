/**
 * CSNet-IDA: Security Operations Center & Network IDS Console Logic
 * Full Phase 2 Integration with real Two-Stage Random Forest Backend
 */

document.addEventListener("DOMContentLoaded", () => {
    // =========================================================================
    // Global State Registry
    // =========================================================================
    const state = {
        currentView: "command-center",
        simRunning: false,
        simIntervalId: null,
        simSpeedMs: 2000,
        simFilter: "all",
        simStepIndex: 0,
        simEvents: [],
        currentDemoStep: 0,
        currentIncidentId: null,
        featureImportanceData: null,
        fiCurrentView: "agg" // 'agg', 'trans', 'group'
    };

    // Complete NSL-KDD Services List (70 standard services)
    const ALL_SERVICES = [
        "http", "ftp_data", "smtp", "telnet", "private", "domain_u", "eco_i", "other",
        "IRC", "X11", "Z39_50", "aol", "auth", "bgp", "courier", "csnet_ns", "ctf", "daytime",
        "discard", "domain", "echo", "ecr_i", "efs", "exec", "finger", "ftp",
        "gopher", "harvest", "hostnames", "http_2784", "http_443", "http_8001",
        "imap4", "iso_tsap", "klogin", "kshell", "ldap", "link", "login", "mtp", "name", "netbios_dgm",
        "netbios_ns", "netbios_ssn", "netstat", "nnsp", "nntp", "ntp_u", "pm_dump", "pop_2",
        "pop_3", "printer", "red_i", "remote_job", "rje", "shell", "sql_net",
        "ssh", "sunrpc", "supdup", "systat", "tftp_u", "tim_i", "time", "urh_i", "urp_i",
        "uucp", "uucp_path", "vmnet", "whois"
    ];

    // =========================================================================
    // Navigation & View Switching
    // =========================================================================
    const navItems = document.querySelectorAll(".sidebar-nav .nav-item");
    const viewPanels = document.querySelectorAll(".view-panel");
    const breadcrumb = document.getElementById("view-breadcrumb");

    const TITLE_MAP = {
        "command-center": "COMMAND CENTER // EXECUTIVE OPERATIONS",
        "live-monitor": "LIVE MONITOR // STREAM SIMULATION & INGESTION",
        "incident-center": "INCIDENT CENTER // THREAT MANAGEMENT & TRIAGE",
        "connection-inspector": "CONNECTION INSPECTOR // 40-FEATURE VECTOR WORKSTATION",
        "demo-mode": "DEMONSTRATION MODE // GUIDED SOC WORKFLOW EVALUATION",
        "threat-intel": "THREAT INTELLIGENCE // ATTACK TAXONOMY & MITRE RUNBOOKS",
        "ml-explainability": "ML EXPLAINABILITY // FEATURE IMPORTANCES & MODEL INTERNALS",
        "model-evaluation": "MODEL EVALUATION // NSL-KDD ACADEMIC BENCHMARKS",
        "dataset-intel": "DATASET INTELLIGENCE // NSL-KDD SPECIFICATIONS & FEATURES"
    };

    function switchTab(viewId) {
        if (!viewId) return;
        state.currentView = viewId;

        // Update nav items
        navItems.forEach(item => {
            if (item.getAttribute("data-view") === viewId) {
                item.classList.add("active");
            } else {
                item.classList.remove("active");
            }
        });

        // Update view panels
        viewPanels.forEach(panel => {
            if (panel.id === `view-${viewId}`) {
                panel.classList.add("active");
            } else {
                panel.classList.remove("active");
            }
        });

        // Update breadcrumb
        if (breadcrumb) {
            breadcrumb.textContent = TITLE_MAP[viewId] || `CSNet-IDA // ${viewId.toUpperCase().replace("-", " ")}`;
        }

        // Lazy-load view-specific content
        if (viewId === "command-center") {
            loadAnalyticsSummary();
            loadOverviewIncidents();
        } else if (viewId === "incident-center") {
            loadIncidents();
        } else if (viewId === "ml-explainability") {
            loadFeatureImportance();
        }
    }

    // Expose switchTab globally for inline HTML onclick attributes
    window.switchTab = switchTab;

    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const viewId = item.getAttribute("data-view");
            if (viewId) switchTab(viewId);
        });
    });

    // Topbar Clock
    const clockEl = document.getElementById("topbar-clock");
    function updateClock() {
        const now = new Date();
        const utcStr = now.toUTCString().split(" ")[4];
        if (clockEl) clockEl.textContent = `UTC ${utcStr}`;
    }
    setInterval(updateClock, 1000);
    updateClock();

    // Collapsible Blocks in Inspector
    window.toggleBlock = function(headerEl) {
        const block = headerEl.closest(".form-collapsible-block");
        if (block) {
            block.classList.toggle("collapsed");
        }
    };

    // =========================================================================
    // 1. Command Center Telemetry, Analytics & Live Traffic Canvas Chart
    // =========================================================================
    function drawTrafficVelocityChart(timeline) {
        const canvas = document.getElementById("traffic-velocity-canvas");
        if (!canvas) return;

        const ctx = canvas.getContext("2d");
        const rect = canvas.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;

        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);

        const width = rect.width;
        const height = rect.height;

        ctx.clearRect(0, 0, width, height);

        const padLeft = 40;
        const padRight = 20;
        const padTop = 20;
        const padBottom = 25;
        const plotWidth = width - padLeft - padRight;
        const plotHeight = height - padTop - padBottom;

        // Draw horizontal grid lines & labels
        ctx.strokeStyle = "rgba(255, 255, 255, 0.06)";
        ctx.fillStyle = "rgba(148, 163, 184, 0.7)";
        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.textAlign = "right";

        [0, 25, 50, 75, 100].forEach(val => {
            const y = padTop + plotHeight - (val / 100) * plotHeight;
            ctx.beginPath();
            ctx.moveTo(padLeft, y);
            ctx.lineTo(width - padRight, y);
            ctx.stroke();
            ctx.fillText(`${val}%`, padLeft - 6, y + 3);
        });

        // Threshold Line (τ = 40%)
        const threshY = padTop + plotHeight - 0.40 * plotHeight;
        ctx.strokeStyle = "rgba(245, 158, 11, 0.65)";
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(padLeft, threshY);
        ctx.lineTo(width - padRight, threshY);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = "#f59e0b";
        ctx.textAlign = "left";
        ctx.fillText("τ = 0.40 Threshold", padLeft + 6, threshY - 4);

        if (!timeline || timeline.length === 0) {
            ctx.fillStyle = "rgba(148, 163, 184, 0.4)";
            ctx.textAlign = "center";
            ctx.font = "11px 'Inter', sans-serif";
            ctx.fillText("Awaiting network telemetry points (Run simulation or execute inference)...", width / 2, height / 2 + 5);
            return;
        }

        const count = Math.min(timeline.length, 25);
        const dataSlice = timeline.slice(-count);
        const stepX = plotWidth / Math.max(dataSlice.length - 1, 1);

        // Draw Volume Bars
        const barWidth = Math.max(4, stepX * 0.45);
        dataSlice.forEach((item, idx) => {
            const x = padLeft + idx * stepX - barWidth / 2;
            const barH = plotHeight * 0.35;
            const y = padTop + plotHeight - barH;

            ctx.fillStyle = item.is_attack ? "rgba(239, 68, 68, 0.35)" : "rgba(34, 197, 94, 0.25)";
            ctx.fillRect(x, y, barWidth, barH);
        });

        // Draw Attack Incursion Rate Line
        ctx.strokeStyle = "#ef4444";
        ctx.lineWidth = 2.5;
        ctx.beginPath();

        let runningAttacks = 0;
        const points = [];

        dataSlice.forEach((item, idx) => {
            if (item.is_attack) runningAttacks++;
            const rate = runningAttacks / (idx + 1);
            const x = padLeft + idx * stepX;
            const y = padTop + plotHeight - rate * plotHeight;
            points.push({ x, y, rate, time: item.timestamp, isAttack: item.is_attack });

            if (idx === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });

        ctx.stroke();

        // Draw Line Points & Glow
        points.forEach(pt => {
            ctx.fillStyle = pt.isAttack ? "#ef4444" : "#22c55e";
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, 3.5, 0, Math.PI * 2);
            ctx.fill();
        });

        // Draw latest time stamp label
        ctx.fillStyle = "rgba(148, 163, 184, 0.8)";
        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.textAlign = "center";
        if (points.length > 0) {
            ctx.fillText(points[0].time, points[0].x, height - 6);
            if (points.length > 1) {
                ctx.fillText(points[points.length - 1].time, points[points.length - 1].x, height - 6);
            }
        }
    }

    window.addEventListener("resize", () => {
        if (state.currentView === "command-center") {
            loadAnalyticsSummary();
        }
    });

    async function loadAnalyticsSummary() {
        try {
            const resp = await fetch("/api/analytics");
            if (!resp.ok) return;
            const data = await resp.json();

            // KPIs
            const kpiTotal = document.getElementById("kpi-total-flows");
            const kpiNormal = document.getElementById("kpi-normal-count");
            const kpiNormalPct = document.getElementById("kpi-normal-pct");
            const kpiAttack = document.getElementById("kpi-attack-count");
            const kpiAttackPct = document.getElementById("kpi-attack-pct");
            const kpiCritical = document.getElementById("kpi-critical-count");
            const kpiLatency = document.getElementById("kpi-avg-latency");

            if (kpiTotal) kpiTotal.textContent = data.total_flows;
            if (kpiNormal) kpiNormal.textContent = data.normal_flows;
            if (kpiAttack) kpiAttack.textContent = data.attack_flows;
            if (kpiCritical) kpiCritical.textContent = data.critical_alerts;
            if (kpiLatency) kpiLatency.textContent = `${data.avg_latency_ms} ms`;

            if (data.total_flows > 0) {
                const normPct = ((data.normal_flows / data.total_flows) * 100).toFixed(1);
                if (kpiNormalPct) kpiNormalPct.textContent = `${normPct}%`;
                if (kpiAttackPct) kpiAttackPct.textContent = `${data.attack_rate_pct}%`;
            } else {
                if (kpiNormalPct) kpiNormalPct.textContent = "0.0%";
                if (kpiAttackPct) kpiAttackPct.textContent = "0.0%";
            }

            // Security Posture Card & Risk Score Gauge
            const postureTitle = document.getElementById("posture-state-title");
            const postureBadge = document.getElementById("posture-state-badge");
            const postureDesc = document.getElementById("posture-score-desc");
            const postureFactors = document.getElementById("posture-factors-list");
            const postureRiskScore = document.getElementById("posture-risk-score");
            const topbarPostureText = document.getElementById("topbar-posture-text");
            const topbarPosturePill = document.getElementById("topbar-posture-pill");

            if (postureTitle) postureTitle.textContent = data.posture;
            if (postureRiskScore) postureRiskScore.textContent = data.risk_score !== undefined ? Math.round(data.risk_score) : 0;

            if (postureBadge) {
                postureBadge.textContent = data.posture_level.toUpperCase();
                postureBadge.className = `posture-state-badge sev-${data.posture_level}`;
            }
            if (topbarPostureText) topbarPostureText.textContent = `POSTURE: ${data.posture_level.toUpperCase()}`;
            if (topbarPosturePill) {
                topbarPosturePill.style.color = data.posture_level === "critical" ? "var(--c-dos)" :
                    data.posture_level === "high" ? "var(--c-r2l)" :
                    data.posture_level === "medium" ? "var(--c-probe)" : "var(--c-normal)";
            }

            if (postureFactors && data.posture_factors) {
                postureFactors.innerHTML = data.posture_factors.map(f => `<div class="factor-item">● ${f}</div>`).join("");
            }

            // Attack Family Breakdown Meters
            const families = data.families || {};
            const attackTotal = data.attack_flows || 1;
            ["dos", "probe", "r2l", "u2r"].forEach(fKey => {
                const fName = fKey === "dos" ? "DoS" : fKey === "probe" ? "Probe" : fKey === "r2l" ? "R2L" : "U2R";
                const count = families[fName] || 0;
                const countEl = document.getElementById(`stat-${fKey}-count`);
                const meterEl = document.getElementById(`meter-${fKey}-overview`);
                if (countEl) countEl.textContent = `${count} flows`;
                if (meterEl) {
                    const pct = data.attack_flows > 0 ? ((count / attackTotal) * 100).toFixed(1) : 0;
                    meterEl.style.width = `${pct}%`;
                }
            });

            // Severity Breakdown Meters
            const sevs = data.severities || {};
            const sevTotal = data.total_flows || 1;
            ["critical", "high", "medium", "low"].forEach(sKey => {
                const count = sevs[sKey] || 0;
                const pct = data.total_flows > 0 ? ((count / sevTotal) * 100).toFixed(1) : 0;
                const countEl = document.getElementById(`stat-sev-${sKey}`);
                const meterEl = document.getElementById(`meter-sev-${sKey}`);
                if (countEl) countEl.textContent = `${count} (${pct}%)`;
                if (meterEl) meterEl.style.width = `${pct}%`;
            });

            // Transport Layer Protocol Distribution
            const protos = data.protocols || {};
            const protoTotal = data.total_flows || 1;
            ["tcp", "udp", "icmp"].forEach(pKey => {
                const count = protos[pKey] || 0;
                const pct = data.total_flows > 0 ? ((count / protoTotal) * 100).toFixed(1) : 0;
                const countEl = document.getElementById(`proto-${pKey}-count`);
                const fillEl = document.getElementById(`proto-${pKey}-fill`);
                if (countEl) countEl.textContent = `${count} (${pct}%)`;
                if (fillEl) fillEl.style.width = `${pct}%`;
            });

            // Top Active Services
            const topServicesEl = document.getElementById("overview-top-services");
            if (topServicesEl) {
                if (data.top_services && data.top_services.length > 0) {
                    topServicesEl.innerHTML = data.top_services.map(([svc, count]) => `
                        <div class="service-row-item">
                            <span class="mono text-cyan">${svc}</span>
                            <span class="mono">${count} flows</span>
                        </div>
                    `).join("");
                } else {
                    topServicesEl.innerHTML = `<div class="text-dim text-center py-2">Awaiting network telemetry...</div>`;
                }
            }

            // Draw Live Traffic Velocity Canvas Chart
            drawTrafficVelocityChart(data.timeline || []);

        } catch (e) {
            console.error("Failed to load analytics summary:", e);
        }
    }

    async function loadOverviewIncidents() {
        const tbody = document.getElementById("overview-incidents-tbody");
        if (!tbody) return;

        try {
            const resp = await fetch("/api/incidents?limit=5");
            if (!resp.ok) return;
            const data = await resp.json();
            const incidents = data.incidents || [];

            if (incidents.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" class="table-empty">No security incidents recorded.</td></tr>`;
                return;
            }

            tbody.innerHTML = incidents.map(inc => `
                <tr>
                    <td><strong class="text-cyan">${inc.id}</strong></td>
                    <td>${inc.timestamp.split(" ")[1] || inc.timestamp}</td>
                    <td><span class="f-badge f-${inc.attack_family.toLowerCase()}">${inc.attack_family}</span></td>
                    <td><span class="sev-badge sev-${inc.severity.toLowerCase()}">${inc.severity.toUpperCase()}</span></td>
                    <td>${(inc.attack_probability * 100).toFixed(1)}%</td>
                    <td>${inc.protocol} / ${inc.service}</td>
                    <td><span class="badge-status">${inc.status}</span></td>
                    <td>
                        <button class="btn btn-outline btn-sm" onclick="openIncidentModal('${inc.id}')">Investigate</button>
                    </td>
                </tr>
            `).join("");
        } catch (e) {
            console.error("Failed to load overview incidents:", e);
        }
    }

    // =========================================================================
    // 2. Live Monitor & Real-Time Simulation Engine
    // =========================================================================
    const simScenarioSelect = document.getElementById("sim-scenario-select");
    const streamToggleBtn = document.getElementById("stream-toggle-btn");
    const streamIcon = document.getElementById("stream-icon");
    const streamBtnText = document.getElementById("stream-btn-text");
    const streamStepBtn = document.getElementById("stream-step-btn");
    const streamReplayBtn = document.getElementById("stream-replay-btn");
    const streamClearBtn = document.getElementById("stream-clear-btn");
    const streamSpeedSelect = document.getElementById("stream-speed");
    const streamFilterSelect = document.getElementById("stream-filter");
    const streamTbody = document.getElementById("stream-tbody");
    const streamStatusText = document.getElementById("stream-status-text");
    const liveBlinkDot = document.getElementById("live-blink-dot");
    const streamEventCounter = document.getElementById("stream-event-counter");
    const streamThreatCounter = document.getElementById("stream-threat-counter");

    const latestFlowId = document.getElementById("latest-flow-id");
    const latestFlowVerdict = document.getElementById("latest-flow-verdict");
    const latestFlowDesc = document.getElementById("latest-flow-desc");
    const latestProto = document.getElementById("latest-proto");
    const latestSvc = document.getElementById("latest-svc");
    const latestFlag = document.getElementById("latest-flag");
    const streamGaugeVal = document.getElementById("stream-gauge-val");
    const streamGaugeFill = document.getElementById("stream-gauge-fill");

    async function executeSimulationStep() {
        const scenario = simScenarioSelect ? simScenarioSelect.value : "mixed_enterprise";
        try {
            const resp = await fetch("/api/simulate-step", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    scenario: scenario,
                    step_index: state.simStepIndex
                })
            });

            if (!resp.ok) throw new Error("Simulation step request failed");
            const data = await resp.json();
            state.simStepIndex++;

            const pred = data.prediction;
            const features = data.features;
            const isAttack = pred.is_attack;
            const prob = pred.stage1.attack_probability;

            // Update Latest Flow Card
            if (latestFlowId) latestFlowId.textContent = pred.sample_id;
            if (latestFlowVerdict) {
                latestFlowVerdict.textContent = pred.final_prediction === "Normal" ? "VERDICT: NORMAL TRAFFIC" : `ATTACK: ${pred.final_prediction}`;
                latestFlowVerdict.style.color = isAttack ? "var(--c-dos)" : "var(--c-normal)";
            }
            if (latestFlowDesc) latestFlowDesc.textContent = data.flow_hint;
            if (latestProto) latestProto.textContent = `PROTO: ${features.protocol_type.toUpperCase()}`;
            if (latestSvc) latestSvc.textContent = `SVC: ${features.service}`;
            if (latestFlag) latestFlag.textContent = `FLAG: ${features.flag}`;

            // Update Gauge
            if (streamGaugeVal) streamGaugeVal.textContent = `${(prob * 100).toFixed(2)}%`;
            if (streamGaugeFill) streamGaugeFill.style.width = `${Math.min(100, Math.max(0, prob * 100))}%`;

            // Append to table
            state.simEvents.unshift({
                timestamp: pred.timestamp.split(" ")[1] || pred.timestamp,
                hint: data.flow_hint,
                proto: features.protocol_type,
                svc: features.service,
                srcBytes: features.src_bytes,
                dstBytes: features.dst_bytes,
                prob: prob,
                stage1Decision: pred.stage1.decision,
                finalVerdict: pred.final_prediction,
                severity: pred.alert_severity,
                isAttack: isAttack,
                sampleId: pred.sample_id
            });

            if (state.simEvents.length > 50) state.simEvents.pop();
            renderStreamTable();

            // Refresh summary counters
            loadAnalyticsSummary();
            loadIncidents();
        } catch (err) {
            console.error("Simulation error:", err);
        }
    }

    function renderStreamTable() {
        if (!streamTbody) return;

        let filtered = state.simEvents;
        const filter = state.simFilter;

        if (filter === "attacks") filtered = filtered.filter(e => e.isAttack);
        else if (filter === "normal") filtered = filtered.filter(e => !e.isAttack);
        else if (filter === "critical") filtered = filtered.filter(e => e.severity === "critical" || e.severity === "high");
        else if (filter === "dos") filtered = filtered.filter(e => e.finalVerdict === "DoS");
        else if (filter === "probe") filtered = filtered.filter(e => e.finalVerdict === "Probe");
        else if (filter === "r2l") filtered = filtered.filter(e => e.finalVerdict === "R2L");
        else if (filter === "u2r") filtered = filtered.filter(e => e.finalVerdict === "U2R");

        if (streamEventCounter) streamEventCounter.textContent = state.simEvents.length;
        if (streamThreatCounter) streamThreatCounter.textContent = state.simEvents.filter(e => e.isAttack).length;

        if (filtered.length === 0) {
            streamTbody.innerHTML = `<tr><td colspan="9" class="table-empty">No events matching current filter (${filter}).</td></tr>`;
            return;
        }

        streamTbody.innerHTML = filtered.slice(0, 25).map(e => `
            <tr>
                <td>${e.timestamp}</td>
                <td><strong>${e.hint}</strong></td>
                <td>${e.proto.toUpperCase()} / ${e.svc}</td>
                <td>${e.srcBytes} / ${e.dstBytes}</td>
                <td class="mono">${(e.prob * 100).toFixed(1)}%</td>
                <td style="color: ${e.isAttack ? 'var(--c-dos)' : 'var(--c-normal)'}; font-weight:600;">${e.stage1Decision}</td>
                <td><span class="f-badge f-${e.finalVerdict.toLowerCase()}">${e.finalVerdict}</span></td>
                <td><span class="sev-badge sev-${e.severity.toLowerCase()}">${e.severity.toUpperCase()}</span></td>
                <td>
                    <button class="btn btn-ghost btn-sm" onclick="inspectSampleVector('${e.sampleId}')">Inspect</button>
                </td>
            </tr>
        `).join("");
    }

    function startStream() {
        if (state.simRunning) return;
        state.simRunning = true;
        if (streamIcon) streamIcon.textContent = "⏸";
        if (streamBtnText) streamBtnText.textContent = "Pause Live Stream";
        if (streamStatusText) {
            streamStatusText.textContent = "STREAMING LIVE";
            streamStatusText.style.color = "var(--c-accent)";
        }
        if (liveBlinkDot) liveBlinkDot.classList.add("active");

        executeSimulationStep();
        state.simIntervalId = setInterval(executeSimulationStep, state.simSpeedMs);
    }

    function pauseStream() {
        if (!state.simRunning) return;
        state.simRunning = false;
        if (streamIcon) streamIcon.textContent = "▶";
        if (streamBtnText) streamBtnText.textContent = "Start Live Stream";
        if (streamStatusText) {
            streamStatusText.textContent = "PAUSED";
            streamStatusText.style.color = "var(--text-muted)";
        }
        if (liveBlinkDot) liveBlinkDot.classList.remove("active");

        if (state.simIntervalId) {
            clearInterval(state.simIntervalId);
            state.simIntervalId = null;
        }
    }

    if (streamToggleBtn) {
        streamToggleBtn.addEventListener("click", () => {
            if (state.simRunning) pauseStream();
            else startStream();
        });
    }

    if (streamStepBtn) {
        streamStepBtn.addEventListener("click", () => {
            pauseStream();
            executeSimulationStep();
        });
    }

    if (streamReplayBtn) {
        streamReplayBtn.addEventListener("click", () => {
            state.simStepIndex = 0;
            executeSimulationStep();
        });
    }

    if (streamClearBtn) {
        streamClearBtn.addEventListener("click", () => {
            state.simEvents = [];
            renderStreamTable();
        });
    }

    if (streamSpeedSelect) {
        streamSpeedSelect.addEventListener("change", (e) => {
            state.simSpeedMs = parseInt(e.target.value, 10);
            if (state.simRunning) {
                pauseStream();
                startStream();
            }
        });
    }

    if (streamFilterSelect) {
        streamFilterSelect.addEventListener("change", (e) => {
            state.simFilter = e.target.value;
            renderStreamTable();
        });
    }

    // =========================================================================
    // 3. Incident Management Center & Investigation Modal
    // =========================================================================
    const incFilterStatus = document.getElementById("inc-filter-status");
    const incFilterFamily = document.getElementById("inc-filter-family");
    const incFilterSeverity = document.getElementById("inc-filter-severity");
    const incSortSelect = document.getElementById("inc-sort-select");
    const incSearchInput = document.getElementById("inc-search-input");
    const incRefreshBtn = document.getElementById("inc-refresh-btn");
    const incidentsTbody = document.getElementById("incidents-tbody");
    const incCountBadge = document.getElementById("inc-count-badge");
    const navIncidentCount = document.getElementById("nav-incident-count");

    // Modal elements
    const incidentModalOverlay = document.getElementById("incident-modal-overlay");
    const modalCloseBtn = document.getElementById("modal-close-btn");
    const modalIncId = document.getElementById("modal-inc-id");
    const modalAttackFamily = document.getElementById("modal-attack-family");
    const modalSeverity = document.getElementById("modal-severity");
    const modalStage1Prob = document.getElementById("modal-stage1-prob");
    const modalStatusBadge = document.getElementById("modal-status-badge");
    const modalPipelineDesc = document.getElementById("modal-pipeline-desc");
    const modalStage2Breakdown = document.getElementById("modal-stage2-breakdown");
    const modalContributionsTbody = document.getElementById("modal-contributions-tbody");
    const modalFeaturesSnapshot = document.getElementById("modal-features-snapshot");
    const modalStatusForm = document.getElementById("modal-status-form");
    const modalStatusSelect = document.getElementById("modal-status-select");
    const modalNotesInput = document.getElementById("modal-notes-input");

    async function loadIncidents() {
        if (!incidentsTbody) return;

        const status = incFilterStatus ? incFilterStatus.value : "all";
        const family = incFilterFamily ? incFilterFamily.value : "all";
        const severity = incFilterSeverity ? incFilterSeverity.value : "all";
        const sortBy = incSortSelect ? incSortSelect.value : "timestamp_desc";
        const search = incSearchInput ? incSearchInput.value.trim() : "";

        let query = `/api/incidents?limit=100&sort_by=${sortBy}`;
        if (status !== "all") query += `&status=${status}`;
        if (family !== "all") query += `&family=${family}`;
        if (severity !== "all") query += `&severity=${severity}`;
        if (search) query += `&search=${encodeURIComponent(search)}`;

        try {
            const resp = await fetch(query);
            if (!resp.ok) return;
            const data = await resp.json();
            const incidents = data.incidents || [];

            if (incCountBadge) incCountBadge.textContent = `${data.total} RECORDS`;
            if (navIncidentCount) navIncidentCount.textContent = data.total;

            if (incidents.length === 0) {
                incidentsTbody.innerHTML = `<tr><td colspan="9" class="table-empty">No security incidents found matching filter criteria.</td></tr>`;
                return;
            }

            incidentsTbody.innerHTML = incidents.map(inc => `
                <tr>
                    <td><strong class="text-cyan">${inc.id}</strong></td>
                    <td>${inc.timestamp}</td>
                    <td><span class="f-badge f-${inc.attack_family.toLowerCase()}">${inc.attack_family}</span></td>
                    <td><span class="sev-badge sev-${inc.severity.toLowerCase()}">${inc.severity.toUpperCase()}</span></td>
                    <td class="mono">${(inc.attack_probability * 100).toFixed(1)}%</td>
                    <td>${inc.protocol} / ${inc.service} (${inc.flag})</td>
                    <td>${inc.src_bytes} / ${inc.dst_bytes}</td>
                    <td><span class="badge-status">${inc.status}</span></td>
                    <td>
                        <button class="btn btn-primary btn-sm" onclick="openIncidentModal('${inc.id}')">Investigate</button>
                    </td>
                </tr>
            `).join("");
        } catch (e) {
            console.error("Failed to load incidents:", e);
        }
    }

    window.inspectSampleVector = function(sampleId) {
        const ev = state.simEvents.find(e => e.sampleId === sampleId);
        switchTab("connection-inspector");
        if (ev && ev.features) {
            for (const [key, value] of Object.entries(ev.features)) {
                const field = inspectorForm.elements[`f_${key}`] || inspectorForm.elements[key];
                if (field) field.value = value;
            }
            if (presetText) presetText.innerHTML = `<strong>Inspecting Ingested Flow (${sampleId}):</strong> ${ev.hint || "Extracted from Live Monitor"}`;
            if (presetBanner) presetBanner.style.display = "flex";
            setTimeout(executeInspectorInference, 100);
        }
    };

    window.openIncidentModal = async function(incidentId) {
        state.currentIncidentId = incidentId;
        try {
            const resp = await fetch(`/api/incidents/${incidentId}`);
            if (!resp.ok) throw new Error("Incident detail fetch failed");
            const data = await resp.json();
            const inc = data.incident;
            const contribs = data.feature_contributions || [];

            if (modalIncId) modalIncId.textContent = inc.id;
            if (modalAttackFamily) {
                modalAttackFamily.textContent = inc.attack_family;
                modalAttackFamily.className = `inv-val f-badge f-${inc.attack_family.toLowerCase()}`;
            }
            if (modalSeverity) {
                modalSeverity.textContent = inc.severity.toUpperCase();
                modalSeverity.className = `inv-val sev-badge sev-${inc.severity.toLowerCase()}`;
            }
            if (modalStage1Prob) modalStage1Prob.textContent = `${(inc.attack_probability * 100).toFixed(2)}%`;
            if (modalStatusBadge) modalStatusBadge.textContent = inc.status;

            if (modalPipelineDesc) {
                modalPipelineDesc.textContent = `Stage 1: P(Attack)=${(inc.attack_probability * 100).toFixed(2)}% (Threshold: ${inc.stage1_threshold.toFixed(2)}) ➔ Stage 2: ${inc.attack_family}`;
            }

            // Stage 2 Probability Breakdown
            if (modalStage2Breakdown) {
                const probs = inc.stage2_probabilities || {};
                modalStage2Breakdown.innerHTML = Object.entries(probs).map(([fam, p]) => `
                    <div class="tree-prob-bar mb-2">
                        <span class="f-badge f-${fam.toLowerCase()}">${fam}:</span>
                        <div class="t-bar-bg"><div class="t-bar-fill fill-${fam.toLowerCase()}" style="width: ${(p * 100).toFixed(1)}%;"></div></div>
                        <span class="mono">${(p * 100).toFixed(1)}%</span>
                    </div>
                `).join("");
            }

            // Model Feature Contributions
            if (modalContributionsTbody) {
                modalContributionsTbody.innerHTML = contribs.map(c => `
                    <tr>
                        <td><strong>${c.feature}</strong></td>
                        <td class="mono">${c.value}</td>
                        <td class="mono text-cyan">${(c.global_importance * 100).toFixed(2)}%</td>
                    </tr>
                `).join("");
            }

            // 40-Feature Snapshot Grid
            if (modalFeaturesSnapshot) {
                const feats = inc.features || {};
                modalFeaturesSnapshot.innerHTML = Object.entries(feats).map(([k, v]) => `
                    <div class="snap-item">
                        <span class="snap-k">${k}:</span>
                        <span class="snap-v">${v}</span>
                    </div>
                `).join("");
            }

            // Pre-populate status form
            if (modalStatusSelect) modalStatusSelect.value = inc.status;
            if (modalNotesInput) modalNotesInput.value = inc.notes || "";

            if (incidentModalOverlay) incidentModalOverlay.style.display = "flex";
        } catch (err) {
            console.error("Modal error:", err);
            alert("Could not load incident details.");
        }
    };

    if (modalCloseBtn) {
        modalCloseBtn.addEventListener("click", () => {
            if (incidentModalOverlay) incidentModalOverlay.style.display = "none";
        });
    }

    if (incidentModalOverlay) {
        incidentModalOverlay.addEventListener("click", (e) => {
            if (e.target === incidentModalOverlay) {
                incidentModalOverlay.style.display = "none";
            }
        });
    }

    if (modalStatusForm) {
        modalStatusForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!state.currentIncidentId) return;

            const newStatus = modalStatusSelect.value;
            const newNotes = modalNotesInput.value;

            try {
                const resp = await fetch(`/api/incidents/${state.currentIncidentId}`, {
                    method: "PATCH",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        status: newStatus,
                        notes: newNotes
                    })
                });

                if (!resp.ok) throw new Error("Status update failed");
                const res = await resp.json();
                if (modalStatusBadge) modalStatusBadge.textContent = newStatus;
                loadIncidents();
                loadOverviewIncidents();
                if (incidentModalOverlay) incidentModalOverlay.style.display = "none";
            } catch (err) {
                console.error("Status update error:", err);
                alert("Failed to update status.");
            }
        });
    }

    [incFilterStatus, incFilterFamily, incFilterSeverity].forEach(sel => {
        if (sel) sel.addEventListener("change", loadIncidents);
    });

    if (incSearchInput) {
        let debounceTimer = null;
        incSearchInput.addEventListener("input", () => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(loadIncidents, 300);
        });
    }

    if (incRefreshBtn) {
        incRefreshBtn.addEventListener("click", loadIncidents);
    }

    // =========================================================================
    // 4. Connection Inspector (40-Feature Deep Inference Workstation)
    // =========================================================================
    const inspectorForm = document.getElementById("inspector-form");
    const serviceDropdown = document.getElementById("f_service");
    const presetButtons = document.querySelectorAll(".preset-pill");
    const presetBanner = document.getElementById("inspector-preset-banner");
    const presetText = document.getElementById("inspector-preset-text");
    const thresholdSlider = document.getElementById("f_threshold");
    const thresholdDisplay = document.getElementById("inspector-threshold-val");
    const submitBtn = document.getElementById("inspector-submit-btn");
    const resetBtn = document.getElementById("inspector-reset-btn");

    // Decision tree elements
    const treeSampleId = document.getElementById("tree-sample-id");
    const treeStage1Prob = document.getElementById("tree-stage1-prob");
    const treeStage1Thresh = document.getElementById("tree-stage1-thresh");
    const treeStage1Decision = document.getElementById("tree-stage1-decision");
    const treeStage2Desc = document.getElementById("tree-stage2-desc");
    const treeStage2Probs = document.getElementById("tree-stage2-probs");
    const treeFinalVerdict = document.getElementById("tree-final-verdict");
    const treeFinalDesc = document.getElementById("tree-final-desc");
    const treeSeverityBadge = document.getElementById("tree-severity-badge");

    function populateInspectorServices() {
        if (!serviceDropdown) return;
        serviceDropdown.innerHTML = "";
        ALL_SERVICES.forEach(svc => {
            const opt = document.createElement("option");
            opt.value = svc;
            opt.textContent = svc;
            if (svc === "ftp_data") opt.selected = true;
            serviceDropdown.appendChild(opt);
        });
    }
    populateInspectorServices();

    if (thresholdSlider) {
        thresholdSlider.addEventListener("input", (e) => {
            const val = parseFloat(e.target.value).toFixed(2);
            if (thresholdDisplay) thresholdDisplay.textContent = val;
            if (treeStage1Thresh) treeStage1Thresh.textContent = val;
        });
    }

    presetButtons.forEach(btn => {
        btn.addEventListener("click", async () => {
            const presetId = btn.getAttribute("data-preset");
            try {
                const resp = await fetch(`/api/presets/${presetId}`);
                if (!resp.ok) throw new Error("Preset fetch failed");
                const preset = await resp.json();

                for (const [key, value] of Object.entries(preset.data)) {
                    const field = inspectorForm.elements[`f_${key}`] || inspectorForm.elements[key];
                    if (field) {
                        field.value = value;
                    }
                }

                if (presetText) presetText.innerHTML = `<strong>${preset.name}:</strong> ${preset.description}`;
                if (presetBanner) presetBanner.style.display = "flex";

                executeInspectorInference();
            } catch (err) {
                console.error("Preset error:", err);
            }
        });
    });

    if (resetBtn) {
        resetBtn.addEventListener("click", () => {
            if (inspectorForm) inspectorForm.reset();
            if (presetBanner) presetBanner.style.display = "none";
        });
    }

    if (inspectorForm) {
        inspectorForm.addEventListener("submit", (e) => {
            e.preventDefault();
            executeInspectorInference();
        });
    }

    async function executeInspectorInference() {
        const formData = new FormData(inspectorForm);
        const payload = {};
        const categorical = ["protocol_type", "service", "flag"];

        for (const [rawKey, value] of formData.entries()) {
            const key = rawKey.startsWith("f_") ? rawKey.substring(2) : rawKey;
            if (key === "threshold") continue;
            if (categorical.includes(key)) {
                payload[key] = String(value).trim();
            } else {
                payload[key] = Number(value);
            }
        }

        const threshold = parseFloat(thresholdSlider ? thresholdSlider.value : 0.40);

        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = `<span>⏳ RUNNING REAL INFERENCE PIPELINE...</span>`;
        }

        try {
            const response = await fetch(`/api/predict?threshold=${threshold}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.detail || "Inference failed");
            }

            const result = await response.json();
            renderInspectorDecisionTree(result);

            // Update telemetry
            loadAnalyticsSummary();
            loadIncidents();
        } catch (err) {
            console.error("Inspector Error:", err);
            alert(`Inference failed: ${err.message}`);
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = `<span>⚡ EXECUTE TWO-STAGE INFERENCE</span>`;
            }
        }
    }

    function renderInspectorDecisionTree(res) {
        if (treeSampleId) treeSampleId.textContent = res.sample_id;

        const prob = res.stage1.attack_probability;
        if (treeStage1Prob) treeStage1Prob.textContent = `${(prob * 100).toFixed(2)}%`;
        if (treeStage1Thresh) treeStage1Thresh.textContent = res.stage1.threshold.toFixed(2);

        if (res.stage1.is_attack) {
            if (treeStage1Decision) {
                treeStage1Decision.textContent = `ATTACK DETECTED (P ≥ ${res.stage1.threshold.toFixed(2)})`;
                treeStage1Decision.style.color = "var(--c-dos)";
                treeStage1Decision.style.borderColor = "rgba(239, 68, 68, 0.4)";
            }
            if (treeStage2Desc) {
                treeStage2Desc.textContent = `Stage 2 Multiclass Random Forest executed on 120 features:`;
            }

            if (res.stage2 && res.stage2.probabilities) {
                if (treeStage2Probs) treeStage2Probs.style.display = "flex";
                const probs = res.stage2.probabilities;
                ["DoS", "Probe", "R2L", "U2R"].forEach(f => {
                    const p = (probs[f] || 0.0) * 100;
                    const valEl = document.getElementById(`t-val-${f.toLowerCase()}`);
                    const barEl = document.getElementById(`t-bar-${f.toLowerCase()}`);
                    if (valEl) valEl.textContent = `${p.toFixed(1)}%`;
                    if (barEl) barEl.style.width = `${p}%`;
                });
            }

            if (treeFinalVerdict) {
                treeFinalVerdict.textContent = `ATTACK CLASSIFIED: ${res.final_prediction}`;
                treeFinalVerdict.style.color = "var(--c-dos)";
            }
            if (treeFinalDesc) {
                treeFinalDesc.textContent = (res.stage2 && res.stage2.description) || `Classified into ${res.final_prediction} attack family.`;
            }
            if (treeSeverityBadge) {
                treeSeverityBadge.className = `verdict-severity-badge sev-${res.alert_severity.toLowerCase()}`;
                treeSeverityBadge.textContent = `SEVERITY: ${res.alert_severity.toUpperCase()} // ${res.final_prediction}`;
            }
        } else {
            if (treeStage1Decision) {
                treeStage1Decision.textContent = `LEGITIMATE TRAFFIC (P < ${res.stage1.threshold.toFixed(2)})`;
                treeStage1Decision.style.color = "var(--c-normal)";
                treeStage1Decision.style.borderColor = "rgba(16, 185, 129, 0.4)";
            }
            if (treeStage2Desc) {
                treeStage2Desc.textContent = "Stage 2 bypassed (Traffic is verified Normal).";
            }
            if (treeStage2Probs) treeStage2Probs.style.display = "none";

            if (treeFinalVerdict) {
                treeFinalVerdict.textContent = "VERDICT: NORMAL TRAFFIC";
                treeFinalVerdict.style.color = "var(--c-normal)";
            }
            if (treeFinalDesc) {
                treeFinalDesc.textContent = "Connection characteristics match normal baseline activity.";
            }
            if (treeSeverityBadge) {
                treeSeverityBadge.className = "verdict-severity-badge sev-normal";
                treeSeverityBadge.textContent = "SEVERITY: SAFE / NORMAL";
            }
        }
    }

    // =========================================================================
    // 5. Demonstration Mode (8 Guided SOC Workflow Steps)
    // =========================================================================
    const DEMO_STEPS = [
        {
            num: "STEP 1 / 8",
            title: "Normal Operations Baseline",
            desc: "The demonstration begins by generating legitimate enterprise web, mail, and DNS traffic vectors. Every connection is evaluated through the real Two-Stage Random Forest models.",
            actionType: "preset",
            actionParam: "normal",
            promptText: "Click 'Execute Step' to simulate legitimate enterprise FTP data traffic."
        },
        {
            num: "STEP 2 / 8",
            title: "Denial of Service (DoS) Neptune SYN Flood",
            desc: "High-volume SYN flood attack exhausting server connection queues with S0 flags and 0 destination bytes.",
            actionType: "preset",
            actionParam: "dos",
            promptText: "Click 'Execute Step' to ingest a high-intensity Neptune SYN flood packet."
        },
        {
            num: "STEP 3 / 8",
            title: "Surveillance & Port Reconnaissance (IPSweep)",
            desc: "Automated network host discovery and port scan probing multiple destination hosts with ICMP echo requests.",
            actionType: "preset",
            actionParam: "probe",
            promptText: "Click 'Execute Step' to evaluate an ICMP ping sweep reconnaissance vector."
        },
        {
            num: "STEP 4 / 8",
            title: "Remote-to-Local Compromise (Warezclient)",
            desc: "Unauthorized external intruder attempting unauthorized file transfers and credential exploitation.",
            actionType: "preset",
            actionParam: "r2l",
            promptText: "Click 'Execute Step' to execute inference on an R2L pirate warez download attempt."
        },
        {
            num: "STEP 5 / 8",
            title: "User-to-Root Privilege Escalation (Rootkit)",
            desc: "Local unauthorized privilege escalation exploiting system calls to obtain root shell credentials.",
            actionType: "preset",
            actionParam: "u2r",
            promptText: "Click 'Execute Step' to score a local root shell escalation vector."
        },
        {
            num: "STEP 6 / 8",
            title: "Decision Threshold Sensitivity Tuning",
            desc: "Demonstrating how tuning the Stage 1 threshold (from standard τ = 0.40 to custom sensitivity values) allows SOC analysts to balance false positives vs. high-security strictness.",
            actionType: "threshold_demo",
            actionParam: null,
            promptText: "Click 'Execute Step' to run comparative evaluation across τ = 0.20, τ = 0.40, and τ = 0.70."
        },
        {
            num: "STEP 7 / 8",
            title: "Real-Time Explainability & Feature Attribution",
            desc: "Extracts real feature contribution scores for the active attack vector, identifying exactly which network features triggered the detection.",
            actionType: "explain",
            actionParam: "dos",
            promptText: "Click 'Execute Step' to compute real-time feature attributions."
        },
        {
            num: "STEP 8 / 8",
            title: "External Generalization Benchmark Summary",
            desc: "Concludes the demonstration with an overview of academic benchmark evaluations on NSL-KDD (Internal 99.93% vs External KDDTest+ 77.20% domain shift).",
            actionType: "eval_summary",
            actionParam: null,
            promptText: "Click 'Execute Step' to view verified research validation metrics."
        }
    ];

    const demoProgressFill = document.getElementById("demo-progress-fill");
    const demoStepNum = document.getElementById("demo-step-num");
    const demoStepTitle = document.getElementById("demo-step-title");
    const demoStepDesc = document.getElementById("demo-step-desc");
    const demoResultBox = document.getElementById("demo-result-box");
    const demoPrevBtn = document.getElementById("demo-prev-btn");
    const demoExecBtn = document.getElementById("demo-exec-btn");
    const demoNextBtn = document.getElementById("demo-next-btn");
    const demoResetBtn = document.getElementById("demo-reset-btn");

    function renderDemoStep() {
        const step = DEMO_STEPS[state.currentDemoStep];
        const pct = ((state.currentDemoStep + 1) / DEMO_STEPS.length) * 100;

        if (demoProgressFill) demoProgressFill.style.width = `${pct}%`;
        if (demoStepNum) demoStepNum.textContent = step.num;
        if (demoStepTitle) demoStepTitle.textContent = step.title;
        if (demoStepDesc) demoStepDesc.textContent = step.desc;
        if (demoResultBox) demoResultBox.innerHTML = `<div class="mono text-dim">${step.promptText}</div>`;

        if (demoPrevBtn) demoPrevBtn.disabled = state.currentDemoStep === 0;
        if (demoNextBtn) demoNextBtn.disabled = state.currentDemoStep === DEMO_STEPS.length - 1;
    }

    if (demoPrevBtn) {
        demoPrevBtn.addEventListener("click", () => {
            if (state.currentDemoStep > 0) {
                state.currentDemoStep--;
                renderDemoStep();
            }
        });
    }

    if (demoNextBtn) {
        demoNextBtn.addEventListener("click", () => {
            if (state.currentDemoStep < DEMO_STEPS.length - 1) {
                state.currentDemoStep++;
                renderDemoStep();
            }
        });
    }

    if (demoResetBtn) {
        demoResetBtn.addEventListener("click", () => {
            state.currentDemoStep = 0;
            renderDemoStep();
        });
    }

    if (demoExecBtn) {
        demoExecBtn.addEventListener("click", async () => {
            const step = DEMO_STEPS[state.currentDemoStep];
            if (demoResultBox) demoResultBox.innerHTML = `<div class="mono text-cyan">⏳ Executing step through model pipeline...</div>`;

            try {
                if (step.actionType === "preset") {
                    const pResp = await fetch(`/api/presets/${step.actionParam}`);
                    const preset = await pResp.json();
                    const iResp = await fetch("/api/predict", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(preset.data)
                    });
                    const res = await iResp.json();

                    demoResultBox.innerHTML = `
                        <div class="demo-result-card">
                            <div class="d-flex justify-between mb-2">
                                <span class="mono text-cyan">SAMPLE: ${res.sample_id}</span>
                                <span class="sev-badge sev-${res.alert_severity.toLowerCase()}">${res.alert_severity.toUpperCase()}</span>
                            </div>
                            <div style="font-size: 1.1rem; font-weight: 700; color: ${res.is_attack ? 'var(--c-dos)' : 'var(--c-normal)'};" class="mb-2">
                                ${res.final_prediction === "Normal" ? "VERDICT: NORMAL TRAFFIC" : `ATTACK CLASSIFIED: ${res.final_prediction}`}
                            </div>
                            <div class="mono text-dim text-xs">
                                Stage 1: P(Attack) = ${(res.stage1.attack_probability * 100).toFixed(2)}% | Threshold: ${res.stage1.threshold.toFixed(2)} | Latency: ${res.latency_ms.toFixed(2)}ms
                            </div>
                        </div>
                    `;
                } else if (step.actionType === "threshold_demo") {
                    const pResp = await fetch("/api/presets/dos");
                    const preset = await pResp.json();
                    const [rLow, rStd, rHigh] = await Promise.all([
                        fetch("/api/predict?threshold=0.20", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(preset.data) }).then(r => r.json()),
                        fetch("/api/predict?threshold=0.40", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(preset.data) }).then(r => r.json()),
                        fetch("/api/predict?threshold=0.70", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(preset.data) }).then(r => r.json())
                    ]);

                    demoResultBox.innerHTML = `
                        <div class="metrics-pill-row mb-2">
                            <div class="m-pill">
                                <span class="m-label">τ = 0.20 (Strict)</span>
                                <span class="m-val mono text-danger">${rLow.stage1.decision}</span>
                            </div>
                            <div class="m-pill">
                                <span class="m-label">τ = 0.40 (Calibrated Default)</span>
                                <span class="m-val mono text-danger">${rStd.stage1.decision}</span>
                            </div>
                            <div class="m-pill">
                                <span class="m-label">τ = 0.70 (Permissive)</span>
                                <span class="m-val mono ${rHigh.stage1.decision === 'Attack' ? 'text-danger' : 'text-normal'}">${rHigh.stage1.decision}</span>
                            </div>
                        </div>
                        <p class="text-dim text-xs">Calibrated threshold τ = 0.40 achieves 99.91% attack recall while minimizing false alarm rates on legitimate traffic.</p>
                    `;
                } else if (step.actionType === "explain") {
                    const pResp = await fetch("/api/presets/dos");
                    const preset = await pResp.json();
                    const eResp = await fetch("/api/explain", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(preset.data)
                    });
                    const eData = await eResp.json();

                    demoResultBox.innerHTML = `
                        <div class="text-xs mb-2"><strong>Top Contributing Features for DoS (Neptune) Vector:</strong></div>
                        <div class="soc-table-wrapper">
                            <table class="soc-table">
                                <thead><tr><th>FEATURE</th><th>VALUE</th><th>IMPORTANCE</th></tr></thead>
                                <tbody>
                                    ${eData.contributions.slice(0, 4).map(c => `
                                        <tr>
                                            <td><strong>${c.feature}</strong></td>
                                            <td class="mono">${c.value}</td>
                                            <td class="mono text-cyan">${(c.global_importance * 100).toFixed(2)}%</td>
                                        </tr>
                                    `).join("")}
                                </tbody>
                            </table>
                        </div>
                    `;
                } else if (step.actionType === "eval_summary") {
                    const evalResp = await fetch("/api/evaluation");
                    const evalData = await evalResp.json();
                    demoResultBox.innerHTML = `
                        <div class="metrics-pill-row">
                            <div class="m-pill">
                                <span class="m-label">Internal Validation Acc</span>
                                <span class="m-val mono text-normal">${(evalData.stage1_internal.accuracy * 100).toFixed(2)}%</span>
                            </div>
                            <div class="m-pill">
                                <span class="m-label">Internal Attack Recall</span>
                                <span class="m-val mono text-normal">${(evalData.stage1_internal.attack_recall * 100).toFixed(2)}%</span>
                            </div>
                            <div class="m-pill">
                                <span class="m-label">KDDTest+ Generalization</span>
                                <span class="m-val mono text-cyan">${(evalData.external_validation.overall_accuracy * 100).toFixed(2)}%</span>
                            </div>
                        </div>
                    `;
                }
            } catch (err) {
                demoResultBox.innerHTML = `<div class="mono text-danger">Execution error: ${err.message}</div>`;
            }
        });
    }

    // =========================================================================
    // 6. ML Explainability & Feature Importance Center
    // =========================================================================
    const fiContainer = document.getElementById("feature-importance-bars-container");
    const fiBtnAgg = document.getElementById("fi-view-agg-btn");
    const fiBtnTrans = document.getElementById("fi-view-trans-btn");
    const fiBtnGroup = document.getElementById("fi-view-group-btn");

    async function loadFeatureImportance() {
        if (!fiContainer) return;
        if (!state.featureImportanceData) {
            try {
                const resp = await fetch("/api/feature-importance");
                if (!resp.ok) return;
                state.featureImportanceData = await resp.json();
            } catch (e) {
                console.error("Failed to load feature importance:", e);
                return;
            }
        }
        renderFeatureImportance();
    }

    function renderFeatureImportance() {
        if (!fiContainer || !state.featureImportanceData) return;
        const data = state.featureImportanceData;

        if (state.fiCurrentView === "agg") {
            const list = data.stage1_all_aggregated || [];
            const maxImp = list.length > 0 ? list[0].importance : 1.0;
            fiContainer.innerHTML = list.map(item => {
                const pct = (item.importance / maxImp) * 100;
                return `
                    <div class="fi-bar-row">
                        <span class="fi-bar-name" title="${item.feature}">${item.feature}</span>
                        <div class="fi-bar-track"><div class="fi-bar-fill" style="width: ${pct}%;"></div></div>
                        <span class="fi-bar-score">${(item.importance * 100).toFixed(2)}%</span>
                    </div>
                `;
            }).join("");
        } else if (state.fiCurrentView === "trans") {
            const list = data.stage1_top20_transformed || [];
            const maxImp = list.length > 0 ? list[0].importance : 1.0;
            fiContainer.innerHTML = list.map(item => {
                const pct = (item.importance / maxImp) * 100;
                return `
                    <div class="fi-bar-row">
                        <span class="fi-bar-name" title="${item.feature}">${item.feature}</span>
                        <div class="fi-bar-track"><div class="fi-bar-fill bg-cyan" style="width: ${pct}%;"></div></div>
                        <span class="fi-bar-score">${(item.importance * 100).toFixed(2)}%</span>
                    </div>
                `;
            }).join("");
        } else if (state.fiCurrentView === "group") {
            const list = data.stage1_grouped || [];
            const maxImp = list.length > 0 ? list[0].importance : 1.0;
            fiContainer.innerHTML = list.map(item => {
                const pct = (item.importance / maxImp) * 100;
                return `
                    <div class="fi-bar-row">
                        <span class="fi-bar-name" style="width: 220px;" title="${item.group}">${item.group} (${item.feature_count})</span>
                        <div class="fi-bar-track"><div class="fi-bar-fill bg-blue" style="width: ${pct}%;"></div></div>
                        <span class="fi-bar-score">${(item.importance * 100).toFixed(1)}%</span>
                    </div>
                `;
            }).join("");
        }
    }

    if (fiBtnAgg) {
        fiBtnAgg.addEventListener("click", () => {
            state.fiCurrentView = "agg";
            fiBtnAgg.classList.add("active");
            if (fiBtnTrans) fiBtnTrans.classList.remove("active");
            if (fiBtnGroup) fiBtnGroup.classList.remove("active");
            renderFeatureImportance();
        });
    }

    if (fiBtnTrans) {
        fiBtnTrans.addEventListener("click", () => {
            state.fiCurrentView = "trans";
            fiBtnTrans.classList.add("active");
            if (fiBtnAgg) fiBtnAgg.classList.remove("active");
            if (fiBtnGroup) fiBtnGroup.classList.remove("active");
            renderFeatureImportance();
        });
    }

    if (fiBtnGroup) {
        fiBtnGroup.addEventListener("click", () => {
            state.fiCurrentView = "group";
            fiBtnGroup.classList.add("active");
            if (fiBtnAgg) fiBtnAgg.classList.remove("active");
            if (fiBtnTrans) fiBtnTrans.classList.remove("active");
            renderFeatureImportance();
        });
    }

    // =========================================================================
    // 7. System Health Modal
    // =========================================================================
    const topbarHealthBtn = document.getElementById("topbar-health-btn");
    const healthModalOverlay = document.getElementById("health-modal-overlay");
    const healthCloseBtn = document.getElementById("health-close-btn");
    const healthModalBody = document.getElementById("health-modal-body");

    if (topbarHealthBtn) {
        topbarHealthBtn.addEventListener("click", async () => {
            try {
                const resp = await fetch("/api/health");
                if (resp.ok && healthModalBody) {
                    const h = await resp.json();
                    healthModalBody.innerHTML = `
                        <div class="spec-list">
                            <div class="spec-item">
                                <span class="spec-key">API Status</span>
                                <span class="spec-val text-normal">● ${h.status.toUpperCase()} (${h.system})</span>
                            </div>
                            <div class="spec-item">
                                <span class="spec-key">Uptime</span>
                                <span class="spec-val mono">${h.uptime_seconds} seconds</span>
                            </div>
                            <div class="spec-item">
                                <span class="spec-key">Preprocessor</span>
                                <span class="spec-val">${h.models.preprocessor}</span>
                            </div>
                            <div class="spec-item">
                                <span class="spec-key">Stage 1 Model</span>
                                <span class="spec-val">${h.models.stage1_model} (τ = ${h.models.stage1_threshold.toFixed(2)})</span>
                            </div>
                            <div class="spec-item">
                                <span class="spec-key">Stage 2 Model</span>
                                <span class="spec-val">${h.models.stage2_model}</span>
                            </div>
                            <div class="spec-item">
                                <span class="spec-key">Telemetry</span>
                                <span class="spec-val mono">${h.telemetry.total_flows_analyzed} flows analyzed | ${h.telemetry.avg_latency_ms}ms avg latency</span>
                            </div>
                        </div>
                    `;
                }
            } catch (e) {}

            if (healthModalOverlay) healthModalOverlay.style.display = "flex";
        });
    }

    if (healthCloseBtn) {
        healthCloseBtn.addEventListener("click", () => {
            if (healthModalOverlay) healthModalOverlay.style.display = "none";
        });
    }

    if (healthModalOverlay) {
        healthModalOverlay.addEventListener("click", (e) => {
            if (e.target === healthModalOverlay) {
                healthModalOverlay.style.display = "none";
            }
        });
    }

    // =========================================================================
    // Initial Load Sequence
    // =========================================================================
    renderDemoStep();
    switchTab("command-center");
});
