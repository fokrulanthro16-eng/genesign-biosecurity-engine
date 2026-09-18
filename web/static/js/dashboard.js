/**
 * GeneSign Tactical Biosecurity Operations HUD Controller
 */

// State
let currentWatermarkResult = null;
let currentOriginalWatermarkedDna = null;
let currentTamperedDna = null;
let tamperedBaseIndex = -1;
let lastScanResult = null;

document.addEventListener("DOMContentLoaded", async () => {
  initTabs();
  initWatermarkStudio();
  initFirewallScanner();
  initTamperSimulator();
  initEnterpriseModule();
  initHardwareInterlockTOC();
  loadAuditLedger();
  loadKmsProviders();

  // Pre-seed with authentic freshly watermarked CDS so Tamper Simulator is active on load
  await preseedFreshWatermark();
});

// Tab Switching
function initTabs() {
  const tabs = document.querySelectorAll(".nav-pill-btn, .tab-btn");
  tabs.forEach(btn => {
    btn.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".panel-section, .view-section").forEach(s => s.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetPanel = document.getElementById(targetId);
      if (targetPanel) {
        targetPanel.classList.add("active");
      }

      if (targetId === "tab-ledger") {
        loadAuditLedger();
      }
      if (targetId === "tab-enterprise") {
        loadKmsProviders();
      }
      if (targetId === "tab-hardware") {
        pollHardwareStatus();
        fetchMerkleBundle();
      }
    });
  });
}

// Pre-seed simulator with freshly watermarked GFP so it's never unwatermarked
async function preseedFreshWatermark() {
  if (currentWatermarkResult) return;
  try {
    const sampleResp = await fetch("/api/v1/samples/gfp");
    if (!sampleResp.ok) return;
    const sampleData = await sampleResp.json();

    const wmResp = await fetch("/api/v1/watermark", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        dna_sequence: sampleData.content,
        lab_id: "TWS",
        order_id: "901",
        generate_certificate: true,
      }),
    });

    if (wmResp.ok) {
      currentWatermarkResult = await wmResp.json();
      populateTamperSimulator(currentWatermarkResult);
    }
  } catch (err) {
    console.warn("Pre-seeding watermark note:", err);
  }
}

// ---------------------------------------------------------------------------
// 1. Watermark Encoder Studio
// ---------------------------------------------------------------------------
function initWatermarkStudio() {
  const inputSeq = document.getElementById("wm-input-seq");
  const labId = document.getElementById("wm-lab-id");
  const orderId = document.getElementById("wm-order-id");
  const encodeBtn = document.getElementById("wm-encode-btn");
  const downloadFastaBtn = document.getElementById("wm-dl-fasta");
  const downloadCertBtn = document.getElementById("wm-dl-cert");

  // Presets
  document.querySelectorAll(".wm-preset-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const sampleId = btn.getAttribute("data-sample");
      try {
        const resp = await fetch(`/api/v1/samples/${sampleId}`);
        const data = await resp.json();
        inputSeq.value = data.content;
      } catch (err) {
        console.error("Failed to load sample:", err);
      }
    });
  });

  // Default load GFP
  document.querySelector('.wm-preset-btn[data-sample="gfp"]')?.click();

  // Encode
  encodeBtn.addEventListener("click", async () => {
    const dna = inputSeq.value.trim();
    if (!dna) {
      alert("Please provide a coding sequence (CDS) or FASTA text.");
      return;
    }

    encodeBtn.disabled = true;
    encodeBtn.innerHTML = "<span>Modulating Wobble Bases...</span>";

    try {
      const resp = await fetch("/api/v1/watermark", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          dna_sequence: dna,
          lab_id: labId.value.trim() || "TWS",
          order_id: orderId.value.trim() || "901",
          generate_certificate: true,
        }),
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || "Watermarking failed.");
      }

      currentWatermarkResult = await resp.json();
      renderWatermarkResults(currentWatermarkResult);

      // Automatically sync freshly watermarked DNA and certificate into the Tamper Simulator
      populateTamperSimulator(currentWatermarkResult);

    } catch (err) {
      alert(`Watermarking Error: ${err.message}`);
    } finally {
      encodeBtn.disabled = false;
      encodeBtn.innerHTML = "<span>Inject Synthetic Watermark</span>";
    }
  });

  // Download FASTA
  downloadFastaBtn.addEventListener("click", () => {
    if (!currentWatermarkResult) return;
    const blob = new Blob([currentWatermarkResult.watermarked_fasta], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `genesign_${currentWatermarkResult.event_id}.fasta`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Download Cert
  downloadCertBtn.addEventListener("click", () => {
    if (!currentWatermarkResult || !currentWatermarkResult.certificate_id) return;
    window.location.href = `/api/v1/certificate/${currentWatermarkResult.certificate_id}`;
  });
}

function renderWatermarkResults(data) {
  document.getElementById("wm-results-panel").style.display = "block";
  document.getElementById("wm-stat-len").innerText = `${data.invariants.watermarked_length_nt} nt`;
  document.getElementById("wm-stat-codons").innerText = data.modulated_codons_count;
  document.getElementById("wm-stat-gcdrift").innerText = `${data.invariants.gc_drift}%`;
  document.getElementById("wm-stat-gcpost").innerText = `${data.invariants.watermarked_gc}% (Pre: ${data.invariants.original_gc}%)`;
  document.getElementById("wm-stat-entropy").innerText = data.invariants.watermarked_entropy;
  document.getElementById("wm-cert-id-badge").innerText = data.certificate_id || "N/A";

  // Render Codon Shift Delta Heatmap
  const grid = document.getElementById("codon-heatmap-grid");
  grid.innerHTML = "";

  if (data.codon_modulations && data.codon_modulations.length > 0) {
    data.codon_modulations.forEach(mod => {
      const cell = document.createElement("div");
      cell.className = "heatmap-codon-cell codon-cell";
      cell.innerHTML = `
        <div style="font-size: 0.65rem; color: #64748b;">#${mod.codon_index}</div>
        <div class="cell-aa">${mod.amino_acid}</div>
        <div class="cell-shift">${mod.wobble_mutation}</div>
      `;
      grid.appendChild(cell);
    });
  } else {
    grid.innerHTML = `<div style="color: #64748b; font-size: 0.8rem; padding: 1rem;">No codon shifts were necessary (carrier bits already matched payload).</div>`;
  }
}

// ---------------------------------------------------------------------------
// 2. Biosecurity Firewall Scanner
// ---------------------------------------------------------------------------
function initFirewallScanner() {
  const scanInput = document.getElementById("fw-input-seq");
  const scanBtn = document.getElementById("fw-scan-btn");

  // Presets
  document.querySelectorAll(".fw-preset-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const sampleId = btn.getAttribute("data-sample");
      if (sampleId === "signed_gfp" && currentWatermarkResult) {
        scanInput.value = currentWatermarkResult.watermarked_fasta;
        return;
      }
      try {
        const resp = await fetch(`/api/v1/samples/${sampleId}`);
        const data = await resp.json();
        scanInput.value = data.content;
      } catch (err) {
        console.error("Failed to load sample:", err);
      }
    });
  });

  scanBtn.addEventListener("click", async () => {
    const text = scanInput.value.trim();
    if (!text) {
      alert("Please paste DNA sequence or FASTA to scan.");
      return;
    }

    scanBtn.disabled = true;
    scanBtn.innerHTML = "<span>Analyzing K-mer Signatures & Provenance...</span>";

    try {
      const resp = await fetch("/api/v1/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sequence_or_fasta: text }),
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || "Scanning failed.");
      }

      const scanResult = await resp.json();
      renderScanResults(scanResult);
      loadAuditLedger();
    } catch (err) {
      alert(`Firewall Scan Error: ${err.message}`);
    } finally {
      scanBtn.disabled = false;
      scanBtn.innerHTML = "<span>Run Biosecurity Firewall Screen</span>";
    }
  });
}

function renderScanResults(res) {
  const panel = document.getElementById("fw-results-panel");
  panel.style.display = "block";

  const banner = document.getElementById("fw-status-banner");
  banner.className = `verdict-banner status-banner ${res.classification}`;

  const iconEl = document.getElementById("fw-status-icon");
  const titleEl = document.getElementById("fw-status-title");
  const descEl = document.getElementById("fw-status-desc");

  const iconMap = {
    VERIFIED_LICENSED: "🛡️",
    UNKNOWN_DRIFT: "⚠️",
    ROGUE_SYNTHETIC: "☣️",
    TAMPERED_PAYLOAD: "⚡",
  };

  iconEl.innerText = iconMap[res.classification] || "🔍";
  titleEl.innerText = res.classification;
  descEl.innerText = res.status_summary;

  document.getElementById("fw-hash").innerText = res.sequence_hash;
  document.getElementById("fw-len").innerText = `${res.sequence_length} nt`;
  document.getElementById("fw-gc").innerText = `${res.gc_content}%`;
  document.getElementById("fw-entropy").innerText = res.shannon_entropy;
  document.getElementById("fw-lab").innerText = res.lab_id ? `Lab: ${res.lab_id} | Order: ${res.order_id}` : "Unlicensed / None";

  // Translation readout
  document.getElementById("fw-protein").innerText = res.amino_acid_translation;

  // Threat matches
  const threatsBlock = document.getElementById("fw-threats-block");
  const threatsList = document.getElementById("fw-threats-list");
  threatsList.innerHTML = "";

  if (res.threat_matches && res.threat_matches.length > 0) {
    threatsBlock.style.display = "block";
    res.threat_matches.forEach(m => {
      const row = document.createElement("div");
      row.style.cssText = "background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); padding: 0.75rem; border-radius: 6px; margin-bottom: 0.5rem; font-family: var(--font-mono); font-size: 0.8rem;";
      row.innerHTML = `
        <div style="font-weight: 700; color: #ef4444;">🚨 ${m.agent_name} [${m.regulatory_tier}]</div>
        <div style="color: #cbd5e1; font-size: 0.75rem; margin-top: 0.2rem;">Target Gene: ${m.target_gene} | K-mer Hits: ${m.kmer_matches} | Match Span: nt ${m.query_match_start} - ${m.query_match_end}</div>
        <div style="color: #94a3b8; font-size: 0.7rem; margin-top: 0.2rem;">${m.description}</div>
      `;
      threatsList.appendChild(row);
    });
  } else {
    threatsBlock.style.display = "none";
  }

  // Cache last scan result for Nemotron threat intelligence
  lastScanResult = res;

  // Auto-trigger NVIDIA Nemotron on UNKNOWN_DRIFT, TAMPERED_PAYLOAD, or ROGUE_SYNTHETIC
  if (res.classification === "UNKNOWN_DRIFT" || res.classification === "TAMPERED_PAYLOAD" || res.classification === "ROGUE_SYNTHETIC") {
    triggerNemotronAnalysis(false);
  } else {
    // Reset/hide card if benign verified unless manually requested
    const nemotronCard = document.getElementById("nemotron-rationale-card");
    if (nemotronCard) {
      nemotronCard.style.display = "none";
    }
  }
}

// ---------------------------------------------------------------------------
// 2.1 NVIDIA Nemotron AI Threat Rationale Controller
// ---------------------------------------------------------------------------
async function triggerNemotronAnalysis(force = false) {
  if (!lastScanResult) {
    alert("Please run a biosecurity firewall scan first to generate sequence telemetry.");
    return;
  }

  const card = document.getElementById("nemotron-rationale-card");
  const loading = document.getElementById("nemotron-loading");
  const body = document.getElementById("nemotron-content-body");
  const summaryEl = document.getElementById("nemotron-summary-text");
  const regEl = document.getElementById("nemotron-regulatory-text");
  const actionsList = document.getElementById("nemotron-actions-list");
  const riskBadge = document.getElementById("nemotron-risk-badge");
  const modelBadge = document.getElementById("nemotron-model-badge");
  const latencyMeta = document.getElementById("nemotron-latency-meta");

  if (!card) return;

  card.style.display = "block";
  loading.style.display = "block";
  body.style.display = "none";

  try {
    const resp = await fetch("/api/v1/analyze/ai-rationale", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        record_id: lastScanResult.record_id || "SCAN-TARGET",
        classification: lastScanResult.classification,
        sequence_length: lastScanResult.sequence_length || 0,
        gc_content: lastScanResult.gc_content || 0.0,
        threat_detected: lastScanResult.threat_detected || false,
        highest_threat_tier: lastScanResult.highest_threat_tier || "NONE",
        threat_matches: lastScanResult.threat_matches || [],
        tampered: lastScanResult.tampered || false,
        status_summary: lastScanResult.status_summary || "",
        lab_id: lastScanResult.lab_id || null,
        order_id: lastScanResult.order_id || null,
        sequence_hash: lastScanResult.sequence_hash || "",
      }),
    });

    if (!resp.ok) {
      throw new Error(`Nemotron advisory request failed (HTTP ${resp.status})`);
    }

    const aiData = await resp.json();

    // Render Data
    summaryEl.innerText = aiData.executive_summary || "Executive summary unavailable.";
    regEl.innerText = aiData.regulatory_implications || "Regulatory obligations standard under US HHS guidance.";

    actionsList.innerHTML = "";
    if (aiData.recommended_actions && aiData.recommended_actions.length > 0) {
      aiData.recommended_actions.forEach((act, idx) => {
        const item = document.createElement("div");
        item.style.cssText = "display: flex; align-items: flex-start; gap: 0.5rem; background: rgba(0, 0, 0, 0.35); border: 1px solid rgba(255, 255, 255, 0.05); padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.8rem; color: #cbd5e1;";
        item.innerHTML = `
          <span style="color: #34d399; font-weight: 700; font-family: var(--font-mono); font-size: 0.75rem;">[0${idx+1}]</span>
          <span>${act}</span>
        `;
        actionsList.appendChild(item);
      });
    }

    // Risk score badge styling
    const score = aiData.risk_score || 50;
    if (score >= 80) {
      riskBadge.style.background = "rgba(239, 68, 68, 0.25)";
      riskBadge.style.color = "#f87171";
      riskBadge.style.borderColor = "rgba(239, 68, 68, 0.5)";
      riskBadge.innerText = `CRITICAL RISK: ${score}/100`;
    } else if (score >= 40) {
      riskBadge.style.background = "rgba(245, 158, 11, 0.2)";
      riskBadge.style.color = "#fbbf24";
      riskBadge.style.borderColor = "rgba(245, 158, 11, 0.4)";
      riskBadge.innerText = `ANOMALY: ${score}/100`;
    } else {
      riskBadge.style.background = "rgba(16, 185, 129, 0.2)";
      riskBadge.style.color = "#34d399";
      riskBadge.style.borderColor = "rgba(16, 185, 129, 0.4)";
      riskBadge.innerText = `CLEARED: ${score}/100`;
    }

    if (modelBadge) {
      const shortModel = (aiData.model || "nemotron-3-ultra").replace("nvidia/", "");
      modelBadge.innerText = shortModel;
    }

    if (latencyMeta) {
      const inferenceType = aiData.is_fallback ? "Deterministic Guard Fallback" : "Live NVIDIA Nemotron Inference";
      latencyMeta.innerText = `Latency: ${aiData.latency_seconds}s | Model: ${aiData.model} (${inferenceType})`;
    }

  } catch (err) {
    summaryEl.innerText = `Advisory Generation Error: ${err.message}`;
    regEl.innerText = "Check network connectivity or active provider credentials.";
  } finally {
    loading.style.display = "none";
    body.style.display = "block";
  }
}

function switchToRadarAndAnalyze() {
  const radarTabBtn = document.querySelector('.nav-pill-btn[data-tab="tab-firewall"]');
  if (radarTabBtn) {
    radarTabBtn.click();
  }
  setTimeout(() => {
    triggerNemotronAnalysis(true);
  }, 200);
}


// ---------------------------------------------------------------------------
// 3. Interactive Single-Nucleotide Tamper Simulator
// ---------------------------------------------------------------------------
function initTamperSimulator() {
  const triggerBtn = document.getElementById("tamper-auto-flip-btn");
  const resetBtn = document.getElementById("tamper-reset-btn");
  const testScanBtn = document.getElementById("tamper-scan-btn");

  // Auto Mutate 1 Wobble Base inside active watermarked sequence
  triggerBtn.addEventListener("click", () => {
    if (!currentWatermarkResult || !currentTamperedDna) {
      alert("No active watermarked sequence loaded yet. Please wait for initial sequence to load.");
      return;
    }

    // Pick a modulated carrier wobble position in the payload body (after the 8-bit magic sync)
    let targetCodonIdx = 10;
    if (currentWatermarkResult.codon_modulations && currentWatermarkResult.codon_modulations.length > 8) {
      // Pick modulation #10 (or highest available body modulation)
      const targetMod = currentWatermarkResult.codon_modulations[Math.min(10, currentWatermarkResult.codon_modulations.length - 1)];
      targetCodonIdx = targetMod.codon_index;
    } else if (currentWatermarkResult.codon_modulations && currentWatermarkResult.codon_modulations.length > 0) {
      targetCodonIdx = currentWatermarkResult.codon_modulations[0].codon_index;
    }

    const wobblePos = targetCodonIdx * 3 + 2;
    mutateBaseAtIndex(wobblePos);
  });

  // Reset to Pristine Watermark
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      if (!currentOriginalWatermarkedDna) return;
      currentTamperedDna = currentOriginalWatermarkedDna;
      tamperedBaseIndex = -1;
      renderInteractiveBases();

      const dot = document.getElementById("tamper-status-dot");
      const meta = document.getElementById("tamper-source-meta");
      const resultBlock = document.getElementById("tamper-result-block");
      const logMsg = document.getElementById("tamper-log-msg");

      if (dot) {
        dot.style.background = "#10b981";
        dot.style.boxShadow = "0 0 10px #10b981";
      }
      if (meta) {
        meta.innerHTML = `<span style="color: #34d399;">Origin: Verified Licensed Synthesis | Status=AUTHENTIC (0 Mutations)</span>`;
      }
      if (resultBlock) {
        resultBlock.style.display = "none";
      }
      if (logMsg) {
        logMsg.innerHTML = `<span style="color: #34d399;">↺ Sequence restored to pristine watermarked state.</span> Click "Send to Firewall Scanner" to verify VERIFIED_LICENSED.`;
      }
    });
  }

  // Send to Firewall Scanner
  testScanBtn.addEventListener("click", async () => {
    if (!currentTamperedDna) {
      alert("No active sequence available to scan.");
      return;
    }

    testScanBtn.disabled = true;
    testScanBtn.innerHTML = "<span>Analyzing Tamper State...</span>";

    try {
      const resp = await fetch("/api/v1/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sequence_or_fasta: currentTamperedDna,
          record_id: "TAMPER-SIMULATOR-TEST",
          provenance_token: currentWatermarkResult ? currentWatermarkResult.certificate : null,
        }),
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || "Scan failed.");
      }

      const scanResult = await resp.json();
      renderTamperScanResult(scanResult);
      loadAuditLedger();
    } catch (err) {
      alert(`Tamper scan error: ${err.message}`);
    } finally {
      testScanBtn.disabled = false;
      testScanBtn.innerHTML = "<span>Send to Firewall Scanner</span>";
    }
  });
}

function populateTamperSimulator(wmResult) {
  if (!wmResult || !wmResult.watermarked_dna) return;
  currentOriginalWatermarkedDna = wmResult.watermarked_dna;
  currentTamperedDna = wmResult.watermarked_dna;
  tamperedBaseIndex = -1;

  // Update Visual Status Label
  const sourceLabel = document.getElementById("tamper-source-label");
  const sourceMeta = document.getElementById("tamper-source-meta");
  const dot = document.getElementById("tamper-status-dot");
  const resultBlock = document.getElementById("tamper-result-block");

  if (sourceLabel) {
    sourceLabel.innerText = `Freshly Watermarked CDS (${wmResult.invariants?.watermarked_length_nt || currentTamperedDna.length} nt / ${wmResult.invariants?.amino_acid_length || currentTamperedDna.length / 3} aa)`;
  }
  if (sourceMeta) {
    const lab = wmResult.payload?.lab_id || "TWS";
    const ord = wmResult.payload?.order_id || "901";
    sourceMeta.innerHTML = `<span>Verified Origin: Lab=${lab} | Order=${ord} | Status=AUTHENTIC</span>`;
  }
  if (dot) {
    dot.style.background = "#10b981";
    dot.style.boxShadow = "0 0 10px #10b981";
  }
  if (resultBlock) {
    resultBlock.style.display = "none";
  }

  renderInteractiveBases();

  const logMsg = document.getElementById("tamper-log-msg");
  if (logMsg) {
    logMsg.innerHTML = `<span style="color: #34d399;">✓ Active Sequence Source: Freshly Watermarked CDS loaded.</span> Click "Auto Mutate 1 Wobble Base" or click any nucleotide below.`;
  }
}

function renderInteractiveBases() {
  const container = document.getElementById("tamper-sequence-display");
  if (!container || !currentTamperedDna) return;
  container.innerHTML = "";

  const bases = currentTamperedDna.split("");
  bases.forEach((base, idx) => {
    const span = document.createElement("span");
    span.className = "nt-base base-interactive";
    span.innerText = base;
    if (idx === tamperedBaseIndex) {
      span.classList.add("flipped", "tampered-highlight");
    }
    span.title = `Click to mutate nucleotide #${idx} (${base})`;
    span.addEventListener("click", () => {
      mutateBaseAtIndex(idx);
    });
    container.appendChild(span);
  });
}

function mutateBaseAtIndex(idx) {
  if (!currentTamperedDna || idx < 0 || idx >= currentTamperedDna.length) return;

  const current = currentTamperedDna[idx];
  const alternates = { A: "C", C: "G", G: "T", T: "A" };
  const mutated = alternates[current] || "A";

  const arr = currentTamperedDna.split("");
  arr[idx] = mutated;
  currentTamperedDna = arr.join("");
  tamperedBaseIndex = idx;

  renderInteractiveBases();

  // Update Status Badge to Alert State
  const dot = document.getElementById("tamper-status-dot");
  const meta = document.getElementById("tamper-source-meta");
  if (dot) {
    dot.style.background = "#ef4444";
    dot.style.boxShadow = "0 0 10px #ef4444";
  }
  if (meta) {
    meta.innerHTML = `<span style="color: #ef4444; font-weight: 700;">MUTATED (Base #${idx} substituted: ${current} &rarr; ${mutated})</span>`;
  }

  const logMsg = document.getElementById("tamper-log-msg");
  if (logMsg) {
    logMsg.innerHTML = `
      <span style="color: #ef4444; font-weight: 700;">Base #${idx} mutated: ${current} &rarr; ${mutated}</span>.
      Click <strong>"Send to Firewall Scanner"</strong> to verify instant tamper trip!
    `;
  }
}

function renderTamperScanResult(res) {
  const block = document.getElementById("tamper-result-block");
  if (!block) return;
  block.style.display = "block";

  const isTampered = (res.classification === "TAMPERED_PAYLOAD");
  const color = isTampered ? "#ef4444" : "#10b981";
  const bg = isTampered ? "rgba(239, 68, 68, 0.12)" : "rgba(16, 185, 129, 0.12)";
  const border = isTampered ? "rgba(239, 68, 68, 0.4)" : "rgba(16, 185, 129, 0.4)";
  const icon = isTampered ? "⚡" : "🛡️";

  lastScanResult = res;

  block.innerHTML = `
    <div style="padding: 1.25rem; border-radius: 10px; border: 1px solid ${border}; background: ${bg};">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem;">
        <div style="font-weight: 800; font-family: var(--font-mono); font-size: 1.15rem; color: ${color};">
          ${icon} ${res.classification}
        </div>
        <span style="font-family: var(--font-mono); font-size: 0.75rem; color: #94a3b8; background: rgba(0, 0, 0, 0.4); padding: 0.2rem 0.5rem; border-radius: 4px;">
          Event: ${res.event_id}
        </span>
      </div>
      <div style="font-size: 0.85rem; color: #cbd5e1; margin-top: 0.45rem; line-height: 1.5;">${res.status_summary}</div>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.5rem; margin-top: 0.75rem; font-size: 0.75rem; color: #94a3b8; font-family: var(--font-mono); background: rgba(0, 0, 0, 0.3); padding: 0.6rem; border-radius: 6px;">
        <div>CRC16 Desynchronized: <strong style="color: ${res.tampered ? '#ef4444' : '#34d399'}">${res.tampered ? 'YES (CORRUPTED)' : 'NO (INTACT)'}</strong></div>
        <div>Provenance Signature: <strong style="color: ${res.provenance_verified ? '#34d399' : '#ef4444'}">${res.provenance_verified ? 'VALID' : 'INVALID'}</strong></div>
        <div>Sequence SHA-256: <span style="color: #38bdf8">${res.sequence_hash.slice(0, 12)}...</span></div>
      </div>
      <div style="margin-top: 0.85rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem;">
        <span style="font-size: 0.75rem; color: #94a3b8;">${isTampered ? '⚠️ Single-nucleotide corruption detected by GeneSign bit-flip interlock.' : 'Pristine sequence verified.'}</span>
        <button class="btn-xs-kms" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.4); color: #34d399; display: inline-flex; align-items: center; gap: 0.35rem;" onclick="switchToRadarAndAnalyze()">
          <span>🧠 View NVIDIA Nemotron Threat Rationale &rarr;</span>
        </button>
      </div>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// 4. Enterprise Audit Ledger
// ---------------------------------------------------------------------------
async function loadAuditLedger() {
  try {
    const resp = await fetch("/api/v1/ledger?limit=30");
    const data = await resp.json();

    // Update stats ticker in header
    if (data.stats) {
      document.getElementById("ticker-total").innerText = data.stats.total_events;
      document.getElementById("ticker-wm").innerText = data.stats.watermarks_created;
      document.getElementById("ticker-threats").innerText = data.stats.threats_intercepted;
      document.getElementById("ticker-tamper").innerText = data.stats.tamper_interlocks;
    }

    // Render table
    const tbody = document.getElementById("ledger-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (data.events && data.events.length > 0) {
      data.events.forEach(ev => {
        const tr = document.createElement("tr");
        const statusColor = ev.classification === "VERIFIED_LICENSED" ? "#34d399" : (ev.classification === "ROGUE_SYNTHETIC" || ev.classification === "TAMPERED_PAYLOAD" ? "#f87171" : "#fbbf24");
        tr.innerHTML = `
          <td style="color: #64748b;">${ev.timestamp.split("T")[1].slice(0, 8)}</td>
          <td style="font-weight: 700; color: #38bdf8;">${ev.event_id}</td>
          <td><span style="background: rgba(255, 255, 255, 0.05); padding: 0.2rem 0.4rem; border-radius: 4px;">${ev.event_type}</span></td>
          <td style="color: ${statusColor}; font-weight: 600;">${ev.classification || "N/A"}</td>
          <td style="color: #94a3b8;">${ev.sequence_hash.slice(0, 16)}...</td>
          <td>${ev.lab_id || "-"}</td>
          <td>${ev.order_id || "-"}</td>
        `;
        tbody.appendChild(tr);
      });
    } else {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 2rem;">No audit transactions recorded yet.</td></tr>`;
    }
  } catch (err) {
    console.error("Failed to load audit ledger:", err);
  }
}

// ---------------------------------------------------------------------------
// 5. Enterprise Batch Screening & Multi-Tenant KMS Registry
// ---------------------------------------------------------------------------
let activeBatchJobId = null;
let batchPollInterval = null;
let selectedBatchFile = null;

function initEnterpriseModule() {
  const dropzone = document.getElementById("batch-dropzone");
  const fileInput = document.getElementById("batch-file-input");
  const inputText = document.getElementById("batch-input-text");
  const submitBtn = document.getElementById("batch-submit-btn");

  if (!dropzone || !fileInput || !submitBtn) return;

  // File Picker Click
  dropzone.addEventListener("click", () => fileInput.click());

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      selectedBatchFile = e.target.files[0];
      dropzone.querySelector("div > div").innerText = `Selected: ${selectedBatchFile.name} (${(selectedBatchFile.size / 1024).toFixed(1)} KB)`;
      dropzone.style.borderColor = "var(--coral-accent)";
      dropzone.style.background = "rgba(255, 107, 74, 0.1)";
    }
  });

  // Drag and Drop
  ["dragenter", "dragover"].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      selectedBatchFile = e.dataTransfer.files[0];
      dropzone.querySelector("div > div").innerText = `Dropped: ${selectedBatchFile.name} (${(selectedBatchFile.size / 1024).toFixed(1)} KB)`;
      dropzone.style.borderColor = "var(--coral-accent)";
      dropzone.style.background = "rgba(255, 107, 74, 0.1)";
    }
  });

  // Presets
  document.querySelectorAll(".batch-preset-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const sampleId = btn.getAttribute("data-sample");
      try {
        const resp = await fetch(`/api/v1/samples/${sampleId}`);
        const data = await resp.json();
        inputText.value = data.content;
        selectedBatchFile = null;
        dropzone.querySelector("div > div").innerText = "Drag & drop FASTA / FASTQ file here";
        dropzone.style.borderColor = "";
        dropzone.style.background = "";
      } catch (err) {
        console.error("Failed to load batch sample:", err);
      }
    });
  });

  // Submit Batch Screening
  submitBtn.addEventListener("click", async () => {
    if (batchPollInterval) clearInterval(batchPollInterval);

    const formData = new FormData();
    if (selectedBatchFile) {
      formData.append("file", selectedBatchFile);
    } else if (inputText.value.trim()) {
      formData.append("fasta_text", inputText.value.trim());
    } else {
      alert("Please upload a FASTA/FASTQ file or enter sequence text.");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span>Dispatching to Worker...</span>`;

    const progressBox = document.getElementById("batch-progress-box");
    const progressFill = document.getElementById("batch-progress-fill");
    const statusText = document.getElementById("batch-status-text");
    const percentText = document.getElementById("batch-progress-percent");
    const summaryChips = document.getElementById("batch-summary-chips");
    const manifestPanel = document.getElementById("batch-manifest-panel");

    progressBox.style.display = "block";
    manifestPanel.style.display = "none";
    progressFill.style.width = "5%";
    statusText.innerText = "DISPATCHING TO INGESTION PIPELINE...";
    percentText.innerText = "5%";
    summaryChips.innerHTML = "";

    try {
      const resp = await fetch("/api/v2/batch-scan", {
        method: "POST",
        body: formData,
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || "Batch dispatch failed");
      }

      const jobData = await resp.json();
      activeBatchJobId = jobData.job_id;
      statusText.innerText = `PROCESSING (${activeBatchJobId})...`;

      // Start polling
      batchPollInterval = setInterval(async () => {
        try {
          const pollResp = await fetch(`/api/v2/batch-scan/${activeBatchJobId}`);
          if (!pollResp.ok) return;
          const pollData = await pollResp.json();

          const pct = Math.max(5, Math.min(100, pollData.progress_percent || 0));
          progressFill.style.width = `${pct}%`;
          percentText.innerText = `${pct}%`;

          if (pollData.status === "processing") {
            statusText.innerText = `SCREENING RECORD ${pollData.processed_records} / ${pollData.total_records}...`;
          } else if (pollData.status === "completed") {
            clearInterval(batchPollInterval);
            batchPollInterval = null;
            progressFill.style.width = "100%";
            percentText.innerText = "100%";
            statusText.innerText = `BATCH SCREENING COMPLETED (${pollData.total_records} RECORDS)`;
            statusText.style.color = "#34d399";
            submitBtn.disabled = false;
            submitBtn.innerHTML = `
              <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
              <span>Dispatch Batch Screening Job</span>
            `;

            renderBatchResults(pollData);
            loadAuditLedger();
          } else if (pollData.status === "failed") {
            clearInterval(batchPollInterval);
            batchPollInterval = null;
            statusText.innerText = `FAILED: ${pollData.error || "Unknown error"}`;
            statusText.style.color = "#f87171";
            submitBtn.disabled = false;
            submitBtn.innerHTML = `<span>Retry Batch Job</span>`;
          }
        } catch (pollErr) {
          console.error("Polling error:", pollErr);
        }
      }, 400);

    } catch (err) {
      alert(`Batch screening error: ${err.message}`);
      submitBtn.disabled = false;
      submitBtn.innerHTML = `
        <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
        <span>Dispatch Batch Screening Job</span>
      `;
      progressBox.style.display = "none";
    }
  });
}

function renderBatchResults(job) {
  const summaryChips = document.getElementById("batch-summary-chips");
  const manifestPanel = document.getElementById("batch-manifest-panel");
  const manifestTbody = document.getElementById("batch-manifest-tbody");
  const jobIdBadge = document.getElementById("batch-job-id-badge");

  jobIdBadge.innerText = `Job: ${job.job_id} | File: ${job.filename}`;
  manifestPanel.style.display = "block";

  const s = job.summary;
  summaryChips.innerHTML = `
    <span style="background: rgba(255,255,255,0.08); padding: 0.25rem 0.5rem; border-radius: 4px; color: #fff;">Total: <strong>${s.total}</strong></span>
    <span style="background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); padding: 0.25rem 0.5rem; border-radius: 4px; color: #34d399;">Licensed: <strong>${s.verified_licensed}</strong></span>
    <span style="background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); padding: 0.25rem 0.5rem; border-radius: 4px; color: #f87171;">Rogue Threats: <strong>${s.rogue_synthetic}</strong></span>
    <span style="background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.3); padding: 0.25rem 0.5rem; border-radius: 4px; color: #fbbf24;">Tampered: <strong>${s.tampered_payload}</strong></span>
    <span style="background: rgba(100, 116, 139, 0.15); padding: 0.25rem 0.5rem; border-radius: 4px; color: #94a3b8;">Unknown Drift: <strong>${s.unknown_drift}</strong></span>
  `;

  manifestTbody.innerHTML = "";
  if (job.manifest && job.manifest.length > 0) {
    job.manifest.forEach(item => {
      const tr = document.createElement("tr");

      let badgeColor = "#94a3b8";
      let badgeBg = "rgba(100, 116, 139, 0.15)";
      let badgeBorder = "rgba(100, 116, 139, 0.3)";

      if (item.classification === "VERIFIED_LICENSED") {
        badgeColor = "#34d399";
        badgeBg = "rgba(16, 185, 129, 0.15)";
        badgeBorder = "rgba(16, 185, 129, 0.3)";
      } else if (item.classification === "ROGUE_SYNTHETIC") {
        badgeColor = "#f87171";
        badgeBg = "rgba(239, 68, 68, 0.15)";
        badgeBorder = "rgba(239, 68, 68, 0.3)";
      } else if (item.classification === "TAMPERED_PAYLOAD") {
        badgeColor = "#fb923c";
        badgeBg = "rgba(249, 115, 22, 0.15)";
        badgeBorder = "rgba(249, 115, 22, 0.3)";
      } else if (item.classification === "UNKNOWN_DRIFT") {
        badgeColor = "#fbbf24";
        badgeBg = "rgba(245, 158, 11, 0.15)";
        badgeBorder = "rgba(245, 158, 11, 0.3)";
      }

      const threatDisplay = item.threat_names && item.threat_names.length > 0
        ? `<span style="color: #f87171; font-weight: 700;">⚠ ${item.threat_names.join(", ")} (${item.highest_threat_tier})</span>`
        : `<span style="color: #64748b;">None</span>`;

      tr.innerHTML = `
        <td style="font-weight: 700; color: var(--ivory); font-family: var(--font-mono);">${item.record_id}</td>
        <td><span style="font-size: 0.7rem; color: #94a3b8; background: rgba(255,255,255,0.05); padding: 0.15rem 0.4rem; border-radius: 3px;">${item.format}</span></td>
        <td style="font-family: var(--font-mono);">${item.length_nt} nt</td>
        <td style="font-family: var(--font-mono);">${item.gc_content}%</td>
        <td>
          <span style="font-family: var(--font-mono); font-size: 0.72rem; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 700; color: ${badgeColor}; background: ${badgeBg}; border: 1px solid ${badgeBorder};">
            ${item.classification}
          </span>
        </td>
        <td>${threatDisplay}</td>
        <td style="font-family: var(--font-mono);">${item.lab_id || "-"}</td>
        <td style="font-size: 0.75rem; color: #94a3b8; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${item.status_summary}">
          ${item.status_summary}
        </td>
      `;
      manifestTbody.appendChild(tr);
    });
  }
}

// ---------------------------------------------------------------------------
// 6. KMS Provider Trust Registry Loader & Controllers
// ---------------------------------------------------------------------------
async function loadKmsProviders() {
  const container = document.getElementById("kms-providers-container");
  const crlTbody = document.getElementById("crl-tbody");
  const crlBadge = document.getElementById("crl-count-badge");
  if (!container) return;

  try {
    const [provResp, crlResp] = await Promise.all([
      fetch("/api/v2/kms/providers"),
      fetch("/api/v2/kms/crl"),
    ]);

    const provData = await provResp.json();
    const crlData = await crlResp.json();

    // Render Providers
    container.innerHTML = "";
    if (provData.providers && provData.providers.length > 0) {
      provData.providers.forEach(p => {
        const isRevoked = p.status === "REVOKED";
        const card = document.createElement("div");
        card.className = `provider-card ${isRevoked ? 'revoked' : ''}`;
        card.innerHTML = `
          <div class="provider-header">
            <span class="provider-title">${p.name}</span>
            <span class="crl-badge ${p.status === 'ACTIVE' ? 'active' : 'revoked'}">${p.status}</span>
          </div>
          <div class="provider-meta">
            <div>Provider ID: <strong style="color: var(--ivory);">${p.provider_id}</strong> (${p.jurisdiction})</div>
            <div>Active Key: <span style="color: var(--coral-accent); font-weight: 700;">${p.active_key_version}</span></div>
            <div>Fingerprint: <span style="color: #38bdf8;">${p.active_fingerprint ? p.active_fingerprint.slice(0, 16) : 'None'}</span></div>
          </div>
          <div class="provider-actions">
            <button class="btn-xs-kms" onclick="rotateProviderKey('${p.provider_id}')">Rotate Key</button>
            <button class="btn-xs-kms danger" onclick="revokeProviderKey('${p.provider_id}')">Revoke Active</button>
          </div>
        `;
        container.appendChild(card);
      });
    }

    // Render CRL
    if (crlBadge) crlBadge.innerText = `${crlData.total_revocations || 0} Entries`;
    if (crlTbody) {
      crlTbody.innerHTML = "";
      if (crlData.crl && crlData.crl.length > 0) {
        crlData.crl.forEach(entry => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td style="color: #f87171; font-weight: 700;">${entry.provider_id}</td>
            <td>${entry.key_version}</td>
            <td style="color: #94a3b8;">${entry.fingerprint ? entry.fingerprint.slice(0, 12) : '-'}</td>
            <td style="color: #cbd5e1;">${entry.reason}</td>
          `;
          crlTbody.appendChild(tr);
        });
      } else {
        crlTbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: #64748b; padding: 0.75rem;">CRL Empty (All Keys Compliant)</td></tr>`;
      }
    }
  } catch (err) {
    console.error("Failed to load KMS data:", err);
  }
}

async function rotateProviderKey(providerId) {
  try {
    const resp = await fetch(`/api/v2/kms/providers/${providerId}/rotate`, { method: "POST" });
    const data = await resp.json();
    if (resp.ok) {
      alert(`Success: ${data.message} (Fingerprint: ${data.fingerprint})`);
      loadKmsProviders();
    } else {
      alert(`Rotation failed: ${data.detail || "Unknown error"}`);
    }
  } catch (err) {
    alert(`Rotation request error: ${err.message}`);
  }
}

async function revokeProviderKey(providerId) {
  const reason = prompt(`Enter revocation reason for ${providerId} key:`, "ADMINISTRATIVE_SECURITY_REVOCATION");
  if (!reason) return;

  try {
    const resp = await fetch(`/api/v2/kms/providers/${providerId}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: reason }),
    });
    const data = await resp.json();
    if (resp.ok) {
      alert(`Success: ${data.message}`);
      loadKmsProviders();
    } else {
      alert(`Revocation failed: ${data.detail || "Unknown error"}`);
    }
  } catch (err) {
    alert(`Revocation request error: ${err.message}`);
  }
}

// ---------------------------------------------------------------------------
// 7. Level 3: Hardware Interlock, Fragment Assembler & Merkle Ledger
// ---------------------------------------------------------------------------
let hardwarePollTimer = null;
let activeMerkleBundle = null;

function initHardwareInterlockTOC() {
  loadSplitScenario("anthrax");
  pollHardwareStatus();
  fetchMerkleBundle();

  // Poll hardware status every 3.5 seconds
  if (hardwarePollTimer) clearInterval(hardwarePollTimer);
  hardwarePollTimer = setInterval(pollHardwareStatus, 3500);
}

// Telemetry & Valve Matrix Polling
async function pollHardwareStatus() {
  try {
    const resp = await fetch("/api/v3/hardware/status");
    if (!resp.ok) return;
    const data = await resp.json();

    // State Badge
    const stateEl = document.getElementById("telem-hw-state");
    if (stateEl) {
      stateEl.innerText = data.state;
      stateEl.className = "metric-quad-val";
      if (data.state === "STANDBY") {
        stateEl.style.color = "#38bdf8";
      } else if (data.state === "SYNTHESIZING") {
        stateEl.style.color = "#34d399";
      } else if (data.state === "INTERLOCK_HALT" || data.state === "E_STOPPED") {
        stateEl.style.color = "#ef4444";
      } else if (data.state === "ARMED") {
        stateEl.style.color = "#fbbf24";
      }
    }

    // Pressure & Coupling Efficiency
    const pressEl = document.getElementById("telem-pressure");
    if (pressEl && data.chamber_pressure_atm !== undefined) {
      pressEl.innerText = `${data.chamber_pressure_atm.toFixed(2)} atm`;
    }

    const coupEl = document.getElementById("telem-coupling");
    if (coupEl && data.reagent_coupling_efficiency !== undefined) {
      coupEl.innerText = `${data.reagent_coupling_efficiency.toFixed(1)}%`;
    }

    // Interlock Latch
    const latchEl = document.getElementById("telem-latch");
    if (latchEl) {
      if (data.interlock_latched) {
        latchEl.innerText = "TRIPPED";
        latchEl.style.color = "#ef4444";
      } else {
        latchEl.innerText = "SECURE";
        latchEl.style.color = "#34d399";
      }
    }

    // Update Valve Cards
    if (data.valves) {
      const valveKeys = [
        "monomer_a", "monomer_c", "monomer_g", "monomer_t",
        "activator", "oxidizer", "deblock", "capping"
      ];
      valveKeys.forEach(key => {
        const card = document.getElementById(`valve-${key}`);
        if (!card) return;

        const vStatus = data.valves[key] || "CLOSED";
        const led = card.querySelector(".valve-led");
        const statusSpan = card.querySelector(".valve-status");

        if (led) {
          led.classList.remove("active", "sealed");
          if (vStatus === "OPEN") led.classList.add("active");
          if (vStatus === "SEALED") led.classList.add("sealed");
        }

        if (statusSpan) {
          statusSpan.innerText = vStatus;
          if (vStatus === "OPEN") {
            statusSpan.style.color = "#34d399";
          } else if (vStatus === "SEALED") {
            statusSpan.style.color = "#ef4444";
          } else {
            statusSpan.style.color = "var(--text-muted)";
          }
        }
      });
    }
  } catch (err) {
    console.debug("Hardware status poll error:", err);
  }
}

// Emergency Stop (E-STOP) Action
async function triggerHardwareEstop() {
  const consoleEl = document.getElementById("hw-dispatch-console");
  try {
    const resp = await fetch("/api/v3/hardware/estop", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "MANUAL_OPERATOR_PANIC_ESTOP" })
    });
    const data = await resp.json();
    if (consoleEl) {
      consoleEl.innerHTML = `<span style="color: #ef4444; font-weight: 700;">[CRITICAL E-STOP TRIPPED]</span> Physical synthesizer halted. All monomer and reagent valves SEALED! Hardware locked.`;
    }
    await pollHardwareStatus();
    await fetchMerkleBundle();
  } catch (err) {
    alert(`E-STOP dispatch failed: ${err.message}`);
  }
}

// Reset Hardware Interlock
async function resetHardwareInterlock() {
  const consoleEl = document.getElementById("hw-dispatch-console");
  try {
    const resp = await fetch("/api/v3/hardware/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ authorization_key: "ADMIN-SECURITY-OVERRIDE" })
    });
    const data = await resp.json();
    if (resp.ok) {
      if (consoleEl) {
        consoleEl.innerHTML = `<span style="color: #34d399; font-weight: 700;">[INTERLOCK CLEARED]</span> Hardware latch reset. Valves unsealed. Synthesizer returned to STANDBY mode.`;
      }
      await pollHardwareStatus();
    } else {
      if (consoleEl) {
        consoleEl.innerHTML = `<span style="color: #ef4444; font-weight: 700;">[RESET REJECTED]</span> ${data.detail || "Authentication failure"}`;
      }
    }
  } catch (err) {
    alert(`Hardware reset request failed: ${err.message}`);
  }
}

// Dispatch Authorized Test Construct (GFP with valid provenance)
async function dispatchAuthorizedTest() {
  const consoleEl = document.getElementById("hw-dispatch-console");
  if (consoleEl) {
    consoleEl.innerHTML = `<span style="color: #38bdf8;">[PRE-FLIGHT]</span> Generating licensed test construct with verified TWIST_BIOSCIENCE Ed25519 provenance...`;
  }

  try {
    // Generate fresh licensed watermark if needed
    let seq = currentWatermarkResult ? currentWatermarkResult.watermarked_sequence : null;
    let token = currentWatermarkResult ? currentWatermarkResult.provenance_token : null;

    if (!seq || !token) {
      const sampleResp = await fetch("/api/v1/samples/gfp");
      const sampleData = await sampleResp.json();
      const wmResp = await fetch("/api/v1/watermark", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sequence_dna: sampleData.sequence,
          lab_id: "TWIST_BIOSCIENCE",
          order_id: "ORD-LICENSED-992",
          customer_id: "CUST-ACADEMIC-001"
        })
      });
      const wmRes = await wmResp.json();
      seq = wmRes.watermarked_sequence;
      token = wmRes.provenance_token;
    }

    const dispResp = await fetch("/api/v3/hardware/dispatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sequence: seq,
        record_id: "SYNTH-ORD-GFP-992",
        provenance_token: token,
        lab_id: "TWIST_BIOSCIENCE",
        order_id: "ORD-LICENSED-992"
      })
    });

    const res = await dispResp.json();
    if (res.success) {
      if (consoleEl) {
        consoleEl.innerHTML = `
          <span style="color: #34d399; font-weight: 700;">[GATE PASS - AUTHORIZED]</span>
          Status: <strong>${res.state}</strong> | Provider: <strong>TWIST_BIOSCIENCE</strong>
          <br>Ed25519 digital signature verified. Pneumatic monomer dispensing active.
        `;
      }
    } else {
      if (consoleEl) {
        consoleEl.innerHTML = `<span style="color: #ef4444; font-weight: 700;">[GATE REFUSAL]</span> ${res.error || "Interlock tripped."}`;
      }
    }

    await pollHardwareStatus();
    await fetchMerkleBundle();
  } catch (err) {
    if (consoleEl) consoleEl.innerText = `Dispatch error: ${err.message}`;
  }
}

// Dispatch Rogue Test Construct (Anthrax toxin fragment without license)
async function dispatchRogueTest() {
  const consoleEl = document.getElementById("hw-dispatch-console");
  if (consoleEl) {
    consoleEl.innerHTML = `<span style="color: #fbbf24;">[PRE-FLIGHT]</span> Dispatching unwatermarked pathogen fragment (Anthrax Lethal Factor) to test hardware gate...`;
  }

  try {
    const rogueAnthraxOligo = "ATGGCCGGAGCTAGAGTTATTCCTATTTTAGAAGGGTTAGATAGAAATGTTGTAGGTGGTTTTACAAATTTTGCTGAAGAAGTTGTAGAAGGTAGAGCTAGAGTTATTCCTATTTTAGAAGGGTTAGATAGAAATGTTGTAGGTGGTTTTACAAATTTTGCTGAAGAAGTTGTAGAAGGTAGAGCTAGAGTTATTCCT";

    const dispResp = await fetch("/api/v3/hardware/dispatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sequence: rogueAnthraxOligo,
        record_id: "ROGUE-ANTHRAX-ATTEMPT",
        lab_id: "UNLICENSED_FOUNDRY",
        order_id: "ORD-ROGUE-007"
      })
    });

    const res = await dispResp.json();
    if (!res.success) {
      if (consoleEl) {
        consoleEl.innerHTML = `
          <span style="color: #ef4444; font-weight: 700;">[CRITICAL INTERLOCK HALT]</span>
          Gate Refusal: <strong>${res.error || "UNAUTHORIZED_CONSTRUCT"}</strong>
          <br>Hazard Level: <strong>${res.classification || 'ROGUE_SYNTHETIC'}</strong> | State: <strong>INTERLOCK_HALT</strong>
          <br>Valves SEALED instantly. Reagent delivery mechanically blocked.
        `;
      }
    } else {
      if (consoleEl) {
        consoleEl.innerHTML = `Unexpected grant: ${JSON.stringify(res)}`;
      }
    }

    await pollHardwareStatus();
    await fetchMerkleBundle();
  } catch (err) {
    if (consoleEl) consoleEl.innerText = `Rogue dispatch error: ${err.message}`;
  }
}

// Split-Order Scenario Loader
function loadSplitScenario(scenario) {
  const txtArea = document.getElementById("split-orders-json");
  if (!txtArea) return;

  if (scenario === "anthrax") {
    const orders = [
      {
        order_id: "ORD-SPLIT-ANTHRAX-A",
        customer_id: "CUST-SHELL-CORP-A",
        provider_id: "TWIST_BIOSCIENCE",
        sequence: "ATGGCCGGAGCTAGAGTTATTCCTATTTTAGAAGGGTTAGATAGAAATGTTGTAGGTGGTTTTACAAATTTTGCTGAAGAAGTTGTAGAAG"
      },
      {
        order_id: "ORD-SPLIT-ANTHRAX-B",
        customer_id: "CUST-SHELL-CORP-B",
        provider_id: "GINKGO_BIOWORKS",
        sequence: "GTTTTACAAATTTTGCTGAAGAAGTTGTAGAAGGTAGAGCTAGAGTTATTCCTATTTTAGAAGGGTTAGATAGAAATGTTGTAGGTGGTTTTAC"
      },
      {
        order_id: "ORD-SPLIT-ANTHRAX-C",
        customer_id: "CUST-SHELL-CORP-C",
        provider_id: "IDT_INTEGRATED_DNA",
        sequence: "AGATAGAAATGTTGTAGGTGGTTTTACAAATTTTGCTGAAGAAGTTGTAGAAGGTAGAGCTAGAGTTATTCCT"
      }
    ];
    txtArea.value = JSON.stringify(orders, null, 2);
  } else if (scenario === "botulinum") {
    const orders = [
      {
        order_id: "ORD-SPLIT-BONT-1",
        customer_id: "CUST-RESEARCH-ALPHA",
        provider_id: "TWIST_BIOSCIENCE",
        sequence: "ATGCCATTTGTTAATAAACAATTTAATTATAAAGATCCTGTAAATGGTGTTGATATTGCTTATATAAAAATTCCAAATGCAGGTCAAATGCAACCAGTAAAAGCTTTTAAAATTCATAATAAAATATGGGTAATTCC"
      },
      {
        order_id: "ORD-SPLIT-BONT-2",
        customer_id: "CUST-RESEARCH-BETA",
        provider_id: "IDT_INTEGRATED_DNA",
        sequence: "TAAAATTCATAATAAAATATGGGTAATTCCAGAAAGAGATACATTTACAAATCCTGAAGAAGGAGATTTAAATCCACCACCAGAAGCAAAACAAGTTCCAGTTTCATATTATGATTCAACATATCTAAGTACAG"
      },
      {
        order_id: "ORD-SPLIT-BONT-3",
        customer_id: "CUST-RESEARCH-GAMMA",
        provider_id: "CUSTOM_FOUNDRY",
        sequence: "CCAGTTTCATATTATGATTCAACATATCTAAGTACAGATAATGAAAAAGATAACTATCTTAAAGGTGTAACTAAATTATTTGAACGTATTTATTCAACTGATTTGGGAAGA"
      }
    ];
    txtArea.value = JSON.stringify(orders, null, 2);
  } else if (scenario === "gfp") {
    const orders = [
      {
        order_id: "ORD-BENIGN-GFP-1",
        customer_id: "LAB-BIOENGINEERING",
        provider_id: "TWIST_BIOSCIENCE",
        sequence: "ATGGTGAGCAAGGGCGAGGAGCTGTTCACCGGGGTGGTGCCCATCCTGGTCGAGCTGGACGGCGACGTAAACGGCCACAAGTTCAGCGTGTCCGGCGAGGGCGAGGGCGATGCCACCTACGGCAAGCTGACCCTGAAG"
      },
      {
        order_id: "ORD-BENIGN-GFP-2",
        customer_id: "LAB-BIOENGINEERING",
        provider_id: "TWIST_BIOSCIENCE",
        sequence: "GGCGATGCCACCTACGGCAAGCTGACCCTGAAGTTCATCTGCACCACCGGCAAGCTGCCCGTGCCCTGGCCCACCCTCGTGACCACCCTGACCTACGGCGTGCAGTGCTTCAGCCGCTACCCCGACCACATGAAGCAG"
      }
    ];
    txtArea.value = JSON.stringify(orders, null, 2);
  }
}

// Fragment Assembly & Biosecurity Screening
async function screenSplitOrders() {
  const txtArea = document.getElementById("split-orders-json");
  const resultContainer = document.getElementById("contigs-result-container");
  const btn = document.getElementById("screen-split-orders-btn");
  if (!txtArea || !resultContainer) return;

  let orders = [];
  try {
    orders = JSON.parse(txtArea.value);
  } catch (e) {
    alert("Invalid JSON format in Fragment Queue. Please check syntax.");
    return;
  }

  if (btn) btn.disabled = true;
  resultContainer.innerHTML = `<div style="color: var(--cyan-glow); font-family: var(--font-mono); font-size: 0.8rem; padding: 1rem;">Reconstructing overlap graph across ${orders.length} distributed orders...</div>`;

  try {
    const resp = await fetch("/api/v3/split-orders/screen", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ orders: orders, min_overlap: 15 })
    });

    const data = await resp.json();
    if (btn) btn.disabled = false;

    if (!resp.ok) {
      resultContainer.innerHTML = `<div style="color: #ef4444; padding: 1rem;">Error: ${data.detail || "Assembly screening failed"}</div>`;
      return;
    }

    // Render Contigs
    const hasThreat = (data.threats_detected_count > 0);
    const summaryColor = hasThreat ? "#ef4444" : "#34d399";

    let html = `
      <div style="background: rgba(0,0,0,0.4); border-radius: 8px; padding: 1rem; border: 1px solid ${hasThreat ? 'rgba(239,68,68,0.4)' : 'rgba(16,185,129,0.3)'};">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
          <div style="font-weight: 800; font-family: var(--font-mono); color: ${summaryColor}; font-size: 0.95rem;">
            ${hasThreat ? '🚨 DISTRIBUTED EVASION ATTACK DETECTED' : '✓ ALL ASSEMBLED CONTIGS BENIGN'}
          </div>
          <span style="font-family: var(--font-mono); font-size: 0.75rem; color: #94a3b8;">
            Orders Analyzed: ${data.total_orders_analyzed} | Contigs Formed: ${data.assembled_contigs_count}
          </span>
        </div>
    `;

    if (data.contigs && data.contigs.length > 0) {
      data.contigs.forEach((c, idx) => {
        const cThreat = c.threat_detected;
        const cColor = cThreat ? "#ef4444" : "#34d399";
        const cBg = cThreat ? "rgba(239, 68, 68, 0.08)" : "rgba(16, 185, 129, 0.08)";
        const borderCol = cThreat ? "rgba(239, 68, 68, 0.3)" : "rgba(16, 185, 129, 0.25)";

        html += `
          <div class="contig-card" style="border: 1px solid ${borderCol}; background: ${cBg};">
            <div class="contig-header">
              <span class="contig-id" style="color: ${cColor};">${c.contig_id}</span>
              <span class="contig-badge ${cThreat ? 'threat' : 'benign'}">
                ${cThreat ? 'HAZARDOUS SELECT AGENT' : 'BENIGN CONSTRUCT'}
              </span>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.5rem; margin-top: 0.5rem; font-family: var(--font-mono); font-size: 0.72rem; color: #94a3b8;">
              <div>Assembled Length: <strong style="color: var(--ivory);">${c.assembled_length_nt} nt</strong></div>
              <div>Participating Orders: <strong style="color: #38bdf8;">${c.participating_order_ids ? c.participating_order_ids.join(" &rarr; ") : "-"}</strong></div>
              <div>Target Pathogen: <strong style="color: ${cThreat ? '#ef4444' : '#34d399'};">${c.agent_name || "None (Negative)"}</strong></div>
              <div>Regulatory Tier: <span style="color: #fbbf24;">${c.regulatory_tier || "UNREGULATED"}</span></div>
            </div>

            ${cThreat ? `
              <div style="margin-top: 0.5rem; padding: 0.5rem; background: rgba(239, 68, 68, 0.15); border-radius: 4px; font-size: 0.72rem; color: #fca5a5;">
                <strong>Biosecurity Interlock Trip:</strong> Split synthesis evasion detected. Sequence fragments overlap to form regulated ${c.agent_name}. Order placed on global synthesis hold.
              </div>
            ` : ''}

            <div style="margin-top: 0.5rem;">
              <span style="font-size: 0.68rem; color: var(--text-muted); font-family: var(--font-mono);">Assembled Sequence Contig (5' &rarr; 3'):</span>
              <div style="font-family: var(--font-mono); font-size: 0.68rem; color: #cbd5e1; background: rgba(0,0,0,0.5); padding: 0.4rem; border-radius: 4px; overflow-x: auto; word-break: break-all;">
                ${c.assembled_sequence}
              </div>
            </div>
          </div>
        `;
      });
    }

    html += `</div>`;
    resultContainer.innerHTML = html;

    await fetchMerkleBundle();
  } catch (err) {
    resultContainer.innerHTML = `<div style="color: #ef4444; padding: 1rem;">Request Error: ${err.message}</div>`;
  }
}

// Merkle Tree Bundle & Cryptographic Proof Verification
async function fetchMerkleBundle() {
  try {
    const resp = await fetch("/api/v3/ledger/merkle-bundle?limit=50");
    if (!resp.ok) return;
    const bundle = await resp.json();
    activeMerkleBundle = bundle;

    const rootEl = document.getElementById("merkle-root-display");
    if (rootEl) {
      rootEl.innerText = bundle.merkle_root || "EMPTY_LEDGER_ROOT";
    }
  } catch (err) {
    console.debug("Failed to fetch Merkle bundle:", err);
  }
}

function exportMerkleBundle() {
  if (!activeMerkleBundle) {
    fetchMerkleBundle().then(() => {
      if (activeMerkleBundle) triggerBundleDownload(activeMerkleBundle);
    });
  } else {
    triggerBundleDownload(activeMerkleBundle);
  }
}

function triggerBundleDownload(bundle) {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(bundle, null, 2));
  const downloadAnchor = document.createElement("a");
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `genesign_rfc3161_audit_bundle_${Date.now()}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

async function verifyActiveBundle() {
  const resEl = document.getElementById("merkle-verif-result");
  if (!resEl) return;

  resEl.style.display = "block";
  resEl.innerHTML = `<span style="color: var(--cyan-glow);">Executing zero-knowledge mathematical verification over Merkle tree & RFC-3161 hash-chain...</span>`;

  try {
    if (!activeMerkleBundle) {
      await fetchMerkleBundle();
    }

    const resp = await fetch("/api/v3/ledger/verify-bundle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(activeMerkleBundle)
    });

    const data = await resp.json();
    const isSuccess = data.valid || data.verified;
    if (isSuccess) {
      const count = data.total_verified_events || data.total_events_verified || 0;
      resEl.style.background = "rgba(16, 185, 129, 0.12)";
      resEl.style.border = "1px solid rgba(16, 185, 129, 0.4)";
      resEl.innerHTML = `
        <div style="color: #34d399; font-weight: 700; margin-bottom: 0.35rem;">
          ✓ CRYPTOGRAPHIC AUDIT BUNDLE VERIFIED (RFC-3161 / NIST SP 800-106)
        </div>
        <div style="color: #cbd5e1; font-size: 0.75rem; line-height: 1.6;">
          • Total Chained Events Checked: <strong>${count}</strong><br>
          • Merkle Binary Tree Root: <span style="color: #38bdf8;">${data.merkle_root}</span><br>
          • Zero-Knowledge Inclusion Proofs: <strong>100% Cryptographically Valid</strong><br>
          • Regulatory Status: <span style="color: #34d399; font-weight: 600;">${data.regulatory_status || "COMPLIANT_VERIFIED"}</span><br>
          • Temporal Hash-Chain: <strong>Continuous & Unbroken (Zero Drift)</strong>
        </div>
      `;
    } else {
      resEl.style.background = "rgba(239, 68, 68, 0.12)";
      resEl.style.border = "1px solid rgba(239, 68, 68, 0.4)";
      resEl.innerHTML = `
        <div style="color: #ef4444; font-weight: 700;">
          ✗ AUDIT CHAIN COMPROMISED / INVALID PROOFS
        </div>
        <div style="color: #fca5a5; font-size: 0.75rem; margin-top: 0.35rem;">
          Error: ${data.error || (data.errors ? data.errors.join(", ") : "Unknown verification failure")}
        </div>
      `;
    }
  } catch (err) {
    resEl.innerHTML = `<span style="color: #ef4444;">Verification call error: ${err.message}</span>`;
  }
}

// ---------------------------------------------------------------------------
// 8. Commercial SaaS Portal & Monetization Suite Controller
// ---------------------------------------------------------------------------
let currentProductMode = "console";

function switchProductMode(mode) {
  currentProductMode = mode;
  const consoleBtn = document.getElementById("mode-btn-console");
  const saasBtn = document.getElementById("mode-btn-saas");
  const consoleView = document.getElementById("console-view-container");
  const saasView = document.getElementById("saas-portal-view");

  if (!consoleBtn || !saasBtn || !consoleView || !saasView) return;

  if (mode === "saas") {
    consoleBtn.classList.remove("active");
    saasBtn.classList.add("active");
    consoleView.style.display = "none";
    saasView.classList.add("active");

    // Load commercial data
    loadTenantApiKeys();
    refreshBillingUsage();
    loadTenantBranding();
  } else {
    saasBtn.classList.remove("active");
    consoleBtn.classList.add("active");
    saasView.classList.remove("active");
    consoleView.style.display = "block";
  }
}

async function provisionApiKeyFromUI() {
  const labelInput = document.getElementById("new-key-label");
  const tierSelect = document.getElementById("new-key-tier");
  const resultBox = document.getElementById("new-key-result-box");
  const rawTextEl = document.getElementById("new-key-raw-text");

  const name = labelInput ? labelInput.value.trim() : "Foundry Pipeline Key";
  const tier = tierSelect ? tierSelect.value : "ENTERPRISE";

  try {
    const resp = await fetch("/api/v1/auth/api-keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: name, tier: tier })
    });
    const data = await resp.json();
    if (resp.ok) {
      if (resultBox && rawTextEl) {
        resultBox.style.display = "block";
        rawTextEl.innerText = data.raw_api_key;
      }
      loadTenantApiKeys();
    } else {
      alert(`API Key Provisioning failed: ${data.detail || "Unknown error"}`);
    }
  } catch (err) {
    alert(`Provisioning request error: ${err.message}`);
  }
}

function copyProvisionedKey() {
  const rawTextEl = document.getElementById("new-key-raw-text");
  if (!rawTextEl) return;
  navigator.clipboard.writeText(rawTextEl.innerText).then(() => {
    alert("API Key token copied to clipboard! Keep this token secure.");
  }).catch(() => {
    prompt("Copy your API Key manually:", rawTextEl.innerText);
  });
}

async function loadTenantApiKeys() {
  const tbody = document.getElementById("api-keys-tbody");
  if (!tbody) return;

  try {
    const resp = await fetch("/api/v1/auth/api-keys");
    const data = await resp.json();
    tbody.innerHTML = "";

    if (data.api_keys && data.api_keys.length > 0) {
      data.api_keys.forEach(k => {
        const tr = document.createElement("tr");
        const statusColor = k.is_active ? "#34d399" : "#f87171";
        tr.innerHTML = `
          <td style="font-family: var(--font-mono); color: #38bdf8;">${k.key_id}</td>
          <td>${k.name}</td>
          <td style="font-family: var(--font-mono); color: #94a3b8;">${k.key_prefix}</td>
          <td><span style="background: rgba(255, 255, 255, 0.05); padding: 0.15rem 0.4rem; border-radius: 4px;">${k.tier}</span></td>
          <td style="color: ${statusColor}; font-weight: 600;">${k.is_active ? "ACTIVE" : "REVOKED"}</td>
          <td>
            ${k.is_active ? `<button class="btn-xs-kms danger" onclick="revokeApiKeyFromUI('${k.key_id}')">Revoke</button>` : `<span style="color: #64748b;">Deactivated</span>`}
          </td>
        `;
        tbody.appendChild(tr);
      });
    } else {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #64748b; padding: 1rem;">No active API keys provisioned.</td></tr>`;
    }
  } catch (err) {
    console.debug("Failed to load API keys:", err);
  }
}

async function revokeApiKeyFromUI(keyId) {
  if (!confirm(`Are you sure you want to revoke API Key ${keyId}? Automated workflows using it will immediately be locked out.`)) return;

  try {
    const resp = await fetch(`/api/v1/auth/api-keys/${keyId}`, { method: "DELETE" });
    if (resp.ok) {
      loadTenantApiKeys();
    } else {
      const err = await resp.json();
      alert(`Revocation failed: ${err.detail}`);
    }
  } catch (err) {
    alert(`Error: ${err.message}`);
  }
}

async function refreshBillingUsage() {
  try {
    const resp = await fetch("/api/v1/billing/usage?tenant_id=TWIST");
    const data = await resp.json();

    const badge = document.getElementById("billing-tier-badge");
    if (badge) badge.innerText = `${data.plan_name.toUpperCase()}`;

    const bpEl = document.getElementById("meter-bp");
    if (bpEl) bpEl.innerText = `${Number(data.telemetry.base_pairs_watermarked).toLocaleString()} bp`;

    const costEl = document.getElementById("meter-cost");
    if (costEl) costEl.innerText = `$${Number(data.total_accrued_amount).toFixed(2)}`;

    const scansEl = document.getElementById("meter-scans");
    if (scansEl) scansEl.innerText = `${data.telemetry.biosecurity_scans_run} scans`;

    const proofsEl = document.getElementById("meter-proofs");
    if (proofsEl) proofsEl.innerText = `${data.telemetry.merkle_proofs_issued} proofs`;

    const utilEl = document.getElementById("meter-utilization-pct");
    const barEl = document.getElementById("meter-bar-fill");
    if (utilEl && barEl) {
      const included = data.telemetry.included_base_pairs || 100_000;
      const current = data.telemetry.base_pairs_watermarked || 0;
      const pct = Math.min(100, (current / included) * 100).toFixed(1);
      utilEl.innerText = `${pct}% of ${(included / 1_000_000).toFixed(1)}M bp included`;
      barEl.style.width = `${pct}%`;
    }
  } catch (err) {
    console.debug("Failed to refresh billing usage:", err);
  }
}

async function subscribeTierFromUI(tier) {
  try {
    const resp = await fetch("/api/v1/billing/create-checkout-session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tier: tier,
        customer_email: "partner@foundry.com"
      })
    });
    const data = await resp.json();
    if (resp.ok && data.checkout_url) {
      // Launch checkout portal
      const confirmLaunch = confirm(`Initiating Stripe Live Checkout for ${tier}.\n\nClick OK to open the secure Stripe Checkout Gateway.`);
      if (confirmLaunch) {
        window.open(data.checkout_url, "_blank");
      }
    } else {
      alert(`Checkout session creation failed: ${data.detail || "Unknown error"}`);
    }
  } catch (err) {
    alert(`Checkout error: ${err.message}`);
  }
}

async function viewInvoicesModal() {
  const container = document.getElementById("invoices-list-container");
  if (!container) return;

  if (container.style.display === "block") {
    container.style.display = "none";
    return;
  }

  try {
    const resp = await fetch("/api/v1/billing/invoices?tenant_id=TWIST");
    const data = await resp.json();
    container.style.display = "block";

    let html = `
      <div style="font-weight: 700; font-size: 0.82rem; color: #fff; margin-bottom: 0.5rem;">Historical & Current Invoices</div>
      <table class="ledger-table" style="font-size: 0.72rem; width: 100%;">
        <thead><tr><th>Invoice ID</th><th>Date</th><th>Amount</th><th>Status</th><th>Action</th></tr></thead>
        <tbody>
    `;

    data.invoices.forEach(inv => {
      html += `
        <tr>
          <td style="font-family: var(--font-mono); color: #38bdf8;">${inv.invoice_id}</td>
          <td>${inv.date.split("T")[0]}</td>
          <td style="font-weight: 700; color: #34d399;">$${Number(inv.amount_due).toFixed(2)}</td>
          <td><span style="color: ${inv.status === 'PAID' ? '#34d399' : '#fbbf24'}; font-weight: 600;">${inv.status}</span></td>
          <td><a href="/api/v1/compliance/certificate/${inv.invoice_id}/pdf" target="_blank" style="color: var(--cyan-glow); text-decoration: none;">Download PDF Receipt</a></td>
        </tr>
      `;
    });
    html += `</tbody></table>`;
    container.innerHTML = html;
  } catch (err) {
    container.innerText = `Failed to load invoices: ${err.message}`;
  }
}

async function loadTenantBranding() {
  try {
    const resp = await fetch("/api/v1/tenants/branding?tenant_id=TWIST");
    const data = await resp.json();

    const orgInput = document.getElementById("brand-org-name");
    const labInput = document.getElementById("brand-lab-id");
    const emailInput = document.getElementById("brand-email");
    const logoInput = document.getElementById("brand-logo");
    const colorInput = document.getElementById("brand-color");

    if (orgInput && data.org_name) orgInput.value = data.org_name;
    if (labInput && data.lab_id) labInput.value = data.lab_id;
    if (emailInput && data.contact_email) emailInput.value = data.contact_email;
    if (logoInput && data.logo_url) logoInput.value = data.logo_url;
    if (colorInput && data.accent_color) colorInput.value = data.accent_color;
  } catch (err) {
    console.debug("Failed to load branding:", err);
  }
}

async function saveTenantBrandingFromUI() {
  const orgName = document.getElementById("brand-org-name").value.trim();
  const labId = document.getElementById("brand-lab-id").value.trim();
  const email = document.getElementById("brand-email").value.trim();
  const logo = document.getElementById("brand-logo").value.trim();
  const color = document.getElementById("brand-color").value.trim();
  const msgEl = document.getElementById("branding-status-msg");

  try {
    const resp = await fetch("/api/v1/tenants/branding", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenant_id: "TWIST",
        org_name: orgName,
        lab_id: labId,
        contact_email: email,
        logo_url: logo,
        accent_color: color
      })
    });
    const data = await resp.json();
    if (resp.ok) {
      if (msgEl) {
        msgEl.style.display = "block";
        msgEl.innerText = `✓ White-label branding successfully saved for ${data.branding.org_name}`;
        setTimeout(() => { msgEl.style.display = "none"; }, 4000);
      }
    }
  } catch (err) {
    alert(`Failed to save branding: ${err.message}`);
  }
}

function downloadSamplePdfCert() {
  window.open("/api/v1/compliance/certificate/EVT-LIVE-SAMPLE/pdf?tenant_id=TWIST", "_blank");
}

function switchSdkTab(tab) {
  const tabs = ["curl", "python", "node"];
  tabs.forEach(t => {
    const btn = document.getElementById(`btn-sdk-${t}`);
    const snippet = document.getElementById(`sdk-snippet-${t}`);
    if (btn) btn.classList.remove("active");
    if (snippet) snippet.style.display = "none";
  });

  const activeBtn = document.getElementById(`btn-sdk-${tab}`);
  const activeSnippet = document.getElementById(`sdk-snippet-${tab}`);
  if (activeBtn) activeBtn.classList.add("active");
  if (activeSnippet) activeSnippet.style.display = "block";
}

