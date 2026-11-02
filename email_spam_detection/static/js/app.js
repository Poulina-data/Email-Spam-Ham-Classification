/**
 * AegisMail AI — Frontend Reactive Controller & Threat Visualizations
 */

document.addEventListener("DOMContentLoaded", () => {
  // Global State
  let currentSensitivity = 0.5;
  let chartDoughnut = null;
  let chartKeywords = null;
  let quarantinedCache = [];

  // DOM Elements
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");
  const toastContainer = document.getElementById("toast-container");
  const quarantineCountBadge = document.getElementById("quarantine-count-badge");
  const activeQuarantineCounter = document.getElementById("active-quarantine-counter");

  // Email Templates
  const emailTemplates = {
    paypal_phish: {
      sender: "security-alert@verify-paypal-service.com",
      subject: "URGENT: Your PayPal account has been limited! Immediate action required",
      body: "Dear Customer,\n\nWe detected suspicious login activity from an unknown IP address. Your funds and debit card have been temporarily frozen.\n\nPlease authenticate your identity within 24 hours at our secure portal: http://paypal-secure-verify.biz/restore\n\nFailure to verify will lead to permanent account suspension."
    },
    lottery_scam: {
      sender: "claim-center@intl-sweepstakes-reward.org",
      subject: "CONGRATULATIONS! You have won $1,500,000 cash prize",
      body: "Winning Notification:\n\nYou have been selected as our grand award prize winner! Your email won a guaranteed cash payout of $1,500,000. Contact our claim collection agent mob ringtone await collection right now to receive your wire transfer.\n\nReply with your full bank details and phone number immediately."
    },
    it_phish: {
      sender: "support@corp-remote-office365-auth.net",
      subject: "Office 365: Your email password expires today",
      body: "System Alert:\n\nYour corporate Microsoft 365 credentials will expire in 3 hours. To maintain access to your corporate email, documents, and teams chat, please keep your existing password by logging in below:\n\nhttp://office365-renew-auth.xyz/login\n\nIT Support Helpdesk"
    },
    clean_sprint: {
      sender: "david.miller@acme-software.com",
      subject: "Sprint 24 Retrospective & Q1 Roadmap Sync",
      body: "Hi team,\n\nGreat work closing out Sprint 24 today! We completed 48 story points and reduced our bug backlog by 35%.\n\nPlease find attached the agenda for tomorrow's retrospective at 11:00 AM in Conference Room B. We will also discuss the Q1 delivery roadmap.\n\nBest regards,\nDavid Miller"
    },
    clean_order: {
      sender: "auto-confirm@amazon.com",
      subject: "Your Amazon.com order #114-8923741 has shipped!",
      body: "Hello,\n\nWe thought you'd like to know that your order containing 'Logitech MX Master 3S Wireless Mouse' has shipped and is on track for delivery tomorrow by 8 PM.\n\nYou can track your package anytime directly from your orders page.\n\nThank you for shopping with us!"
    }
  };

  // =========================================================================
  // Tab Switching
  // =========================================================================
  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");
      tabButtons.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetPane = document.getElementById(targetId);
      if (targetPane) {
        targetPane.classList.add("active");
      }

      // Tab specific triggers
      if (targetId === "tab-quarantine") {
        fetchQuarantine();
      } else if (targetId === "tab-pipeline") {
        fetchModelInfo();
      } else if (targetId === "tab-analytics") {
        fetchAnalytics();
      } else if (targetId === "tab-sandbox") {
        fetchRules();
      }
    });
  });

  // =========================================================================
  // Toast Notifications
  // =========================================================================
  function showToast(message, type = "info") {
    const toast = document.createElement("div");
    toast.className = `toast-item toast-${type}`;

    let iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
    if (type === "success") {
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
    } else if (type === "danger") {
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
    }

    toast.innerHTML = `<span>${iconSvg}</span><span>${message}</span>`;
    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(50px)";
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  // =========================================================================
  // Template Click Handlers
  // =========================================================================
  document.querySelectorAll(".template-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const templateKey = btn.getAttribute("data-template");
      const data = emailTemplates[templateKey];
      if (data) {
        document.getElementById("scan-sender").value = data.sender;
        document.getElementById("scan-subject").value = data.subject;
        document.getElementById("scan-body").value = data.body;
        showToast(`Loaded template: "${data.subject.substring(0, 32)}..."`, "info");
      }
    });
  });

  // Clear Form
  document.getElementById("btn-clear-scan")?.addEventListener("click", () => {
    document.getElementById("scan-sender").value = "";
    document.getElementById("scan-subject").value = "";
    document.getElementById("scan-body").value = "";
    document.getElementById("results-placeholder").style.display = "flex";
    document.getElementById("results-content").style.display = "none";
  });

  // =========================================================================
  // Single Email Scan API Call
  // =========================================================================
  const scanForm = document.getElementById("email-scan-form");
  scanForm?.addEventListener("submit", async (e) => {
    e.preventDefault();

    const sender = document.getElementById("scan-sender").value.trim();
    const subject = document.getElementById("scan-subject").value.trim();
    const body = document.getElementById("scan-body").value.trim();

    if (!body) {
      showToast("Please enter email body text to analyze", "danger");
      return;
    }

    const btnSubmit = document.getElementById("btn-analyze-submit");
    const originalBtnHtml = btnSubmit.innerHTML;
    btnSubmit.disabled = true;
    btnSubmit.innerHTML = `
      <span class="radar-scan-box" style="width:20px;height:20px;margin-right:6px;">
        <span class="radar-circle"></span>
      </span> Analyzing NLP Features...
    `;

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sender,
          subject,
          body,
          threshold: currentSensitivity
        })
      });

      const responseData = await res.json();
      if (!responseData.success) {
        throw new Error(responseData.detail || "Scan request failed");
      }

      renderScanResults(responseData.data);
      updateQuarantineBadge();
      showToast(
        responseData.data.label === "spam"
          ? "🚨 Threat Detected! Email isolated in Quarantine."
          : "✅ Email Verified as Clean (Ham).",
        responseData.data.label === "spam" ? "danger" : "success"
      );
    } catch (err) {
      console.error(err);
      showToast(`Error analyzing email: ${err.message}`, "danger");
    } finally {
      btnSubmit.disabled = false;
      btnSubmit.innerHTML = originalBtnHtml;
    }
  });

  // Render Single Scan Results
  function renderScanResults(data) {
    document.getElementById("results-placeholder").style.display = "none";
    const content = document.getElementById("results-content");
    content.style.display = "block";

    // Verdict Banner
    const banner = document.getElementById("result-verdict-banner");
    const verdictTitle = document.getElementById("result-verdict-title");
    const verdictSubtitle = document.getElementById("result-verdict-subtitle");
    const verdictIcon = document.getElementById("result-verdict-icon");

    banner.className = `verdict-banner verdict-${data.label}`;

    if (data.label === "spam") {
      verdictTitle.textContent = "THREAT DETECTED: MALICIOUS SPAM";
      verdictSubtitle.textContent = `Identified as ${data.risk_tier} (Threat Score: ${data.threat_score}/100). Quarantined automatically.`;
      verdictIcon.innerHTML = `<svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>`;
    } else {
      verdictTitle.textContent = "LEGITIMATE EMAIL VERIFIED (HAM)";
      verdictSubtitle.textContent = `Clean correspondence (Threat Score: ${data.threat_score}/100). Safe for inbox delivery.`;
      verdictIcon.innerHTML = `<svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
    }

    // Probability Bars
    const spamPct = (data.spam_probability * 100).toFixed(1);
    const hamPct = (data.ham_probability * 100).toFixed(1);

    document.getElementById("bar-spam-fill").style.width = `${spamPct}%`;
    document.getElementById("bar-ham-fill").style.width = `${hamPct}%`;
    document.getElementById("prob-spam-text").textContent = `${spamPct}%`;
    document.getElementById("prob-ham-text").textContent = `${hamPct}%`;

    // Explainability Features (Top N-Grams)
    const featuresWrap = document.getElementById("result-features-wrap");
    featuresWrap.innerHTML = "";
    if (data.top_features && data.top_features.length > 0) {
      data.top_features.forEach(feat => {
        const pill = document.createElement("span");
        const isSpam = feat.leans === "spam" || feat.score > 0;
        pill.className = `feature-pill ${isSpam ? "spam-impact" : "ham-impact"}`;
        pill.innerHTML = `
          <span>${feat.word}</span>
          <span class="feature-score">${feat.score > 0 ? "+" : ""}${feat.score}</span>
        `;
        pill.title = `Impact: ${isSpam ? 'Pushes toward Spam' : 'Anchors as Ham'} (Log Odds: ${feat.score})`;
        featuresWrap.appendChild(pill);
      });
    } else {
      featuresWrap.innerHTML = `<span style="font-size:0.8rem;color:var(--text-muted);">No influential vocabulary n-grams matched.</span>`;
    }

    // Security Heuristics Signals
    const signalsList = document.getElementById("result-signals-list");
    signalsList.innerHTML = "";
    if (data.heuristic_signals && data.heuristic_signals.length > 0) {
      data.heuristic_signals.forEach(sig => {
        const row = document.createElement("div");
        row.className = "signal-row";
        row.innerHTML = `
          <span class="severity-tag ${sig.severity}">${sig.severity}</span>
          <div>
            <strong style="color:var(--text-primary);">${sig.type}:</strong>
            <span style="color:var(--text-secondary); margin-left:4px;">${sig.detail}</span>
          </div>
        `;
        signalsList.appendChild(row);
      });
    } else {
      signalsList.innerHTML = `
        <div class="signal-row" style="background:rgba(16,185,129,0.06);border-color:rgba(16,185,129,0.2);">
          <span class="severity-tag" style="background:rgba(16,185,129,0.2);color:var(--accent-emerald);">CLEAN</span>
          <span style="color:var(--text-secondary);">No suspicious links, urgency triggers, or spoofing patterns detected.</span>
        </div>
      `;
    }

    // Cleaned spaCy text snippet
    const cleanSnippet = document.getElementById("result-cleaned-snippet");
    if (cleanSnippet) {
      cleanSnippet.textContent = data.clean_email || "(Empty)";
    }
  }

  // =========================================================================
  // Quarantine Vault Operations
  // =========================================================================
  async function fetchQuarantine() {
    const statusFilter = document.getElementById("quarantine-status-filter")?.value || "ALL";
    const searchQuery = document.getElementById("quarantine-search-input")?.value.trim() || "";
    const tbody = document.getElementById("quarantine-table-body");

    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:2rem;color:var(--text-muted);">Loading quarantine records...</td></tr>`;

    try {
      const url = `/api/quarantine?status=${encodeURIComponent(statusFilter)}&search=${encodeURIComponent(searchQuery)}`;
      const res = await fetch(url);
      const resData = await res.json();

      if (!resData.success) throw new Error("Failed to load quarantine");
      quarantinedCache = resData.data;

      // Update counters
      const activeCount = quarantinedCache.filter(item => item.status === "QUARANTINED").length;
      if (quarantineCountBadge) quarantineCountBadge.textContent = activeCount;
      if (activeQuarantineCounter) activeQuarantineCounter.textContent = `${activeCount} threats`;

      if (quarantinedCache.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:3rem;color:var(--text-muted);">No quarantined emails matching filter.</td></tr>`;
        return;
      }

      tbody.innerHTML = "";
      quarantinedCache.forEach(item => {
        const tr = document.createElement("tr");
        const dateStr = new Date(item.timestamp).toLocaleString();
        const probPct = (item.spam_probability * 100).toFixed(1);
        const isReleased = item.status === "RELEASED";

        tr.innerHTML = `
          <td style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted);">#${item.id}</td>
          <td style="font-size:0.8rem;white-space:nowrap;">${dateStr}</td>
          <td>
            <div style="font-weight:600;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${item.sender}">
              ${item.sender || "(Unknown)"}
            </div>
          </td>
          <td>
            <div style="font-weight:500;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${item.subject}">
              ${item.subject || "(No Subject)"}
            </div>
          </td>
          <td>
            <span style="font-weight:700;color:var(--accent-rose);">${probPct}%</span>
          </td>
          <td>
            <span class="table-badge ${isReleased ? 'badge-released' : 'badge-quarantined'}">
              ${item.status}
            </span>
          </td>
          <td>
            <div class="action-btn-group">
              <button class="action-icon-btn btn-inspect" data-id="${item.id}" title="Inspect Details">
                <svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              </button>
              ${!isReleased ? `
                <button class="action-icon-btn btn-release" data-id="${item.id}" title="Release to Inbox">
                  <svg viewBox="0 0 24 24"><path d="M5 12h14"/><path d="M12 5l7 7-7 7"/></svg>
                </button>
              ` : ''}
              <button class="action-icon-btn btn-delete" data-id="${item.id}" title="Purge Record">
                <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              </button>
            </div>
          </td>
        `;
        tbody.appendChild(tr);
      });

      // Bind row actions
      attachQuarantineRowListeners();
    } catch (err) {
      console.error(err);
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:2rem;color:var(--accent-rose);">Error: ${err.message}</td></tr>`;
    }
  }

  function attachQuarantineRowListeners() {
    // Inspect Modal
    document.querySelectorAll(".btn-inspect").forEach(btn => {
      btn.addEventListener("click", () => {
        const id = parseInt(btn.getAttribute("data-id"));
        const item = quarantinedCache.find(x => x.id === id);
        if (item) openInspectModal(item);
      });
    });

    // Release
    document.querySelectorAll(".btn-release").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = parseInt(btn.getAttribute("data-id"));
        if (!confirm(`Release email #${id} from quarantine to inbox?`)) return;

        try {
          const res = await fetch(`/api/quarantine/${id}/release`, { method: "POST" });
          const d = await res.json();
          if (d.success) {
            showToast(`Email #${id} released to inbox.`, "success");
            fetchQuarantine();
          }
        } catch (e) {
          showToast(`Release failed: ${e.message}`, "danger");
        }
      });
    });

    // Delete
    document.querySelectorAll(".btn-delete").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = parseInt(btn.getAttribute("data-id"));
        if (!confirm(`Permanently purge quarantine record #${id}?`)) return;

        try {
          const res = await fetch(`/api/quarantine/${id}`, { method: "DELETE" });
          const d = await res.json();
          if (d.success) {
            showToast(`Quarantine record #${id} purged.`, "info");
            fetchQuarantine();
          }
        } catch (e) {
          showToast(`Purge failed: ${e.message}`, "danger");
        }
      });
    });
  }

  // Quarantine Search & Filter change events
  document.getElementById("quarantine-status-filter")?.addEventListener("change", fetchQuarantine);
  let searchDebounceTimer;
  document.getElementById("quarantine-search-input")?.addEventListener("input", () => {
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(fetchQuarantine, 300);
  });

  // Export CSV
  document.getElementById("btn-export-quarantine")?.addEventListener("click", () => {
    window.location.href = "/api/quarantine/export";
    showToast("Exporting Quarantine CSV archive...", "info");
  });

  // Update badge counter helper
  async function updateQuarantineBadge() {
    try {
      const res = await fetch("/api/quarantine?status=QUARANTINED");
      const d = await res.json();
      if (d.success && quarantineCountBadge) {
        quarantineCountBadge.textContent = d.count;
      }
    } catch (_) {}
  }

  // =========================================================================
  // Inspect Modal
  // =========================================================================
  const inspectModal = document.getElementById("inspect-modal");
  const modalCloseBtn = document.getElementById("modal-close-btn");
  const modalDismissBtn = document.getElementById("modal-dismiss-btn");

  function openInspectModal(item) {
    document.getElementById("modal-meta-sender").textContent = item.sender || "Unknown";
    document.getElementById("modal-meta-date").textContent = new Date(item.timestamp).toLocaleString();
    document.getElementById("modal-meta-subject").textContent = item.subject || "(No Subject)";
    document.getElementById("modal-meta-score").textContent = `${(item.spam_probability * 100).toFixed(1)}%`;
    document.getElementById("modal-meta-status").textContent = item.status;
    document.getElementById("modal-meta-reason").textContent = item.reason || "High probability spam pattern";
    document.getElementById("modal-body-content").textContent = item.body;

    inspectModal.classList.add("open");
  }

  [modalCloseBtn, modalDismissBtn].forEach(btn => {
    btn?.addEventListener("click", () => {
      inspectModal.classList.remove("open");
    });
  });

  inspectModal?.addEventListener("click", (e) => {
    if (e.target === inspectModal) inspectModal.classList.remove("open");
  });

  // =========================================================================
  // Batch Email Scanner
  // =========================================================================
  const btnProcessBatch = document.getElementById("btn-process-batch");
  const batchTextarea = document.getElementById("batch-textarea");
  const fileInput = document.getElementById("batch-file-input");
  const uploadDropzone = document.getElementById("batch-upload-dropzone");

  uploadDropzone?.addEventListener("click", () => fileInput.click());

  fileInput?.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (evt) => {
      batchTextarea.value = evt.target.result;
      showToast(`Loaded file: ${file.name}`, "info");
    };
    reader.readAsText(file);
  });

  btnProcessBatch?.addEventListener("click", async () => {
    const rawContent = batchTextarea.value.trim();
    if (!rawContent) {
      showToast("Please paste email lines or upload a CSV file", "danger");
      return;
    }

    // Parse lines or paragraphs
    const lines = rawContent.split(/\r?\n/).filter(l => l.trim().length > 5);
    const emails = lines.map((line, idx) => {
      return {
        sender: `sender_${idx + 1}@external.com`,
        subject: `Batch Inspection #${idx + 1}`,
        body: line
      };
    });

    if (emails.length === 0) {
      showToast("No valid email content detected in input", "danger");
      return;
    }

    const progressContainer = document.getElementById("batch-progress-bar");
    const progressFill = document.getElementById("batch-progress-fill");
    progressContainer.style.display = "block";
    progressFill.style.width = "20%";

    btnProcessBatch.disabled = true;

    try {
      progressFill.style.width = "60%";
      const res = await fetch("/api/scan-batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          emails,
          threshold: currentSensitivity
        })
      });

      progressFill.style.width = "100%";
      const resData = await res.json();
      if (!resData.success) throw new Error("Batch processing failed");

      renderBatchResults(resData.data);
      updateQuarantineBadge();
      showToast(`Batch Completed: ${resData.data.total_processed} emails analyzed!`, "success");
    } catch (err) {
      console.error(err);
      showToast(`Batch Error: ${err.message}`, "danger");
    } finally {
      setTimeout(() => {
        progressContainer.style.display = "none";
        progressFill.style.width = "0%";
        btnProcessBatch.disabled = false;
      }, 600);
    }
  });

  function renderBatchResults(data) {
    document.getElementById("batch-results-wrap").style.display = "block";
    document.getElementById("batch-stat-total").textContent = data.total_processed;
    document.getElementById("batch-stat-spam").textContent = data.spam_detected;
    document.getElementById("batch-stat-ham").textContent = data.ham_verified;
    document.getElementById("batch-stat-rate").textContent = `${data.threat_rate}%`;

    const tbody = document.getElementById("batch-table-body");
    tbody.innerHTML = "";

    data.results.forEach((item, idx) => {
      const tr = document.createElement("tr");
      const isSpam = item.label === "spam";
      tr.innerHTML = `
        <td style="font-family:var(--font-mono);font-size:0.75rem;">#${idx + 1}</td>
        <td>
          <div style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${item.body}">
            ${item.body}
          </div>
        </td>
        <td>
          <span class="table-badge ${isSpam ? 'badge-quarantined' : 'badge-released'}">
            ${item.label.toUpperCase()}
          </span>
        </td>
        <td style="font-weight:700;color:${isSpam ? 'var(--accent-rose)' : 'var(--accent-emerald)'};">
          ${(item.spam_probability * 100).toFixed(1)}%
        </td>
        <td>
          <span class="severity-tag ${item.risk_tier}">${item.risk_tier}</span>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  // =========================================================================
  // Tab 4: Model Pipeline & Architecture Explorer
  // =========================================================================
  async function fetchModelInfo() {
    try {
      const res = await fetch("/api/model-info");
      const resData = await res.json();
      if (!resData.success) throw new Error("Could not load pipeline details");

      const meta = resData.data;

      // Render 8 Stages
      const stagesContainer = document.getElementById("pipeline-stages-container");
      stagesContainer.innerHTML = "";

      meta.stages.forEach(stg => {
        const card = document.createElement("div");
        card.className = "stage-card";
        card.innerHTML = `
          <span class="stage-badge-num">STAGE ${stg.stage}</span>
          <h3>${stg.title}</h3>
          <span class="stage-file-pill">${stg.file}</span>
          <p>${stg.description}</p>
        `;
        stagesContainer.appendChild(card);
      });

      // Confusion Matrix Numbers
      const cm = meta.confusion_matrix;
      document.getElementById("cm-tp").textContent = cm.actual_spam_pred_spam;
      document.getElementById("cm-fn").textContent = cm.actual_spam_pred_ham;
      document.getElementById("cm-fp").textContent = cm.actual_ham_pred_spam;
      document.getElementById("cm-tn").textContent = cm.actual_ham_pred_ham;

      // Evaluation Metrics
      document.getElementById("metric-accuracy").textContent = `${(meta.metrics.overall_accuracy * 100).toFixed(1)}%`;
      document.getElementById("metric-precision").textContent = `${(meta.metrics.spam_precision * 100).toFixed(0)}%`;
      document.getElementById("metric-recall").textContent = `${(meta.metrics.spam_recall * 100).toFixed(0)}%`;
      document.getElementById("metric-f1").textContent = `${(meta.metrics.spam_f1_score * 100).toFixed(0)}%`;

      // Top Vocabulary Pills
      const spamVocabWrap = document.getElementById("top-spam-vocab-pills");
      const hamVocabWrap = document.getElementById("top-ham-vocab-pills");
      spamVocabWrap.innerHTML = "";
      hamVocabWrap.innerHTML = "";

      meta.top_spam_vocabulary.forEach(v => {
        const pill = document.createElement("span");
        pill.className = "feature-pill spam-impact";
        pill.innerHTML = `<span>${v.ngram}</span><span class="feature-score">+${v.log_ratio}</span>`;
        spamVocabWrap.appendChild(pill);
      });

      meta.top_ham_vocabulary.forEach(v => {
        const pill = document.createElement("span");
        pill.className = "feature-pill ham-impact";
        pill.innerHTML = `<span>${v.ngram}</span><span class="feature-score">${v.log_ratio}</span>`;
        hamVocabWrap.appendChild(pill);
      });
    } catch (err) {
      console.error(err);
      showToast(`Model info error: ${err.message}`, "danger");
    }
  }

  // =========================================================================
  // Tab 5: Analytics Dashboard & Charts
  // =========================================================================
  async function fetchAnalytics() {
    try {
      const res = await fetch("/api/analytics");
      const resData = await res.json();
      if (!resData.success) throw new Error("Could not load analytics");

      const stats = resData.data;

      // Update KPI Counter Cards
      document.getElementById("kpi-total-scans").textContent = stats.total_scans;
      document.getElementById("kpi-spam-threats").textContent = stats.spam_count;
      document.getElementById("kpi-clean-ham").textContent = stats.ham_count;
      document.getElementById("kpi-detection-rate").textContent = `${stats.detection_rate}%`;

      // Render Charts
      renderCharts(stats);
    } catch (err) {
      console.error(err);
      showToast(`Analytics error: ${err.message}`, "danger");
    }
  }

  function renderCharts(stats) {
    if (typeof Chart === "undefined") return;

    // Doughnut Chart (Threat Distribution)
    const ctxDoughnut = document.getElementById("chart-doughnut")?.getContext("2d");
    if (ctxDoughnut) {
      if (chartDoughnut) chartDoughnut.destroy();

      const critical = stats.risk_breakdown["CRITICAL_SPAM"] || stats.spam_count || 0;
      const suspicious = stats.risk_breakdown["SUSPICIOUS"] || 0;
      const safe = stats.risk_breakdown["SAFE"] || stats.ham_count || 0;

      chartDoughnut = new Chart(ctxDoughnut, {
        type: "doughnut",
        data: {
          labels: ["Critical Threats", "Suspicious", "Safe (Ham)"],
          datasets: [{
            data: [critical, suspicious, safe],
            backgroundColor: ["#f43f5e", "#f59e0b", "#10b981"],
            borderColor: "#0f172a",
            borderWidth: 2,
            hoverOffset: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "bottom",
              labels: { color: "#94a3b8", font: { family: "Inter" } }
            }
          },
          cutout: "70%"
        }
      });
    }

    // Bar Chart (Top Threat Trigger Keywords)
    const ctxKeywords = document.getElementById("chart-keywords")?.getContext("2d");
    if (ctxKeywords) {
      if (chartKeywords) chartKeywords.destroy();

      chartKeywords = new Chart(ctxKeywords, {
        type: "bar",
        data: {
          labels: ["claim", "prize", "award", "urgent", "guarantee", "mob", "await", "ringtone"],
          datasets: [{
            label: "Log Likelihood Weight (Spam Pull)",
            data: [4.12, 3.89, 3.65, 3.42, 3.10, 2.95, 2.80, 2.72],
            backgroundColor: "rgba(6, 182, 212, 0.7)",
            borderColor: "#06b6d4",
            borderWidth: 1,
            borderRadius: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              grid: { color: "rgba(255, 255, 255, 0.05)" },
              ticks: { color: "#94a3b8" }
            },
            x: {
              grid: { display: false },
              ticks: { color: "#94a3b8" }
            }
          },
          plugins: {
            legend: { display: false }
          }
        }
      });
    }
  }

  // =========================================================================
  // Tab 6: Security Sandbox & Custom Rules
  // =========================================================================
  const sliderSensitivity = document.getElementById("slider-sensitivity");
  const sliderValueText = document.getElementById("slider-val-text");
  const sliderDescriptor = document.getElementById("slider-descriptor");

  sliderSensitivity?.addEventListener("input", (e) => {
    const val = parseFloat(e.target.value);
    currentSensitivity = val;
    sliderValueText.textContent = `${(val * 100).toFixed(0)}%`;

    if (val < 0.35) {
      sliderDescriptor.textContent = "Aggressive Mode: Flags borderline suspicious items as spam";
      sliderDescriptor.style.color = "var(--accent-amber)";
    } else if (val > 0.65) {
      sliderDescriptor.textContent = "Conservative Mode: Demands high confidence before quarantining";
      sliderDescriptor.style.color = "var(--accent-cyan)";
    } else {
      sliderDescriptor.textContent = "Balanced Mode: Standard MultinomialNB 50% decision boundary";
      sliderDescriptor.style.color = "var(--text-secondary)";
    }
  });

  async function fetchRules() {
    const tbody = document.getElementById("rules-table-body");
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:1.5rem;color:var(--text-muted);">Loading security rules...</td></tr>`;

    try {
      const res = await fetch("/api/rules");
      const d = await res.json();
      if (!d.success) throw new Error("Failed to load rules");

      if (d.data.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:2rem;color:var(--text-muted);">No custom rules defined yet.</td></tr>`;
        return;
      }

      tbody.innerHTML = "";
      d.data.forEach(rule => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td style="font-family:var(--font-mono);font-size:0.75rem;">#${rule.id}</td>
          <td><span style="font-weight:600;color:var(--accent-cyan);">${rule.rule_type}</span></td>
          <td style="font-family:var(--font-mono);font-size:0.82rem;">${rule.value}</td>
          <td><span class="table-badge ${rule.action === 'force_spam' ? 'badge-quarantined' : 'badge-released'}">${rule.action}</span></td>
          <td>
            <button class="action-icon-btn btn-delete-rule" data-id="${rule.id}" title="Delete Rule">
              <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });

      document.querySelectorAll(".btn-delete-rule").forEach(btn => {
        btn.addEventListener("click", async () => {
          const id = parseInt(btn.getAttribute("data-id"));
          try {
            const delRes = await fetch(`/api/rules/${id}`, { method: "DELETE" });
            const delData = await delRes.json();
            if (delData.success) {
              showToast(`Rule #${id} removed.`, "info");
              fetchRules();
            }
          } catch (e) {
            showToast(`Delete failed: ${e.message}`, "danger");
          }
        });
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--accent-rose);">${err.message}</td></tr>`;
    }
  }

  // Create Rule Form
  document.getElementById("create-rule-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();

    const rule_type = document.getElementById("rule-type").value;
    const value = document.getElementById("rule-value").value.trim();
    const action = document.getElementById("rule-action").value;

    if (!value) {
      showToast("Please specify a domain, email, or keyword value", "danger");
      return;
    }

    try {
      const res = await fetch("/api/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rule_type, value, action })
      });

      const d = await res.json();
      if (!d.success) throw new Error("Could not save rule");

      showToast(`Rule for "${value}" added successfully!`, "success");
      document.getElementById("rule-value").value = "";
      fetchRules();
    } catch (err) {
      showToast(`Rule Error: ${err.message}`, "danger");
    }
  });

  // Initial Badge Refresh
  updateQuarantineBadge();
});

