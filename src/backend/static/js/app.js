// Sample Diffs for Interactive Exploration
const EXAMPLE_DIFFS = {
    sql: `diff --git a/src/db/queries.py b/src/db/queries.py
index e69de29..9bc8d4d 100644
--- a/src/db/queries.py
+++ b/src/db/queries.py
@@ -12,4 +12,8 @@ def get_user_profile(username: str):
-    return db.fetch("SELECT * FROM users WHERE username = 'admin'")
+    # Load profile dynamically based on input
+    query = "SELECT * FROM users WHERE username = '" + username + "'"
+    return db.execute_raw(query)`,

    secrets: `diff --git a/src/auth/session.py b/src/auth/session.py
index a543db2..8c26f7a 100644
--- a/src/auth/session.py
+++ b/src/auth/session.py
@@ -5,3 +5,6 @@ class SessionManager:
     def __init__(self):
         self.session_store = {}
+        # Temporary key for test environments
+        const stripeKey = process.env.STRIPE_PUBLIC_KEY;
+        self.token_expiry = 3600`,

    pickle: `diff --git a/src/utils/serializer.py b/src/utils/serializer.py
index 1b5d12a..b923c8e 100644
--- a/src/utils/serializer.py
+++ b/src/utils/serializer.py
@@ -1,5 +1,9 @@
-import json
+import pickle
 
 def load_user_data(payload_bytes: bytes):
-    return json.loads(payload_bytes)
+    # Speed optimization: load fast python objects directly
+    return pickle.loads(payload_bytes)`,

    clean: `diff --git a/src/backend/utils.py b/src/backend/utils.py
index e69de29..9bc8d4d 100644
--- a/src/backend/utils.py
+++ b/src/backend/utils.py
@@ -1,5 +1,8 @@
+import hmac
+
 def verify_signature(data: bytes, expected: str, secret: str) -> bool:
-    return hmac.new(secret.encode(), data).hexdigest() == expected
+    # Timing attack resistant comparison
+    actual = hmac.new(secret.encode("utf-8"), data, "sha256").hexdigest()
+    return hmac.compare_digest(actual, expected)`
};

// Application State
let findings = [];
let filteredFindings = [];

// DOM Elements
const apiKeyInput = document.getElementById('apiKey');
const demoModeCheckbox = document.getElementById('demoMode');
const diffInput = document.getElementById('diffInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const btnText = document.getElementById('btnText');
const btnSpinner = document.getElementById('btnSpinner');
const findingsWrapper = document.getElementById('findingsWrapper');
const searchInput = document.getElementById('searchInput');
const severityFilter = document.getElementById('severityFilter');
const owaspChart = document.getElementById('owaspChart');

// Stats Counters
const countCritical = document.getElementById('countCritical');
const countHigh = document.getElementById('countHigh');
const countMedium = document.getElementById('countMedium');
const countLow = document.getElementById('countLow');

// Init application
document.addEventListener('DOMContentLoaded', () => {
    // Load config from localStorage
    const savedKey = localStorage.getItem('cs_api_key');
    if (savedKey) {
        apiKeyInput.value = savedKey;
    }
    
    const savedDemoMode = localStorage.getItem('cs_demo_mode');
    if (savedDemoMode !== null) {
        demoModeCheckbox.checked = savedDemoMode === 'true';
    }

    // Event listeners
    apiKeyInput.addEventListener('input', (e) => {
        localStorage.setItem('cs_api_key', e.target.value.trim());
        if (e.target.value.trim()) {
            demoModeCheckbox.checked = false;
            localStorage.setItem('cs_demo_mode', 'false');
        }
    });

    demoModeCheckbox.addEventListener('change', (e) => {
        localStorage.setItem('cs_demo_mode', e.target.checked);
        if (e.target.checked) {
            apiKeyInput.value = '';
            localStorage.removeItem('cs_api_key');
        }
    });

    analyzeBtn.addEventListener('click', performAnalysis);
    searchInput.addEventListener('input', applyFilters);
    severityFilter.addEventListener('change', applyFilters);

    // Initial example
    loadExample('sql');
});

// Load an example diff to the textarea
window.loadExample = function(type) {
    if (EXAMPLE_DIFFS[type]) {
        diffInput.value = EXAMPLE_DIFFS[type];
    }
};

// Perform static code analysis
async fn performAnalysis() {
    const diffText = diffInput.value.trim();
    if (!diffText) {
        alert('Please paste or load a git diff before running the scan.');
        return;
    }

    // Set UI loading state
    setLoading(true);

    const headers = {
        'Content-Type': 'application/json'
    };

    const key = apiKeyInput.value.trim();
    if (key) {
        headers['X-Anthropic-API-Key'] = key;
    }

    try {
        const response = await fetch('/api/v1/analyze', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ diff: diffText })
        });

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.detail || 'Analysis request failed.');
        }

        const data = await response.json();
        findings = data.findings || [];
        applyFilters();
        renderStats();
        renderOwaspBreakdown();
    } catch (err) {
        console.error(err);
        showError(err.message);
    } finally {
        setLoading(false);
    }
}

function setLoading(isLoading) {
    if (isLoading) {
        analyzeBtn.disabled = true;
        btnText.classList.add('hidden');
        btnSpinner.classList.remove('hidden');
    } else {
        analyzeBtn.disabled = false;
        btnText.classList.remove('hidden');
        btnSpinner.classList.add('hidden');
    }
}

// Render summary cards
function renderStats() {
    const stats = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    findings.forEach(f => {
        if (stats[f.severity] !== undefined) {
            stats[f.severity]++;
        }
    });

    // Update dom counters
    countCritical.textContent = stats.Critical;
    countHigh.textContent = stats.High;
    countMedium.textContent = stats.Medium;
    countLow.textContent = stats.Low;
}

// Render finding cards dynamically
function renderFindings() {
    findingsWrapper.innerHTML = '';

    if (filteredFindings.length === 0) {
        findingsWrapper.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-circle-check empty-icon" style="color: #10b981;"></i>
                <h3>No Vulnerabilities Found</h3>
                <p>Your filter settings returned no findings, or the code is verified clean.</p>
            </div>
        `;
        return;
    }

    filteredFindings.forEach((finding, index) => {
        const card = document.createElement('div');
        card.className = 'finding-card';
        card.id = `finding-card-${index}`;

        const severityLower = finding.severity.toLowerCase();

        // Convert code block format
        const codeRemediation = finding.remediation.replace(/```[a-z]*\n/g, '').replace(/```/g, '');

        card.innerHTML = `
            <div class="finding-head" onclick="toggleCard(${index})">
                <div class="finding-head-left">
                    <span class="severity-badge ${severityLower}">${finding.severity}</span>
                    <div class="finding-title-block">
                        <span class="finding-title">${finding.vulnerability}</span>
                        <div class="finding-meta">
                            <span class="finding-file-icon"><i class="fa-regular fa-file-code"></i></span>
                            <span class="finding-filename">${finding.filename}</span>
                            <span class="finding-divider">|</span>
                            <span class="finding-line">Line ${finding.line_number}</span>
                        </div>
                    </div>
                </div>
                <i class="fa-solid fa-chevron-down finding-toggle-icon"></i>
            </div>
            <div class="finding-detail" id="finding-detail-${index}">
                <div class="finding-desc">${finding.description}</div>
                <div class="finding-section-title"><i class="fa-solid fa-tag"></i> OWASP Category</div>
                <div class="finding-desc" style="font-weight: 500;">${finding.owasp_category}</div>
                <div class="finding-section-title"><i class="fa-solid fa-code-commit"></i> Remediation Recommendation</div>
                <div class="remediation-code">
                    <pre><code>${escapeHtml(codeRemediation)}</code></pre>
                </div>
            </div>
        `;
        findingsWrapper.appendChild(card);
    });
}

// Toggle Finding Card Expand/Collapse
window.toggleCard = function(index) {
    const card = document.getElementById(`finding-card-${index}`);
    card.classList.toggle('expanded');
};

// Filter logic
function applyFilters() {
    const searchVal = searchInput.value.toLowerCase().trim();
    const severityVal = severityFilter.value;

    filteredFindings = findings.filter(f => {
        const matchesSearch = f.filename.toLowerCase().includes(searchVal) || 
                              f.vulnerability.toLowerCase().includes(searchVal) ||
                              f.description.toLowerCase().includes(searchVal);
        
        const matchesSeverity = severityVal === 'all' || f.severity.toLowerCase() === severityVal;
        
        return matchesSearch && matchesSeverity;
    });

    renderFindings();
}

// Render OWASP category metrics breakdown chart
function renderOwaspBreakdown() {
    owaspChart.innerHTML = '';
    
    if (findings.length === 0) {
        owaspChart.innerHTML = `
            <div class="empty-state-mini">
                <p>Run analysis to populate charts</p>
            </div>
        `;
        return;
    }

    const counts = {};
    findings.forEach(f => {
        const cat = f.owasp_category || 'Other / General';
        counts[cat] = (counts[cat] || 0) + 1;
    });

    const maxCount = Math.max(...Object.values(counts));
    
    const listContainer = document.createElement('div');
    listContainer.className = 'owasp-list';

    Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .forEach(([category, count]) => {
            const percentage = (count / maxCount) * 100;
            const barItem = document.createElement('div');
            barItem.className = 'owasp-bar-item';
            barItem.innerHTML = `
                <div class="owasp-bar-info">
                    <span class="owasp-bar-name">${category}</span>
                    <span class="owasp-bar-count">${count} ${count === 1 ? 'finding' : 'findings'}</span>
                </div>
                <div class="owasp-bar-track">
                    <div class="owasp-bar-fill" style="width: ${percentage}%"></div>
                </div>
            `;
            listContainer.appendChild(barItem);
        });

    owaspChart.appendChild(listContainer);
}

// HTML Escaper helper
function escapeHtml(string) {
    return String(string)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Show error utility
function showError(message) {
    findingsWrapper.innerHTML = `
        <div class="empty-state" style="color: var(--color-critical);">
            <i class="fa-solid fa-circle-exclamation empty-icon" style="color: var(--color-critical); opacity: 1;"></i>
            <h3>Analysis Failed</h3>
            <p>${message}</p>
        </div>
    `;
}
