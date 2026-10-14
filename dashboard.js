// ============================================================
// THREAT VECTOR — DASHBOARD RISK RADAR & AI THREAT INSPECTOR
// ============================================================

(function() {
    let radarChart = null;

    const CATEGORY_KEYS = ['URGENCY', 'AUTHORITY', 'FAKELINKS', 'INCENTIVE', 'COERCION'];
    const CATEGORY_LABELS = ['⚡ Urgency', '👔 Authority', '🔗 Fake Links', '🎁 Incentive', '⚠️ Coercion'];

    function initRadar(profileData) {
        const ctx = document.getElementById('riskRadarChart');
        if (!ctx) return;

        const vulnValues = CATEGORY_KEYS.map(cat => {
            const stats = profileData.category_stats || {};
            return (stats[cat] && stats[cat].vuln) ? stats[cat].vuln : 0;
        });

        if (radarChart) radarChart.destroy();

        radarChart = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: CATEGORY_LABELS,
                datasets: [{
                    label: 'Vulnerability Index (%)',
                    data: vulnValues,
                    backgroundColor: 'rgba(37, 99, 235, 0.2)',
                    borderColor: '#2563EB',
                    pointBackgroundColor: '#0F2744',
                    pointBorderColor: '#FFFFFF',
                    pointHoverBackgroundColor: '#FFFFFF',
                    pointHoverBorderColor: '#0F2744',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        angleLines: { color: '#E2E8F0' },
                        grid: { color: '#E2E8F0' },
                        pointLabels: {
                            font: { size: 12, weight: '600', family: '-apple-system, BlinkMacSystemFont, Segoe UI, Roboto' },
                            color: '#0F2744'
                        },
                        suggestedMin: 0,
                        suggestedMax: 100,
                        ticks: { stepSize: 25, backdropColor: 'transparent' }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });

        renderVectorBars(profileData);
    }

    function renderVectorBars(profileData) {
        const container = document.getElementById('vector-progress-bars');
        if (!container) return;

        const stats = profileData.category_stats || {};
        let html = '';

        CATEGORY_KEYS.forEach((cat, idx) => {
            const label = CATEGORY_LABELS[idx];
            const data = stats[cat] || { total: 0, vuln: 0 };
            const vuln = data.vuln || 0;
            const barColor = vuln > 50 ? 'var(--accent-rose)' : (vuln > 25 ? 'var(--accent-amber)' : 'var(--accent-emerald)');

            html += `
                <div style="margin-bottom: 0.9rem;">
                    <div style="display: flex; justify-content: space-between; font-size: 0.88rem; font-weight: 600; margin-bottom: 0.25rem;">
                        <span>${label}</span>
                        <span style="color: ${barColor};">${vuln}% Vulnerability (${data.total || 0} drills)</span>
                    </div>
                    <div style="background: #E2E8F0; height: 8px; border-radius: 999px; overflow: hidden;">
                        <div style="background: ${barColor}; width: ${vuln}%; height: 100%; border-radius: 999px; transition: width 0.4s ease;"></div>
                    </div>
                </div>
            `;
        });

        container.innerHTML = html;
    }

    // Reset Data Handler
    const btnResetData = document.getElementById('btn-reset-data');
    if (btnResetData) {
        btnResetData.addEventListener('click', async () => {
            if (confirm('Are you sure you want to reset your audit log and risk profile?')) {
                try {
                    const res = await fetch('/api/reset', { method: 'POST' });
                    const data = await res.json();
                    if (data.success) {
                        window.location.reload();
                    }
                } catch (err) {
                    console.error('Reset failed:', err);
                }
            }
        });
    }

    // ============================================================
    // AI REAL-TIME THREAT & FILE INSPECTOR TOOL
    // ============================================================
    const modalBackdrop = document.getElementById('inspector-modal-backdrop');
    const btnCloseModal = document.getElementById('btn-close-inspector');
    const inspectorInput = document.getElementById('inspector-input');
    const btnRunInspect = document.getElementById('btn-run-inspect');
    const inspectorLoading = document.getElementById('inspector-loading');
    const inspectorResult = document.getElementById('inspector-result');
    const statusBanner = document.getElementById('inspector-status-banner');
    const statusIcon = document.getElementById('inspector-status-icon');
    const statusText = document.getElementById('inspector-status-text');
    const scoreBadge = document.getElementById('inspector-score-badge');
    const scoreText = document.getElementById('inspector-score-text');
    const meterFill = document.getElementById('inspector-meter-fill');
    const flagsList = document.getElementById('inspector-flags-list');
    const flagsContainer = document.getElementById('inspector-flags-container');
    const recText = document.getElementById('inspector-recommendation-text');
    const btnSampleThreat = document.getElementById('btn-inspect-sample-threat');
    const btnSampleSafe = document.getElementById('btn-inspect-sample-safe');

    // Dropzone elements
    const dropzone = document.getElementById('inspector-dropzone');
    const fileInput = document.getElementById('inspector-file-input');
    const dropzonePrompt = document.getElementById('dropzone-prompt');
    const dropzoneSelected = document.getElementById('dropzone-file-selected');
    const selectedFileName = document.getElementById('selected-file-name');
    const selectedFileSize = document.getElementById('selected-file-size');
    const btnRemoveFile = document.getElementById('btn-remove-file');
    const fileBadge = document.getElementById('inspector-file-badge');
    const fileBadgeText = document.getElementById('inspector-file-badge-text');

    let currentSelectedFile = null;

    function openInspector() {
        if (modalBackdrop) {
            modalBackdrop.style.display = 'flex';
            if (inspectorInput) inspectorInput.focus();
        }
    }

    function closeInspector() {
        if (modalBackdrop) {
            modalBackdrop.style.display = 'none';
        }
    }

    document.querySelectorAll('.btn-open-inspector').forEach(btn => {
        btn.addEventListener('click', openInspector);
    });

    if (btnCloseModal) btnCloseModal.addEventListener('click', closeInspector);

    if (modalBackdrop) {
        modalBackdrop.addEventListener('click', (e) => {
            if (e.target === modalBackdrop) closeInspector();
        });
    }

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modalBackdrop && modalBackdrop.style.display === 'flex') {
            closeInspector();
        }
    });

    // File Selection & Drag-and-Drop
    function handleFile(file) {
        if (!file) return;
        currentSelectedFile = file;
        if (selectedFileName) selectedFileName.textContent = file.name;
        if (selectedFileSize) selectedFileSize.textContent = `(${(file.size / 1024).toFixed(1)} KB)`;
        if (dropzonePrompt) dropzonePrompt.style.display = 'none';
        if (dropzoneSelected) dropzoneSelected.style.display = 'flex';
    }

    function clearFile() {
        currentSelectedFile = null;
        if (fileInput) fileInput.value = '';
        if (dropzonePrompt) dropzonePrompt.style.display = 'block';
        if (dropzoneSelected) dropzoneSelected.style.display = 'none';
    }

    if (dropzone) {
        dropzone.addEventListener('click', (e) => {
            if (e.target !== btnRemoveFile && fileInput) {
                fileInput.click();
            }
        });

        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        });

        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('dragover');
        });

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                handleFile(e.dataTransfer.files[0]);
            }
        });
    }

    if (fileInput) {
        fileInput.addEventListener('change', () => {
            if (fileInput.files && fileInput.files[0]) {
                handleFile(fileInput.files[0]);
            }
        });
    }

    if (btnRemoveFile) {
        btnRemoveFile.addEventListener('click', (e) => {
            e.stopPropagation();
            clearFile();
        });
    }

    // Sample Fillers
    if (btnSampleThreat) {
        btnSampleThreat.addEventListener('click', () => {
            if (inspectorInput) {
                inspectorInput.value = "CRITICAL ALERT: Your cloud storage has reached 99.4% quota. Your account will be purged in 45 minutes unless verified immediately at http://storage-admin.xyz/verify-quota. Purchase $100 gift card if required.";
            }
        });
    }

    if (btnSampleSafe) {
        btnSampleSafe.addEventListener('click', () => {
            if (inspectorInput) {
                inspectorInput.value = "Campus Notice: IT Services will conduct scheduled network maintenance this Sunday from 2:00 AM to 4:00 AM. No user action or password reset is required. Visit https://library.university.edu for schedule details.";
            }
        });
    }

    // Run Inspection using FormData supporting text and/or file
    if (btnRunInspect) {
        btnRunInspect.addEventListener('click', async () => {
            const text = (inspectorInput ? inspectorInput.value : '').trim();
            if (!text && !currentSelectedFile) {
                alert('Please enter text/links OR upload a suspicious PDF/image screenshot to inspect.');
                return;
            }

            if (inspectorLoading) inspectorLoading.style.display = 'block';
            if (inspectorResult) inspectorResult.style.display = 'none';
            btnRunInspect.disabled = true;

            try {
                const formData = new FormData();
                if (text) formData.append('input_text', text);
                if (currentSelectedFile) formData.append('file', currentSelectedFile);

                const res = await fetch('/api/inspect', {
                    method: 'POST',
                    body: formData
                });

                const data = await res.json();
                if (inspectorLoading) inspectorLoading.style.display = 'none';

                if (res.ok) {
                    renderInspectionResult(data);
                } else {
                    alert(data.recommendation || 'Failed to inspect submission.');
                }
            } catch (err) {
                if (inspectorLoading) inspectorLoading.style.display = 'none';
                console.error('Inspection error:', err);
                alert('An error occurred while contacting the AI inspection engine.');
            } finally {
                btnRunInspect.disabled = false;
            }
        });
    }

    function renderInspectionResult(data) {
        if (!inspectorResult) return;
        inspectorResult.style.display = 'block';

        const isThreat = data.status === 'THREAT DETECTED';
        const score = data.risk_score || 0;

        // Attachment info pill
        if (fileBadge && fileBadgeText) {
            if (data.file_info) {
                fileBadge.style.display = 'flex';
                const f = data.file_info;
                fileBadgeText.textContent = `Scanned File: ${f.filename} (${f.size_kb} KB${f.file_type ? ' - ' + f.file_type : ''}${f.page_count ? ' - ' + f.page_count + ' pages' : ''}${f.dimensions ? ' - ' + f.dimensions : ''})`;
            } else {
                fileBadge.style.display = 'none';
            }
        }

        if (statusBanner) {
            statusBanner.className = `xai-banner ${isThreat ? 'danger' : 'success'}`;
        }
        if (statusIcon) statusIcon.textContent = isThreat ? '🚨' : '🛡️';
        if (statusText) statusText.textContent = data.status;
        if (scoreBadge) {
            scoreBadge.textContent = `Risk Score: ${score}% (${isThreat ? 'High Risk' : 'Low Risk'})`;
            scoreBadge.className = `badge ${isThreat ? 'badge-threat' : 'badge-safe'}`;
        }

        if (scoreText) scoreText.textContent = `${score}%`;
        if (meterFill) {
            meterFill.style.width = `${score}%`;
            meterFill.style.background = score > 60 ? 'var(--accent-rose)' : (score > 30 ? 'var(--accent-amber)' : 'var(--accent-emerald)');
        }

        if (flagsContainer && flagsList) {
            if (data.red_flags && data.red_flags.length > 0) {
                flagsContainer.style.display = 'block';
                flagsList.innerHTML = data.red_flags.map(f => `
                    <div style="display: flex; gap: 0.5rem; font-size: 0.84rem; color: #991B1B; background: var(--accent-rose-bg); padding: 0.35rem 0.65rem; border-radius: 4px; border: 1px solid var(--accent-rose-border);">
                        <span>•</span>
                        <span>${f}</span>
                    </div>
                `).join('');
            } else {
                flagsContainer.style.display = 'none';
                flagsList.innerHTML = '';
            }
        }

        if (recText) {
            recText.textContent = data.recommendation;
        }
    }

    if (typeof INITIAL_PROFILE !== 'undefined') {
        initRadar(INITIAL_PROFILE);
    }
})();
