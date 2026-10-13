document.addEventListener('DOMContentLoaded', function() {
    const filterForm = document.getElementById('filterForm');
    if (filterForm) {
        filterForm.addEventListener('submit', function(e) {
            const inputs = filterForm.querySelectorAll('input, select');
            let hasValue = false;
            inputs.forEach(input => {
                if (input.value && input.name !== 'page') {
                    hasValue = true;
                }
            });
        });
    }

    const acknowledgeButtons = document.querySelectorAll('.acknowledge-btn');
    acknowledgeButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const alertId = this.dataset.alertId;
            const originalHtml = this.innerHTML;
            this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
            this.disabled = true;

            fetch(`/alerts/${alertId}/acknowledge`, { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        this.outerHTML = '<i class="bi bi-check-circle-fill text-success" title="Acknowledged"></i>';
                    } else {
                        this.innerHTML = originalHtml;
                        this.disabled = false;
                        alert('Failed to acknowledge alert');
                    }
                })
                .catch(err => {
                    console.error(err);
                    this.innerHTML = originalHtml;
                    this.disabled = false;
                    alert('Error acknowledging alert');
                });
        });
    });

    const dateInputs = document.querySelectorAll('input[type="date"]');
    dateInputs.forEach(input => {
        if (!input.value) {
            const today = new Date();
            if (input.name === 'start_date') {
                const weekAgo = new Date(today);
                weekAgo.setDate(weekAgo.getDate() - 7);
                input.value = weekAgo.toISOString().split('T')[0];
            } else if (input.name === 'end_date') {
                input.value = today.toISOString().split('T')[0];
            }
        }
    });

    const tables = document.querySelectorAll('table.table-hover tbody tr');
    tables.forEach(row => {
        row.style.cursor = 'pointer';
        row.addEventListener('click', function(e) {
            if (e.target.tagName === 'A' || e.target.tagName === 'BUTTON' || e.target.closest('a, button')) {
                return;
            }
            const link = this.querySelector('a[href*="/alerts/"]');
            if (link) {
                window.location.href = link.href;
            }
        });
    });
});

function refreshDashboard() {
    fetch('/api/stats')
        .then(r => r.json())
        .then(data => {
            updateStatsCards(data);
        })
        .catch(console.error);
}

function updateStatsCards(stats) {
    const severityMap = {
        'Critical': 'critical',
        'High': 'high',
        'Medium': 'medium',
        'Low': 'low'
    };

    Object.keys(severityMap).forEach(sev => {
        const element = document.getElementById(`stat-${sev.toLowerCase()}`);
        if (element) {
            element.textContent = stats.by_severity[sev] || 0;
        }
    });

    const totalElement = document.getElementById('stat-total');
    if (totalElement) {
        totalElement.textContent = stats.total_alerts;
    }
}

setInterval(refreshDashboard, 30000);