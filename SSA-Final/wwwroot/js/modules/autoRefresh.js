// Polls the current list page while any scan is in a non-terminal state (Pending/InProgress).
// Detection: _ScanList.cshtml emits #active-scans-indicator when active scans are present.
// On each tick the partial is re-fetched and #resultsContainer is replaced in-place.
// Polling stops automatically once no active scans remain on the page.

import { getUrl, buildUrl } from '/js/modules/urlState.js';

const POLL_INTERVAL_MS = 5000;

export function initAutoRefresh() {
    if (hasActiveScans()) {
        schedulePoll();
    }
}

function hasActiveScans() {
    return !!document.getElementById('active-scans-indicator');
}

function schedulePoll() {
    setTimeout(async () => {
        await refresh();

        // Continue polling only if active scans are still visible after the refresh.
        if (hasActiveScans()) {
            schedulePoll();
        }
    }, POLL_INTERVAL_MS);
}

async function refresh() {
    const url = buildUrl(getUrl());

    try {
        const response = await fetch(url, {
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            credentials: 'same-origin'
        });

        if (!response.ok) return;

        const html = await response.text();
        const container = document.getElementById('resultsContainer');
        if (!container) return;

        container.innerHTML = html;

        // Re-initialise Bootstrap tooltips injected by the refreshed partial.
        container
            .querySelectorAll('[data-bs-toggle="tooltip"]')
            .forEach(el => new bootstrap.Tooltip(el));

    } catch {
        // Network hiccup — silently skip this cycle and let the next scheduled poll retry.
    }
}
