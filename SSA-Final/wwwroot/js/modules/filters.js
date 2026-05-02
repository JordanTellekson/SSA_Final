import { getUrl, removeParams, setParam, setPage, navigate } from '/js/modules/urlState.js';

export function initFilters() {
    const filterForm = document.getElementById('filterForm');
    const clearBtn = document.getElementById('clearFiltersBtn');
    const resetBtn = document.getElementById('resetBtn');

    // Apply filters — merge form values into current URL, preserving query
    filterForm?.addEventListener('submit', (e) => {
        e.preventDefault();

        const url = getUrl();
        const data = new FormData(filterForm);

        // Set or clear each filter param based on form value
        setParam(url, 'Status', data.get('Status'));
        setParam(url, 'HasMalicious', data.get('HasMalicious'));
        setPage(url, 1);

        // query is already in the URL from the address bar
        navigate(url);
    });

    // Clear filter params only — query stays untouched in the URL
    clearBtn?.addEventListener('click', (e) => {
        e.preventDefault();
        const url = getUrl();
        removeParams(url, ['Status', 'HasMalicious']);
        setPage(url, 1);
        navigate(url);
    });

    // Wipe everything
    resetBtn?.addEventListener('click', () => {
        window.location.href = window.location.pathname;
    });
}