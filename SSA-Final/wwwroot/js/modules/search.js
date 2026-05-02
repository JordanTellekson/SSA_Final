import { getUrl, setParam, setPage, buildUrl, replace, navigate } from '/js/modules/urlState.js';

export function initSearch() {
    const form = document.getElementById('searchForm');
    const input = document.getElementById('searchInput');
    const clearBtn = document.getElementById('clearSearchBtn');

    if (!input) return;

    let debounceTimer;

    // Intercept the native form submit (Enter key, submit button, etc.)
    form?.addEventListener('submit', (e) => {
        e.preventDefault();
        clearTimeout(debounceTimer);
        performSearch(input.value, 1);
    });

    input.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            performSearch(input.value, 1);
        }, 300);
    });

    // Clear only the query param — all filter params are preserved
    // because we build from getUrl(), not from the form fields.
    clearBtn?.addEventListener('click', (e) => {
        e.preventDefault();
        clearTimeout(debounceTimer);
        input.value = '';           // visually clear the input field
        const url = getUrl();
        url.searchParams.delete('query');
        setPage(url, 1);
        navigate(url);
    });
}

export function performSearch(query, page) {
    const url = getUrl();

    // setParam deletes the key if query is blank, preserves everything else
    setParam(url, 'query', query);
    setPage(url, page);

    fetchResults(url);
}

export function performSearchFromUrl(url) {
    fetchResults(url);
}

function fetchResults(url) {
    fetch(buildUrl(url), {
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
    })
        .then(res => {
            if (!res.ok) throw new Error(`Server returned ${res.status}`);
            return res.text();
        })
        .then(html => {
            updateResults(html);
            replace(url);
        })
        .catch(err => console.error('Search fetch failed:', err));
}

function updateResults(html) {
    const container = document.getElementById('resultsContainer');
    if (!container) return;

    container.innerHTML = html;

    container
        .querySelectorAll('[data-bs-toggle="tooltip"]')
        .forEach(el => new bootstrap.Tooltip(el));
}