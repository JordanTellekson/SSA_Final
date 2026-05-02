import { getUrl, setPage, buildUrl, replace } from '/js/modules/urlState.js';

export function initPagination() {

    document.addEventListener('click', (e) => {
        const link = e.target.closest('.page-link');
        if (!link) return;

        e.preventDefault();

        const page = link.dataset.page;
        if (!page) return;

        const url = getUrl();
        setPage(url, page);

        // All existing params (query, Status, HasMalicious) are preserved
        // by building from the current URL via getUrl().
        fetch(buildUrl(url), {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        })
            .then(res => {
                if (!res.ok) throw new Error(`Server returned ${res.status}`);
                return res.text();
            })
            .then(html => {
                const container = document.getElementById('resultsContainer');
                if (!container) return;
                container.innerHTML = html;

                // Re-initialise tooltips injected by the partial
                container
                    .querySelectorAll('[data-bs-toggle="tooltip"]')
                    .forEach(el => new bootstrap.Tooltip(el));

                replace(url);
            })
            .catch(err => console.error('Pagination fetch failed:', err));
    });
}