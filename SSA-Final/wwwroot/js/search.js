document.addEventListener("DOMContentLoaded", function () {

    const input = document.getElementById('searchInput');
    const resetBtn = document.getElementById('resetBtn');

    if (!input) return;

    let debounceTimer;

    input.addEventListener('input', function () {
        clearTimeout(debounceTimer);

        debounceTimer = setTimeout(() => {
            performSearch(input.value, 1);
        }, 300);
    });

    input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            performSearch(input.value, 1);
        }
    });

    if (resetBtn) {
        resetBtn.addEventListener('click', function () {
            input.value = '';
            performSearch('', 1);
        });
    }

    document.addEventListener('click', function (e) {
        const link = e.target.closest('.page-link');
        if (!link) return;

        e.preventDefault();

        const page = link.getAttribute('data-page');
        if (!page) return;

        performSearch(input.value, page);
    });

    function performSearch(query, page) {

        const baseUrl = window.location.pathname;
        const params = new URLSearchParams();

        if (query && query.trim() !== '') {
            params.set('query', query.trim());
        }

        params.set('page', page);

        const url = `${baseUrl}?${params.toString()}`;

        fetch(url, {
            headers: {
                "X-Requested-With": "XMLHttpRequest"
            }
        })
            .then(res => res.text())
            .then(html => {
                document.getElementById('resultsContainer').innerHTML = html;

                document
                    .getElementById('resultsContainer')
                    .querySelectorAll('[data-bs-toggle="tooltip"]')
                    .forEach(el => new bootstrap.Tooltip(el));

                const newUrl = new URL(window.location);

                if (query && query.trim() !== '') {
                    newUrl.searchParams.set('query', query.trim());
                } else {
                    newUrl.searchParams.delete('query');
                }

                newUrl.searchParams.set('page', page);

                window.history.replaceState({}, '', newUrl);
            });
    }
});