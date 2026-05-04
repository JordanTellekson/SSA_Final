export function getUrl() {
    return new URL(window.location.href);
}

export function setParam(url, key, value) {
    if (value != null && value.toString().trim() !== '') {
        url.searchParams.set(key, value);
    } else {
        url.searchParams.delete(key);
    }
}

export function removeParams(url, keys) {
    keys.forEach(k => url.searchParams.delete(k));
}

export function setPage(url, page = 1) {
    url.searchParams.set('page', page.toString());
}

// Returns a relative URL string (pathname + query string) — avoids sending
// the full origin to fetch(), which can cause subtle mismatches.
export function buildUrl(url) {
    const qs = url.searchParams.toString();
    return qs ? `${url.pathname}?${qs}` : url.pathname;
}

export function replace(url) {
    window.history.replaceState({}, '', buildUrl(url));
}

export function navigate(url) {
    window.location.href = buildUrl(url);
}