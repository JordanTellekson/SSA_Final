// Entry point for initializing the controls on DomainScan-based index views
import { initSearch } from '/js/modules/search.js';
import { initFilters } from '/js/modules/filters.js';
import { initPagination } from '/js/modules/pagination.js';

document.addEventListener('DOMContentLoaded', () => {
    initSearch();
    initFilters();
    initPagination();
});