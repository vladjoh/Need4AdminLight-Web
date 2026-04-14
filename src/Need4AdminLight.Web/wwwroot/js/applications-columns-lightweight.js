(function () {
    function norm(s) { return (s || '').trim().toLowerCase(); }

    function compareValues(a, b, asc) {
        var sa = a ?? '';
        var sb = b ?? '';
        var tickRe = /^\d{19}$/;
        if (tickRe.test(sa) && tickRe.test(sb)) {
            var ba = BigInt(sa), bb = BigInt(sb);
            var tc = ba < bb ? -1 : ba > bb ? 1 : 0;
            return asc ? tc : -tc;
        }
        if (sa !== '' && sb !== '' && /^\d+$/.test(sa) && /^\d+$/.test(sb) && sa.length === sb.length) {
            var cs = sa < sb ? -1 : sa > sb ? 1 : 0;
            return asc ? cs : -cs;
        }
        var na = parseFloat(sa), nb = parseFloat(sb);
        if (sa !== '' && sb !== '' && !isNaN(na) && !isNaN(nb) && na !== nb) {
            return asc ? na - nb : nb - na;
        }
        var c = String(sa).localeCompare(String(sb), undefined, { sensitivity: 'base' });
        return asc ? c : -c;
    }

    function sortByKey(table, key, asc) {
        var tbody = table.querySelector('tbody');
        if (!tbody) return;
        var rows = Array.from(tbody.querySelectorAll('tr'));
        rows.sort(function (ra, rb) {
            var va = ra.getAttribute('data-sort-' + key) || '';
            var vb = rb.getAttribute('data-sort-' + key) || '';
            var c = compareValues(va, vb, asc);
            if (c !== 0) return c;
            var ua = ra.getAttribute('data-sort-name') || '';
            var ub = rb.getAttribute('data-sort-name') || '';
            return String(ua).localeCompare(String(ub), undefined, { sensitivity: 'base' });
        });
        rows.forEach(function (r) { tbody.appendChild(r); });
    }

    function applyRowFilters(table) {
        var tbody = table.querySelector('tbody');
        if (!tbody) return;
        var searchEl = document.getElementById('search-applications');
        var q = norm(searchEl ? searchEl.value : '');
        tbody.querySelectorAll('tr').forEach(function (tr) {
            var hide = false;
            if (q && norm(tr.textContent || '').indexOf(q) < 0) hide = true;
            tr.classList.toggle('report-row-hidden', hide);
        });
    }

    function wireHeaderSort(table) {
        var state = { key: 'name', asc: true };
        table.querySelectorAll('th[data-sort]').forEach(function (th) {
            th.classList.add('sortable-col');
            th.addEventListener('click', function () {
                var key = th.getAttribute('data-sort');
                if (!key) return;
                if (state.key === key) state.asc = !state.asc;
                else { state.key = key; state.asc = true; }
                sortByKey(table, state.key, state.asc);
                applyRowFilters(table);
            });
        });
        sortByKey(table, state.key, state.asc);
    }

    function init() {
        var table = document.getElementById('tbl-applications');
        if (!table) return;
        var searchEl = document.getElementById('search-applications');
        if (searchEl) searchEl.addEventListener('input', function () { applyRowFilters(table); });
        wireHeaderSort(table);
        applyRowFilters(table);
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
