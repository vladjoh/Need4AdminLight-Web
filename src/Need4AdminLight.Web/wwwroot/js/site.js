(function () {
    try {
        var qs = new URLSearchParams(window.location.search || '');
        if (qs.get('signedout') === '1') {
            sessionStorage.removeItem('n4al-generated-privileged');
            sessionStorage.removeItem('n4al-generated-applications');
            sessionStorage.removeItem('n4al-generated-agents');
        }
    } catch (e) { /* ignore */ }

    /** When a report was already generated this session, add ?reuse=1 so the server returns IMemoryCache (navbar + Overview buttons). */
    function applyReportReuseLinks() {
        try {
            var map = [
                { path: '/PrivilegedUsers', key: 'n4al-generated-privileged' },
                { path: '/Applications', key: 'n4al-generated-applications' }
            ];
            document.querySelectorAll('a[data-scan="true"]').forEach(function (a) {
                var href = a.getAttribute('href');
                if (!href) {
                    return;
                }
                var u = new URL(href, window.location.origin);
                var pathname = (u.pathname || '').replace(/\/$/, '') || '/';
                for (var i = 0; i < map.length; i++) {
                    var mp = map[i].path.replace(/\/$/, '');
                    if (pathname === mp) {
                        if (sessionStorage.getItem(map[i].key) === '1') {
                            u.searchParams.set('reuse', '1');
                            a.setAttribute('href', u.pathname + u.search + u.hash);
                        }
                        break;
                    }
                }
            });
            document.querySelectorAll('a.overview-report-btn[data-report-session]').forEach(function (a) {
                var k = 'n4al-generated-' + a.getAttribute('data-report-session');
                if (sessionStorage.getItem(k) === '1') {
                    a.textContent = 'Show report';
                }
            });
        } catch (e) { /* ignore */ }
    }

    function hrefHasReuseParam(href) {
        try {
            var u = new URL(href, window.location.origin);
            var r = u.searchParams.get('reuse');
            return r === '1' || r === 'true' || r === 'yes';
        } catch (e) {
            return false;
        }
    }

    applyReportReuseLinks();

    function compareValues(a, b, asc) {
        var sa = a ?? '';
        var sb = b ?? '';
        var na = parseFloat(sa);
        var nb = parseFloat(sb);
        if (sa !== '' && sb !== '' && !isNaN(na) && !isNaN(nb)) {
            if (na !== nb) {
                return asc ? na - nb : nb - na;
            }
        }
        var c = String(sa).localeCompare(String(sb), undefined, { sensitivity: 'base' });
        if (c !== 0) {
            return asc ? c : -c;
        }
        return 0;
    }

    function initReportTable(table) {
        if (!table || table.dataset.reportInit) {
            return;
        }
        table.dataset.reportInit = '1';
        var tbody = table.querySelector('tbody');
        if (!tbody) {
            return;
        }
        var id = table.id;
        var searchEl = id ? document.querySelector('[data-report-search="' + id + '"]') : null;

        function applySearch() {
            var q = (searchEl && searchEl.value || '').trim().toLowerCase();
            tbody.querySelectorAll('tr').forEach(function (tr) {
                if (!q) {
                    tr.classList.remove('report-row-hidden');
                    return;
                }
                var t = (tr.textContent || '').toLowerCase();
                tr.classList.toggle('report-row-hidden', t.indexOf(q) < 0);
            });
        }

        if (searchEl) {
            searchEl.addEventListener('input', applySearch);
        }

        var theadRow = table.querySelector('thead tr');
        if (!theadRow) {
            return;
        }

        theadRow.querySelectorAll('th[data-sort]').forEach(function (th) {
            th.classList.add('sortable-col');
            th.setAttribute('role', 'button');
            th.tabIndex = 0;
            th.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    th.click();
                }
            });

            th.addEventListener('click', function () {
                var key = th.getAttribute('data-sort');
                if (!key) {
                    return;
                }
                var asc;
                if (th.dataset.sortDir === undefined) {
                    asc = key === 'risk' ? false : true;
                } else {
                    asc = th.dataset.sortDir !== 'asc';
                }
                th.dataset.sortDir = asc ? 'asc' : 'desc';
                theadRow.querySelectorAll('th[data-sort]').forEach(function (h) {
                    if (h !== th) {
                        delete h.dataset.sortDir;
                    }
                });
                theadRow.querySelectorAll('th[data-sort]').forEach(function (h) {
                    h.removeAttribute('aria-sort');
                });
                th.setAttribute('aria-sort', asc ? 'ascending' : 'descending');

                var rows = Array.from(tbody.querySelectorAll('tr'));
                rows.sort(function (ra, rb) {
                    var va = ra.getAttribute('data-sort-' + key) || '';
                    var vb = rb.getAttribute('data-sort-' + key) || '';
                    var c = compareValues(va, vb, asc);
                    if (c !== 0) {
                        return c;
                    }
                    var ua = ra.getAttribute('data-sort-upn') || ra.getAttribute('data-sort-name') || '';
                    var ub = rb.getAttribute('data-sort-upn') || rb.getAttribute('data-sort-name') || '';
                    return String(ua).localeCompare(String(ub), undefined, { sensitivity: 'base' });
                });
                rows.forEach(function (r) {
                    tbody.appendChild(r);
                });
            });
        });
    }

    document.querySelectorAll('table.report-sortable').forEach(initReportTable);

    var overlay = document.getElementById('scan-overlay');
    var titleEl = document.getElementById('scan-overlay-title');
    var textEl = document.getElementById('scan-overlay-text');
    var subEl = document.getElementById('scan-overlay-sub');
    var defaultTitle = titleEl ? titleEl.textContent : '';
    var defaultText = textEl ? textEl.textContent : '';
    var defaultSub = subEl ? subEl.textContent : '';

    document.querySelectorAll('a.n4a-signout').forEach(function (a) {
        a.addEventListener('click', function () {
            try {
                sessionStorage.removeItem('n4al-generated-privileged');
                sessionStorage.removeItem('n4al-generated-applications');
                sessionStorage.removeItem('n4al-generated-agents');
            } catch (e) { /* ignore */ }
        });
    });

    document.querySelectorAll('a[data-scan="true"]').forEach(function (a) {
        a.addEventListener('click', function () {
            try {
                var href = a.getAttribute('href') || '';
                if (hrefHasReuseParam(href)) {
                    return;
                }
            } catch (e) { /* ignore */ }
            if (!overlay) {
                return;
            }
            if (titleEl) {
                titleEl.textContent = a.getAttribute('data-scan-title') || defaultTitle;
            }
            if (textEl) {
                textEl.textContent = a.getAttribute('data-scan-text') || defaultText;
            }
            if (subEl) {
                subEl.textContent = a.getAttribute('data-scan-sub') || defaultSub;
                subEl.style.display = subEl.textContent ? '' : 'none';
            }
            overlay.classList.add('active');
            overlay.setAttribute('aria-hidden', 'false');
        });
    });
})();
