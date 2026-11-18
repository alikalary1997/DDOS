/* Topology map interaction: select a node to trace its branch and show its details.
   Purely presentational - nothing here edits or navigates away from the page. */
(function () {
    'use strict';

    const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ESCAPES[char]);

    function nodes() {
        const el = document.getElementById('topo-nodes-data');
        if (!el) return [];
        try {
            const parsed = JSON.parse(el.textContent || '[]');
            return Array.isArray(parsed) ? parsed : [];
        } catch (_) {
            return [];
        }
    }

    function start() {
        const svg = document.querySelector('[data-topo-svg]');
        const map = document.querySelector('[data-topo-map]');
        if (!svg || !map) return;

        const byKey = new Map(nodes().map(node => [String(node.key), node]));
        const nodeEls = Array.from(svg.querySelectorAll('[data-node]'));
        const linkEls = Array.from(svg.querySelectorAll('.tmap-link'));
        const panel = document.querySelector('[data-topo-inspect]');
        const title = panel?.querySelector('[data-inspect-title]');
        const hint = panel?.querySelector('[data-inspect-hint]');
        const detail = panel?.querySelector('[data-inspect-detail]');

        // Parent/child adjacency, so a selected branch can be traced in both directions.
        const parents = new Map(), children = new Map();
        linkEls.forEach(link => {
            const from = link.dataset.from, to = link.dataset.to;
            if (!children.has(from)) children.set(from, []);
            children.get(from).push(to);
            parents.set(to, from);
        });

        function branchOf(key) {
            const branch = new Set([key]);
            // Walk down through every descendant.
            const down = [key];
            while (down.length) {
                const current = down.pop();
                (children.get(current) || []).forEach(child => {
                    if (!branch.has(child)) { branch.add(child); down.push(child); }
                });
            }
            // Walk up to the root so the selected node's own path stays highlighted.
            let up = parents.get(key);
            const seen = new Set();
            while (up && !seen.has(up)) { seen.add(up); branch.add(up); up = parents.get(up); }
            return branch;
        }

        function clear() {
            nodeEls.forEach(el => el.classList.remove('is-selected', 'is-dim'));
            linkEls.forEach(el => el.classList.remove('is-active', 'is-dim'));
            if (title) title.textContent = 'Network overview';
            if (hint) hint.hidden = false;
            if (detail) { detail.hidden = true; detail.replaceChildren(); }
        }

        function row(label, value) {
            const dt = document.createElement('dt');
            dt.textContent = label;
            const dd = document.createElement('dd');
            dd.textContent = value;
            return [dt, dd];
        }

        function select(key) {
            const node = byKey.get(key);
            if (!node) return;
            const branch = branchOf(key);
            nodeEls.forEach(el => {
                const inBranch = branch.has(el.dataset.node);
                el.classList.toggle('is-selected', el.dataset.node === key);
                el.classList.toggle('is-dim', !inBranch);
            });
            linkEls.forEach(el => {
                // A link belongs to the branch when both ends are in it.
                const inBranch = branch.has(el.dataset.from) && branch.has(el.dataset.to);
                el.classList.toggle('is-active', inBranch);
                el.classList.toggle('is-dim', !inBranch);
            });
            if (title) title.textContent = node.name;
            if (hint) hint.hidden = true;
            if (detail) {
                detail.hidden = false;
                detail.replaceChildren(...renderDetail(node, key));
            }
            if (panel && window.matchMedia('(max-width: 1100px)').matches) {
                panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
        }

        // Sensor readings belong in a stat grid; the connection facts stay a definition list.
        const sensorStat = (label, value, unit, tone) => {
            const empty = value === null || value === undefined;
            const text = empty ? '—' : (typeof value === 'number' ? formatNumber(value) : value);
            return `<div class="tmap-stat${empty ? ' is-empty' : ''}"${tone ? ` data-tone="${tone}"` : ''}>
                <span>${esc(label)}</span><b>${esc(text)}${empty ? '' : `<em>${esc(unit || '')}</em>`}</b></div>`;
        };

        function formatNumber(value) {
            // Two decimals for MB/s figures, whole numbers for counts and percentages.
            return Number.isInteger(value) ? String(value) : value.toFixed(2);
        }

        function cpuTone(cpu) {
            if (cpu === null || cpu === undefined) return '';
            return cpu > 80 ? 'bad' : cpu > 65 ? 'wn' : 'ok';
        }

        function renderDetail(node, key) {
            const r = node.readings || {};
            const bandwidth = (r.bandwidth_in === null || r.bandwidth_in === undefined)
                ? null : r.bandwidth_in + (r.bandwidth_out || 0);
            const upstream = (parents.get(key) && byKey.get(parents.get(key)))?.name || 'Top level';
            const downstream = (children.get(key) || []).length;

            const facts = document.createElement('dl');
            facts.className = 'tmap-detail';
            facts.append(...[
                row('Address', node.ip),
                row('Role', node.label || node.level),
                row('Upstream', upstream),
                row('Downstream', `${downstream} device${downstream === 1 ? '' : 's'}`),
                r.ping_ms !== null && r.ping_ms !== undefined ? row('Ping', `${r.ping_ms.toFixed(1)} ms · ${r.packet_loss ?? 0}% loss`) : null,
            ].filter(Boolean).flat());

            const grid = document.createElement('div');
            grid.className = 'tmap-stats';
            grid.innerHTML = [
                sensorStat('CPU', r.cpu === null || r.cpu === undefined ? null : Math.round(r.cpu), '%', cpuTone(r.cpu)),
                sensorStat('Bandwidth', bandwidth, 'Mbps'),
                sensorStat('Users', r.users, ''),
                sensorStat('Uptime', r.uptime, ''),
            ].join('');

            return [grid, facts];
        }

        nodeEls.forEach(el => {
            el.addEventListener('click', () => {
                if (el.classList.contains('is-selected')) clear();
                else select(el.dataset.node);
            });
            el.addEventListener('keydown', event => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    if (el.classList.contains('is-selected')) clear();
                    else select(el.dataset.node);
                }
            });
        });

        svg.addEventListener('click', event => {
            if (!event.target.closest('[data-node]')) clear();
        });
    }

    if (typeof document !== 'undefined') {
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
        else start();
    }
})();
