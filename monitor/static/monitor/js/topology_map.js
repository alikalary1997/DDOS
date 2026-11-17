/* Topology map interaction: select a node to trace its branch and show its details.
   Purely presentational - nothing here edits or navigates away from the page. */
(function () {
    'use strict';

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
                detail.replaceChildren(...[
                    row('Address', node.ip),
                    row('Role', node.label || node.level),
                    row('Reading', node.summary || 'No data'),
                    row('Detail', node.note || 'No data'),
                    row('Upstream', (parents.get(key) && byKey.get(parents.get(key)))?.name || 'Top level'),
                    row('Downstream', String((children.get(key) || []).length)),
                ].flat());
            }
            if (panel && window.matchMedia('(max-width: 1100px)').matches) {
                panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
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
