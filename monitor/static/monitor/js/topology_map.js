/* Dotted connectors for the topology map.
   Geometry is read from the real rendered card boxes, so the lines stay correct whatever
   number of cards each column holds. Nothing here navigates or mutates app state. */
(function () {
    'use strict';

    function data() {
        const node = document.getElementById('topo-links-data');
        if (!node) return [];
        try {
            const parsed = JSON.parse(node.textContent || '[]');
            return Array.isArray(parsed) ? parsed : [];
        } catch (_) {
            return [];
        }
    }

    function draw() {
        const svg = document.querySelector('[data-topo-links]');
        const wrap = document.querySelector('[data-topo-map]');
        const grid = document.querySelector('.topo-columns');
        if (!svg || !wrap || !grid) return;

        const links = data();
        const box = grid.getBoundingClientRect();
        if (!box.width) return;

        svg.setAttribute('viewBox', `0 0 ${box.width} ${box.height}`);
        svg.setAttribute('preserveAspectRatio', 'none');
        svg.replaceChildren();

        // `data-topo-card` surfaces as dataset.topoCard - the camelCase form is what the DOM
        // actually exposes, and reading the wrong key silently draws no lines at all.
        const cards = new Map();
        grid.querySelectorAll('[data-topo-card]').forEach(card => {
            const rect = card.getBoundingClientRect();
            cards.set(String(card.dataset.topoCard), {
                key: String(card.dataset.topoCard),
                left: rect.left - box.left,
                right: rect.right - box.left,
                middle: rect.top - box.top + rect.height / 2,
            });
        });

        const ns = 'http://www.w3.org/2000/svg';

        // Group links by parent so a parent with several children shares one stub that leaves
        // its right edge, then branches to each child. This is the org-chart fan-out shape:
        // a short horizontal stub, a vertical trunk, then a horizontal run into each child.
        const byParent = new Map();
        links.forEach(link => {
            const [parentKey, childKey] = String(link.id).split('-');
            const from = cards.get(parentKey), to = cards.get(childKey);
            if (!from || !to) return;
            if (to.left <= from.right) return;          // child must sit to the right of the parent
            if (!byParent.has(parentKey)) byParent.set(parentKey, { from, children: [] });
            byParent.get(parentKey).children.push(to);
        });

        const addPath = (d, id) => {
            const path = document.createElementNS(ns, 'path');
            path.setAttribute('d', d);
            if (id) path.setAttribute('data-link', id);
            svg.appendChild(path);
            return path;
        };

        const STUB = 14;   // horizontal distance the shared trunk sits out from the parent
        byParent.forEach((group, parentKey) => {
            const { from, children } = group;
            const startX = from.right;                       // exactly on the card's edge
            const startY = from.middle;
            // Nearest child edge drives the trunk position, so even tight gutters get a trunk.
            const nearestLeft = Math.min(...children.map(child => child.left));
            const trunkX = Math.min(startX + STUB, startX + (nearestLeft - startX) / 2);

            // Shared stub out of the parent, always drawn edge-first.
            addPath(`M ${startX} ${startY} L ${trunkX} ${startY}`, `${parentKey}-stub`);

            // The vertical trunk spans from the parent's row to the furthest child's row.
            const ys = children.map(child => child.middle).concat([startY]);
            const topY = Math.min(...ys), bottomY = Math.max(...ys);
            if (bottomY - topY > 0.5) {
                addPath(`M ${trunkX} ${topY} L ${trunkX} ${bottomY}`, `${parentKey}-trunk`);
            }

            // One branch per child, running to that child's left edge.
            children.forEach(child => {
                addPath(`M ${trunkX} ${child.middle} L ${child.left} ${child.middle}`,
                        `${parentKey}-${child.key ?? ''}`);
            });
        });
    }

    let frame = null;
    function schedule() {
        if (frame) cancelAnimationFrame(frame);
        frame = requestAnimationFrame(() => { frame = null; draw(); });
    }

    if (typeof document !== 'undefined') {
        const start = () => {
            draw();
            window.addEventListener('resize', schedule);
            if (typeof ResizeObserver === 'function') {
                const grid = document.querySelector('.topo-columns');
                if (grid) new ResizeObserver(schedule).observe(grid);
            }
        };
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
        else start();
    }
})();
