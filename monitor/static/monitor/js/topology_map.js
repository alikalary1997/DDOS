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
            const switchPanel = document.getElementById('tmapSwitch');
            if (switchPanel) { switchPanel.hidden = true; switchPanel.replaceChildren(); }
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
            // A switch opens its live port panel; every other device just shows its details.
            const switchPanel = document.getElementById('tmapSwitch');
            if (switchPanel) {
                if ((node.device_type || '') === 'cisco') openSwitch(switchPanel, node);
                else { switchPanel.hidden = true; switchPanel.replaceChildren(); }
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

        /* ---- switch port panel (Cisco) ---- */
        // Ports come from the server's own SNMP read. Nothing here is estimated: if SNMP fails
        // the panel says why rather than drawing a made-up green/red grid.
        function portState(port) {
            if (port.admin === 'down') return 'disabled';
            return port.oper === 'up' ? 'up' : 'down';
        }

        function openSwitch(host, node) {
            const template = host.dataset.portsUrlTemplate || '';
            const url = template.replace(/0\/ports\/$/, `${node.key}/ports/`) || `/devices/topology/map/switch/${node.key}/ports/`;
            host.hidden = false;
            host.dataset.deviceId = String(node.key);
            host.innerHTML = `<div class="tmap-sw-head"><div><p class="eyebrow">SWITCH</p><h2>${esc(node.name)}</h2>` +
                `<span class="tmap-sw-ip">${esc(node.ip || '')}</span></div>` +
                `<span class="tmap-sw-state" data-state="loading">Reading ports…</span></div>` +
                '<div class="tmap-sw-body"><p class="tmap-hint">Reading live port state from SNMP…</p></div>';
            fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
                .then(response => response.json().catch(() => ({ ok: false, error: 'The port list could not be read.' })))
                .then(data => {
                    // A slower request for another switch must not overwrite this one.
                    if (host.dataset.deviceId !== String(node.key)) return;
                    renderSwitch(host, node, data);
                })
                .catch(() => {
                    if (host.dataset.deviceId !== String(node.key)) return;
                    renderSwitch(host, node, { ok: false, error: 'The server could not be reached.' });
                });
        }

        function renderSwitch(host, node, data) {
            const head = host.querySelector('.tmap-sw-head');
            const state = host.querySelector('.tmap-sw-state');
            const body = host.querySelector('.tmap-sw-body');
            if (!data.ok) {
                if (state) { state.dataset.state = 'error'; state.textContent = 'SNMP unavailable'; }
                if (body) body.innerHTML = `<p class="tmap-hint">Live port state is unavailable. ${esc(data.error || '')}</p>`;
                return;
            }
            const ports = data.ports || [];
            if (state) {
                state.dataset.state = 'online';
                state.textContent = `${data.connected} connected · ${data.total - data.connected} not connected`;
            }
            const grid = ports.map(port => {
                // The port number alone fits the square: Gi0/1 -> 0/1, Gi1/0/24 -> 1/0/24.
                const text = port.name.replace(/[^0-9/]/g, '') || port.name;
                return `<button type="button" class="tmap-port" data-port="${port.index}" data-state="${portState(port)}" ` +
                    `title="${esc(port.name)} — ${portState(port)}">${esc(text)}</button>`;
            }).join('');
            if (body) {
                body.innerHTML = `<div class="tmap-port-grid">${grid || '<p class="tmap-hint">This switch reported no physical ports.</p>'}</div>` +
                    '<div class="tmap-sw-foot">' +
                    '<span class="tmap-key"><i data-state="up"></i>Connected</span>' +
                    '<span class="tmap-key"><i data-state="down"></i>Not connected</span>' +
                    '<span class="tmap-key"><i data-state="disabled"></i>Disabled</span>' +
                    '<span class="tmap-hint">Click a port for its details.</span></div>' +
                    '<div class="tmap-port-detail" data-port-detail hidden></div>';
                body.querySelectorAll('.tmap-port').forEach(button => {
                    button.addEventListener('click', () => showPort(host, ports, Number(button.dataset.port)));
                });
            }
            if (head) head.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        function showPort(host, ports, index) {
            const port = ports.find(item => item.index === index);
            const detail = host.querySelector('[data-port-detail]');
            if (!port || !detail) return;
            host.querySelectorAll('.tmap-port').forEach(button => {
                button.classList.toggle('is-selected', Number(button.dataset.port) === index);
            });
            const state = portState(port);
            const label = { up: 'CONNECTED', down: 'NOT CONNECTED', disabled: 'DISABLED' }[state];
            const tone = state === 'up' ? 'online' : state === 'disabled' ? 'warn' : 'error';
            const speed = port.speed_mbps ? `${port.speed_mbps} Mbps` : '—';
            detail.hidden = false;
            detail.innerHTML = `<div class="tmap-sw-head"><div><p class="eyebrow">PORT</p><h2>${esc(port.name)}</h2></div>` +
                `<span class="tmap-sw-state" data-state="${tone}">${label}</span></div>` +
                '<dl class="tmap-detail">' +
                `<dt>Admin / oper</dt><dd>${esc(port.admin)} / ${esc(port.oper)}</dd>` +
                `<dt>Speed</dt><dd>${esc(speed)}</dd>` +
                `<dt>SNMP ifIndex</dt><dd>${esc(port.index)}</dd>` +
                (port.alias ? `<dt>Alias</dt><dd>${esc(port.alias)}</dd>` : '') +
                '</dl>';
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
