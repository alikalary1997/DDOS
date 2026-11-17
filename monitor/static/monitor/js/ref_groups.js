/* Groups page interaction, ported from the reference design: a group sidebar with per-status
   counters, a summary card for the selected group, and a device table whose Group and
   Topology cells are inline selects. Persisting changes posts to the existing device edit
   endpoint; nothing here invents data. */
(function () {
    'use strict';

    function read(id, fallback) {
        const el = document.getElementById(id);
        if (!el) return fallback;
        try { return JSON.parse(el.textContent || 'null') ?? fallback; } catch (_) { return fallback; }
    }

    function start() {
        const rowsEl = document.getElementById('refRows');
        const sideEl = document.getElementById('refSide');
        if (!rowsEl || !sideEl) return;

        const DEVICES = read('ref-devices', []);
        const SIDEBAR = read('ref-sidebar', []);
        const GROUP_OPTIONS = read('ref-group-options', []);
        const TOPOLOGY_OPTIONS = read('ref-topology-options', []);
        const CONFIG = read('ref-config', { canAdd: false, canDelete: false });

        const state = { group: 'all', filter: 'all', flash: '' };
        const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

        const byId = id => DEVICES.find(d => String(d.id) === String(id));
        const nameOf = key => {
            if (!key) return '';
            const [, raw] = String(key).split(':');
            return (byId(raw) || {}).name || '';
        };

        // Status tone used by the dots and counters: worst state in the branch wins.
        function tone(counts) {
            if (!counts) return 'n';
            if (counts.offline) return 'r';
            if (counts.unknown) return 'w';
            if (counts.online) return 'g';
            return 'n';
        }

        function visible() {
            if (state.group === 'all') return DEVICES.slice();
            if (state.group === 'none') return DEVICES.filter(d => !d.group_key);
            return DEVICES.filter(d => d.group_key === state.group);
        }

        function buildSidebar() {
            const item = entry => {
                const counts = entry.counts || {};
                const n = (counts.online || 0) + (counts.unknown || 0) + (counts.offline || 0);
                const deletable = CONFIG.canDelete && entry.key.startsWith('g:');
                return `<div class="gi${state.group === entry.key ? ' on' : ''}" data-ref-group="${esc(entry.key)}">
                    <span class="gd" style="background:${n ? dotColor(counts) : '#3a4b5f'}"></span>
                    <span class="gn">${esc(entry.label)}</span>
                    <span class="gb g">${counts.online || 0}</span>
                    ${counts.unknown ? `<span class="gb w">${counts.unknown}</span>` : ''}
                    ${counts.offline ? `<span class="gb r">${counts.offline}</span>` : ''}
                    ${deletable ? `<button type="button" class="gi-del" data-ref-delete-group="${esc(entry.key)}" title="Delete group ${esc(entry.label)}" aria-label="Delete group ${esc(entry.label)}">&times;</button>` : ''}
                </div>`;
            };
            const grouped = SIDEBAR.filter(entry => entry.key !== 'all' && entry.key !== 'none');
            sideEl.innerHTML = `<div class="ch"><h2>Groups</h2><span class="sp"></span>
                    ${CONFIG.canAdd ? '<button type="button" class="btn" data-ref-add-group">+ Group</button>' : ''}</div>
                ${SIDEBAR.filter(e => e.key === 'all').map(item).join('')}
                ${grouped.map(item).join('')}
                ${SIDEBAR.filter(e => e.key === 'none').map(item).join('')}
                <div class="mut" style="font-size:11px;margin-top:8px">Counters: <span style="color:var(--ref-ok)">OK</span> ·
                    <span style="color:var(--ref-wn)">warning</span> · <span style="color:var(--ref-bad)">critical</span></div>`;
        }

        function dotColor(counts) {
            return counts.offline ? 'var(--ref-bad)' : counts.unknown ? 'var(--ref-wn)' : 'var(--ref-ok)';
        }

        function buildSummary() {
            const target = document.getElementById('refSummary');
            if (!target) return;
            const list = visible();
            const counts = { online: 0, unknown: 0, offline: 0 };
            let cpu = 0, cpuN = 0, traffic = 0, users = 0;
            list.forEach(d => {
                counts[d.status] = (counts[d.status] || 0) + 1;
                if (d.cpu !== null && d.cpu !== undefined) { cpu += d.cpu; cpuN++; }
                if (d.traffic_mbps !== null) traffic += d.traffic_mbps;
                if (d.users !== null && d.users !== undefined) users += d.users;
            });
            const label = state.group === 'all' ? 'All devices'
                : state.group === 'none' ? 'Ungrouped devices'
                : (SIDEBAR.find(e => e.key === state.group) || {}).label || '';
            const pill = !list.length ? ['n', 'EMPTY'] : counts.offline ? ['bad', 'CRITICAL']
                : counts.unknown ? ['wn', 'WARNING'] : ['ok', 'HEALTHY'];
            const pct = v => (list.length ? (v / list.length) * 100 : 0);
            const groupEntry = state.group.startsWith('g:');

            target.innerHTML = `<div class="card">
                <div class="ch"><h2 style="font-size:15px">${esc(label)}</h2>
                    <span class="pill ${pill[0]}">${pill[1]}</span><span class="sp"></span>
                    ${groupEntry && CONFIG.canDelete ? `<button type="button" class="btn st" data-ref-delete-group="${esc(state.group)}">Delete group</button>` : ''}
                </div>
                <div style="display:flex;height:8px;border-radius:4px;overflow:hidden;background:#1f2a37;margin:4px 0 10px">
                    <i style="width:${pct(counts.online)}%;background:var(--ref-ok)"></i>
                    <i style="width:${pct(counts.unknown)}%;background:var(--ref-wn)"></i>
                    <i style="width:${pct(counts.offline)}%;background:var(--ref-bad)"></i>
                </div>
                <div class="kv">
                    <div><span class="mut">Devices</span><b>${list.length}</b></div>
                    <div><span class="mut">Online</span><b style="color:var(--ref-ok)">${counts.online}</b></div>
                    <div><span class="mut">Warnings</span><b style="color:${counts.unknown + counts.offline ? 'var(--ref-wn)' : 'var(--ref-tx)'}">${counts.unknown + counts.offline}</b></div>
                    <div><span class="mut">Avg CPU</span><b>${cpuN ? Math.round(cpu / cpuN) + '%' : '—'}</b></div>
                    <div><span class="mut">Traffic</span><b>${traffic ? traffic.toFixed(1) + ' Mbps' : '—'}</b></div>
                </div>
            </div>`;
        }

        function options(list, selected) {
            return list.map(option =>
                `<option value="${esc(option.key)}"${option.key === selected ? ' selected' : ''}>${esc(option.label)}</option>`).join('');
        }

        // Topology picker: "Not connected" plus every other device.
        function topologyOptions(device) {
            const others = TOPOLOGY_OPTIONS.filter(option => String(option.key) !== `d:${device.id}`);
            return `<option value="">Not connected</option>${options(others, device.topology_key)}`;
        }

        function cpuCell(cpu) {
            if (cpu === null || cpu === undefined) return '<span class="mut">—</span>';
            const colour = cpu > 80 ? 'var(--ref-bad)' : cpu > 65 ? 'var(--ref-wn)' : 'var(--ref-ok)';
            return `<b style="color:${colour}">${Math.round(cpu)}%</b><span class="bar"><b style="width:${Math.min(100, cpu)}%;background:${colour}"></b></span>`;
        }

        function statusPill(device) {
            if (device.status === 'online') return '<span class="pill ok">ONLINE</span>';
            if (device.status === 'offline') return '<span class="pill bad">OFFLINE</span>';
            return '<span class="pill n">NOT TESTED</span>';
        }

        function buildTable() {
            const rows = visible().filter(d => state.filter !== 'un' || !d.group_key);
            rowsEl.innerHTML = rows.map(device => `
                <tr class="${state.flash === String(device.id) ? 'fl' : ''}" data-ref-row="${device.id}">
                    <td><b>${esc(device.name)}</b><div class="mut">${esc(device.model)}</div></td>
                    <td>${esc(device.ip)}</td>
                    <td><select class="in" data-ref-set-group="${device.id}" style="min-width:110px">
                        ${options(GROUP_OPTIONS, device.group_key)}</select></td>
                    <td style="white-space:nowrap"><select class="in" data-ref-set-topology="${device.id}" style="min-width:170px">
                        ${topologyOptions(device)}</select></td>
                    <td>${cpuCell(device.cpu)}</td>
                    <td class="n">${device.traffic_mbps === null ? '<span class="mut">—</span>' : device.traffic_mbps.toFixed(2) + ' Mbps'}</td>
                    <td class="n">${device.users === null || device.users === undefined ? '<span class="mut">—</span>' : device.users}</td>
                    <td>${statusPill(device)}</td>
                    <td><a class="btn" href="/devices/${device.id}/edit/">Edit</a></td>
                </tr>`).join('') || `<tr><td colspan="9" class="mut" style="padding:18px 8px">No devices here yet. Use + Add device, or change a device's Group in the table.</td></tr>`;
        }

        function render() {
            buildSidebar();
            buildSummary();
            buildTable();
        }

        /* ---- persistence: reuse the existing device edit form endpoint ---- */
        function postField(deviceId, name, value, done) {
            // The edit form is POST-only and needs the full field set; load it, then submit.
            fetch(`/devices/${deviceId}/edit/`, { credentials: 'same-origin' })
                .then(response => response.text())
                .then(html => {
                    const doc = new DOMParser().parseFromString(html, 'text/html');
                    const form = doc.querySelector('form[data-device-edit-form]');
                    if (!form) throw new Error('edit form unavailable');
                    const data = new FormData(form);
                    data.set(name, value);
                    return fetch(form.action, { method: 'POST', body: data, credentials: 'same-origin' });
                })
                .then(response => {
                    if (!response.ok) throw new Error('save failed');
                    done && done();
                })
                .catch(() => { window.location.reload(); });
        }

        function setGroup(deviceId, key) {
            const device = byId(deviceId);
            if (!device) return;
            device.group_key = key;
            rebuildSidebarCounts();
            postField(deviceId, 'group', key, () => render());
            render();
        }

        function setTopology(deviceId, key) {
            const device = byId(deviceId);
            if (!device) return;
            device.topology_key = key;
            postField(deviceId, 'topology_parent', key, () => render());
            render();
        }

        function rebuildSidebarCounts() {
            SIDEBAR.forEach(entry => {
                const subset = entry.key === 'all' ? DEVICES
                    : entry.key === 'none' ? DEVICES.filter(d => !d.group_key)
                    : DEVICES.filter(d => d.group_key === entry.key);
                const counts = { online: 0, unknown: 0, offline: 0 };
                subset.forEach(d => { counts[d.status] = (counts[d.status] || 0) + 1; });
                entry.counts = counts;
            });
            SIDEBAR.forEach(entry => { if (entry.key.startsWith('g:')) entry.label = nameOfGroup(entry.key) || entry.label; });
        }

        function nameOfGroup(key) {
            const option = GROUP_OPTIONS.find(o => o.key === key);
            return option ? option.label : '';
        }

        /* ---- events ---- */
        sideEl.addEventListener('click', event => {
            const del = event.target.closest('[data-ref-delete-group]');
            if (del) {
                const entry = SIDEBAR.find(e => e.key === del.dataset.refDeleteGroup) || {};
                const target = document.getElementById('refDeleteGroupDialog');
                if (!target) return;
                target.querySelector('[name="group_label"]').textContent = entry.label || 'this group';
                target.querySelector('form').action = `/devices/groups/${String(del.dataset.refDeleteGroup).split(':')[1]}/delete/`;
                target.showModal();
                return;
            }
            if (event.target.closest('[data-ref-add-group]')) {
                document.getElementById('addGroupDialog')?.showModal();
                return;
            }
            const item = event.target.closest('[data-ref-group]');
            if (!item) return;
            state.group = item.dataset.refGroup;
            state.filter = 'all';
            document.querySelectorAll('[data-ref-filter]').forEach(b => b.classList.toggle('on', b.dataset.refFilter === 'all'));
            render();
        });

        document.addEventListener('click', event => {
            const filter = event.target.closest('[data-ref-filter]');
            if (filter) {
                state.filter = filter.dataset.refFilter;
                document.querySelectorAll('[data-ref-filter]').forEach(b => b.classList.toggle('on', b === filter));
                buildTable();
                return;
            }
            const del = event.target.closest('#refSummary [data-ref-delete-group]');
            if (del) {
                const entry = SIDEBAR.find(e => e.key === del.dataset.refDeleteGroup) || {};
                const target = document.getElementById('refDeleteGroupDialog');
                if (!target) return;
                target.querySelector('[name="group_label"]').textContent = entry.label || 'this group';
                target.querySelector('form').action = `/devices/groups/${String(del.dataset.refDeleteGroup).split(':')[1]}/delete/`;
                target.showModal();
                return;
            }
            const addDevice = event.target.closest('[data-ref-add-device]');
            if (addDevice) document.getElementById('addDeviceDialog')?.showModal();
        });

        rowsEl.addEventListener('change', event => {
            const group = event.target.closest('[data-ref-set-group]');
            if (group) return setGroup(group.dataset.refSetGroup, group.value);
            const topology = event.target.closest('[data-ref-set-topology]');
            if (topology) return setTopology(topology.dataset.refSetTopology, topology.value);
        });

        document.getElementById('refDeleteGroupDialog')?.addEventListener('click', event => {
            if (event.target.closest('[data-close-group-delete]')) event.target.closest('dialog').close();
        });

        render();
    }

    if (typeof document !== 'undefined') {
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
        else start();
    }
})();
