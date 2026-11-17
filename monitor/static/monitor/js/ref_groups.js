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
        const GROUP_CREATE_URL = CONFIG.groupCreateUrl || '/devices/groups/';
        // CSRF comes from the page's own form token; Django sets the cookie for good measure.
        const csrfToken = document.querySelector('[name="csrfmiddlewaretoken"]')?.value
            || (document.cookie.match(/(?:^|; )csrftoken=([^;]+)/) || [])[1] || '';

        const state = { group: 'all', filter: 'all', flash: '', adding: false, saving: false };
        // Pending edits per device: { group?: key, topology?: key }. Nothing is written until Save.
        const pending = new Map();
        const hasPending = device => pending.has(String(device.id));
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
                    ${CONFIG.canAdd ? '<button type="button" class="btn" data-ref-add-group>+ Group</button>' : ''}</div>
                ${state.adding ? `<div class="ref-add-row">
                    <input class="in" id="refGroupName" placeholder="Group / agent name" maxlength="120" autocomplete="off" style="flex:1;min-width:0">
                    <button type="button" class="btn go" data-ref-save-group>Add</button>
                    <button type="button" class="btn" data-ref-cancel-group title="Cancel" aria-label="Cancel">&times;</button>
                </div><div class="ref-add-error" id="refGroupError" role="alert"></div>` : ''}
                ${SIDEBAR.filter(e => e.key === 'all').map(item).join('')}
                ${grouped.map(item).join('')}
                ${SIDEBAR.filter(e => e.key === 'none').map(item).join('')}
                <div class="mut" style="font-size:11px;margin-top:8px">Counters: <span style="color:var(--ref-ok)">OK</span> ·
                    <span style="color:var(--ref-wn)">warning</span> · <span style="color:var(--ref-bad)">critical</span></div>`;
            // The reference focuses the new input immediately so you can type straight away.
            if (state.adding) document.getElementById('refGroupName')?.focus();
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
        function topologyOptions(device, selected) {
            const value = selected === undefined ? device.topology_key : selected;
            const others = TOPOLOGY_OPTIONS.filter(option => String(option.key) !== `d:${device.id}`);
            return `<option value="">Not connected</option>${options(others, value)}`;
        }

        // Save bar: appears whenever any row has unsaved changes.
        function buildSaveBar() {
            const bar = document.getElementById('refSaveBar');
            if (!bar) return;
            const count = pending.size;
            if (!count) {
                bar.innerHTML = '';
                bar.hidden = true;
                return;
            }
            bar.hidden = false;
            bar.innerHTML = `<span><b>${count}</b> device${count === 1 ? '' : 's'} with unsaved changes</span>
                <span class="sp"></span>
                <button type="button" class="btn" data-ref-discard-all>Discard</button>
                <button type="button" class="btn go" data-ref-save-all${state.saving ? ' disabled' : ''}>${state.saving ? 'Saving…' : 'Save changes'}</button>`;
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

        // Green when enabled, red when disabled (matches the fleet table's toggle).
        function protectionButton(device) {
            if (!CONFIG.canAdd) {
                return device.protection
                    ? '<span class="pill ok">Enabled</span>'
                    : '<span class="pill bad">Disabled</span>';
            }
            const on = !!device.protection;
            return `<button type="button" class="btn ref-protection" data-ref-protection="${device.id}"
                data-state="${on ? 'enabled' : 'disabled'}"
                aria-pressed="${on}"
                title="Click to ${on ? 'disable' : 'enable'} DDoS Protection for ${esc(device.name)}">
                ${on ? 'Enabled' : 'Disabled'}</button>`;
        }

        // Toggle protection for one device; the button shows the switching state meanwhile.
        function toggleProtection(deviceId, button) {
            const device = byId(deviceId);
            if (!device) return;
            const next = !device.protection;
            if (button) {
                button.disabled = true;
                button.textContent = 'Saving…';
            }
            const body = new FormData();
            body.set('enabled', next ? '1' : '0');
            body.set('csrfmiddlewaretoken', csrfToken);
            return fetch(`/devices/${deviceId}/sensors/ddos-protection/toggle/`, {
                method: 'POST', body, credentials: 'same-origin', redirect: 'manual',
            }).then(response => {
                // Django redirects on success; a 4xx means the change did not apply.
                if (response.type !== 'opaqueredirect' && !response.ok && response.status !== 0) {
                    throw new Error('toggle failed');
                }
                device.protection = next;
                render();
            }).catch(() => {
                if (button) { button.disabled = false; button.textContent = device.protection ? 'Enabled' : 'Disabled'; }
                const bar = document.getElementById('refSaveBar');
                if (bar) {
                    bar.hidden = false;
                    bar.insertAdjacentHTML('afterbegin', `<span class="ref-save-error">Could not change Protection for ${esc(device.name)}.</span>`);
                }
            });
        }

        function buildTable() {
            // Reference filters: all / high CPU (>80%) / not connected to topology.
            const rows = visible().filter(d => {
                if (state.filter === 'hi') return d.cpu !== null && d.cpu !== undefined && d.cpu > 80;
                if (state.filter === 'un') return !d.topology_key;
                return true;
            });
            rowsEl.innerHTML = rows.map(device => {
                const edit = pending.get(String(device.id)) || {};
                const groupValue = edit.group !== undefined ? edit.group : device.group_key;
                const topologyValue = edit.topology !== undefined ? edit.topology : device.topology_key;
                const dirty = hasPending(device);
                return `
                <tr class="${state.flash === String(device.id) ? 'fl' : ''}" data-ref-row="${device.id}" data-dirty="${dirty}">
                    <td><b>${esc(device.name)}</b><div class="mut">${esc(device.model)}</div></td>
                    <td>${esc(device.ip)}</td>
                    <td><select class="in" data-ref-set-group="${device.id}" style="min-width:110px">
                        ${options(GROUP_OPTIONS, groupValue)}</select></td>
                    <td style="white-space:nowrap"><select class="in" data-ref-set-topology="${device.id}" style="min-width:170px">
                        ${topologyOptions(device, topologyValue)}</select></td>
                    <td>${cpuCell(device.cpu)}</td>
                    <td class="n">${device.traffic_mbps === null ? '<span class="mut">—</span>' : device.traffic_mbps.toFixed(2) + ' Mbps'}</td>
                    <td class="n">${device.users === null || device.users === undefined ? '<span class="mut">—</span>' : device.users}</td>
                    <td>${statusPill(device)}</td>
                    <td>${protectionButton(device)}</td>
                    <td><a class="btn ref-settings" href="/devices/${device.id}/sensors/?view=settings" title="Open settings for ${esc(device.name)}">Settings</a></td>
                    <td class="ref-row-actions">
                        ${dirty ? `<button type="button" class="btn go" data-ref-save-row="${device.id}">Save</button>
                        <button type="button" class="btn" data-ref-cancel-row="${device.id}" title="Discard changes">Cancel</button>`
                        : `<button type="button" class="btn" data-ref-edit-device="${device.id}">Edit</button>`}
                    </td>
                </tr>`;
            }).join('') || `<tr><td colspan="11" class="mut" style="padding:18px 8px">No devices here yet. Use + Add device, or change a device's Group in the table.</td></tr>`;
            buildSaveBar();
        }

        function render() {
            buildSidebar();
            buildSummary();
            buildTable();
        }

        /* ---- editing: stage changes locally, write only when Save is pressed ---- */
        function stage(deviceId, field, value) {
            const device = byId(deviceId);
            if (!device) return;
            const key = String(deviceId);
            const edit = pending.get(key) || {};
            const originalKey = field === 'topology' ? 'topology_key' : 'group_key';
            // Selecting the stored value again clears the pending flag for that field.
            if (value === device[originalKey]) delete edit[field];
            else edit[field] = value;
            if (Object.keys(edit).length) pending.set(key, edit);
            else pending.delete(key);
            render();
        }

        /* ---- persistence: reuse the existing device edit form endpoint ---- */
        // The edit form is rendered with Django's "edit" prefix, so its real field names are
        // edit-group / edit-topology_parent. Posting the unprefixed pair silently saved nothing.
        const EDIT_FIELD = { group: 'edit-group', topology: 'edit-topology_parent' };

        function postField(deviceId, field, value) {
            // The edit form is POST-only and needs the full field set; load it, then submit.
            return fetch(`/devices/${deviceId}/edit/`, { credentials: 'same-origin' })
                .then(response => {
                    if (!response.ok) throw new Error('edit form unavailable');
                    return response.text();
                })
                .then(html => {
                    const doc = new DOMParser().parseFromString(html, 'text/html');
                    const form = doc.querySelector('form[data-device-edit-form]');
                    if (!form) throw new Error('edit form unavailable');
                    const data = new FormData(form);
                    data.set(EDIT_FIELD[field], value);
                    return fetch(form.action, {
                        method: 'POST', body: data, credentials: 'same-origin',
                        headers: { Accept: 'application/json' },
                    });
                })
                .then(response => {
                    // The view answers JSON when Accept says so; a 400 means validation failed.
                    if (!response.ok) throw new Error('save failed');
                    return true;
                });
        }

        // Push one device's staged changes; resolves true when the server accepted them.
        function saveDevice(deviceId) {
            const key = String(deviceId);
            const edit = pending.get(key);
            const device = byId(deviceId);
            if (!edit || !device) return Promise.resolve(true);
            const work = [];
            if (edit.group !== undefined) work.push(postField(deviceId, 'group', edit.group));
            if (edit.topology !== undefined) work.push(postField(deviceId, 'topology', edit.topology));
            return Promise.all(work).then(() => {
                if (edit.group !== undefined) device.group_key = edit.group;
                if (edit.topology !== undefined) device.topology_key = edit.topology;
                pending.delete(key);
                rebuildSidebarCounts();
                state.flash = key;
                setTimeout(() => { state.flash = ''; render(); }, 5000);
                render();
                return true;
            });
        }

        function saveAll() {
            const ids = [...pending.keys()];
            if (!ids.length) return;
            state.saving = true;
            buildSaveBar();
            Promise.all(ids.map(id => saveDevice(id).catch(() => false)))
                .then(results => {
                    state.saving = false;
                    if (results.some(ok => !ok)) {
                        // Keep the failed rows staged so nothing is silently lost.
                        const bar = document.getElementById('refSaveBar');
                        if (bar) bar.insertAdjacentHTML('afterbegin', '<span class="ref-save-error">Some changes could not be saved. Retry.</span>');
                    }
                    render();
                });
        }

        function discard(deviceId) {
            pending.delete(String(deviceId));
            render();
        }

        /* Create a group from the inline sidebar row, exactly like the reference: the new row
           appears immediately and the sidebar selects it. */
        function createGroup() {
            const input = document.getElementById('refGroupName');
            const errorEl = document.getElementById('refGroupError');
            const name = (input?.value || '').trim();
            if (!name) {
                if (errorEl) errorEl.textContent = 'Enter a group name.';
                input?.focus();
                return;
            }
            // Names are unique in NetShield; catch it here so the inline row can explain it.
            const exists = GROUP_OPTIONS.some(o => String(o.label).toLowerCase() === name.toLowerCase());
            if (exists) {
                if (errorEl) errorEl.textContent = `A group named "${name}" already exists.`;
                return;
            }
            const body = new FormData();
            body.set('group_name', name);
            body.set('parent', '');                 // top level, like the reference
            body.set('next', 'tree');
            body.set('csrfmiddlewaretoken', csrfToken);
            fetch(GROUP_CREATE_URL, { method: 'POST', body, credentials: 'same-origin', redirect: 'manual' })
                .then(() => { window.location.reload(); })
                .catch(() => {
                    if (errorEl) errorEl.textContent = 'The group could not be created. Reload and retry.';
                });
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
                state.adding = true;
                buildSidebar();
                return;
            }
            if (event.target.closest('[data-ref-cancel-group]')) {
                state.adding = false;
                buildSidebar();
                return;
            }
            if (event.target.closest('[data-ref-save-group]')) {
                createGroup();
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
            if (group) return stage(group.dataset.refSetGroup, 'group', group.value);
            const topology = event.target.closest('[data-ref-set-topology]');
            if (topology) return stage(topology.dataset.refSetTopology, 'topology', topology.value);
        });

        /* ---- inline editing: never leave the page for the old edit screen ---- */
        let editingId = null;

        function closeEdit() {
            editingId = null;
            const host = document.getElementById('refEditDevice');
            if (host) { host.hidden = true; host.replaceChildren(); }
        }

        function openEdit(deviceId) {
            const host = document.getElementById('refEditDevice');
            const device = byId(deviceId);
            if (!host || !device) return;
            editingId = String(deviceId);
            // Reuse the server's own edit form so validation and field names stay authoritative.
            fetch(`/devices/${deviceId}/edit/`, { credentials: 'same-origin' })
                .then(response => {
                    if (!response.ok) throw new Error('edit form unavailable');
                    return response.text();
                })
                .then(html => {
                    const doc = new DOMParser().parseFromString(html, 'text/html');
                    const form = doc.querySelector('form[data-device-edit-form]');
                    if (!form) throw new Error('edit form unavailable');
                    // Lay the server form out as the inline card (the CSS handles the grid).
                    form.className = 'card ref-device-form';
                    form.querySelectorAll('.form-grid > label').forEach(label => {
                        if (label.classList && label.classList.contains) label.classList.add('ref-field');
                        else label.className = (label.className ? label.className + ' ' : '') + 'ref-field';
                    });
                    const footer = form.querySelector('.dialog-footer');
                    if (footer) {
                        footer.className = 'ref-form-actions';
                        footer.innerHTML = `<button class="btn go" type="submit">Save changes</button>` +
                            `<button class="btn" type="button" data-ref-edit-cancel>Cancel</button>`;
                    }
                    form.querySelectorAll('.modal-notice').forEach(note => {
                        note.className = 'ref-form-note';
                        note.textContent = 'Database changes only. Leave the password blank to keep it. Router rules are retained.';
                    });
                    // Errors from the server are shown above the fields, not in a dialog.
                    const errors = form.querySelector('[data-management-errors]');
                    if (errors) errors.className = 'ref-form-error';

                    host.replaceChildren(document.importNode(form, true));
                    host.hidden = false;
                    host.querySelector('form').addEventListener('submit', submitEdit);
                    host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    host.querySelector('input[name$="name"]')?.focus();
                })
                .catch(() => {
                    // Last resort only: fall back to the standalone page.
                    window.location.assign(`/devices/${deviceId}/edit/`);
                });
        }

        function submitEdit(event) {
            event.preventDefault();
            const form = event.currentTarget;
            const host = document.getElementById('refEditDevice');
            const button = form.querySelector('button[type=submit]');
            if (button) { button.disabled = true; button.textContent = 'Saving…'; }
            fetch(form.action, {
                method: 'POST', body: new FormData(form), credentials: 'same-origin',
                headers: { Accept: 'application/json' },
            })
                .then(response => response.json().catch(() => ({ ok: false, error: `Save failed (${response.status}).` })))
                .then(result => {
                    if (!result.ok) {
                        // Render field errors in place so nothing is lost.
                        const box = host.querySelector('[data-management-errors]');
                        if (box) {
                            box.classList.add('ref-form-error');
                            const lines = [result.error || 'Device was not saved.'];
                            Object.entries(result.errors || {}).forEach(([, entries]) => {
                                (entries || []).forEach(entry => lines.push(entry.message));
                            });
                            box.innerHTML = lines.filter(Boolean).map(line => `<div>${esc(line)}</div>`).join('');
                        }
                        if (button) { button.disabled = false; button.textContent = 'Save changes'; }
                        return;
                    }
                    // Apply the saved values to the row without a reload.
                    const device = byId(editingId);
                    if (device && result.device) {
                        device.name = result.device.name;
                        device.ip = String(result.device.management_ip);
                        device.model = result.device.model || device.model;
                        device.group_key = result.device.group_id ? `g:${result.device.group_id}` : '';
                        device.topology_key = result.device.topology_parent_id ? `d:${result.device.topology_parent_id}` : '';
                    }
                    closeEdit();
                    rebuildSidebarCounts();
                    state.flash = String(editingId);
                    setTimeout(() => { state.flash = ''; render(); }, 5000);
                    render();
                })
                .catch(() => {
                    const box = host?.querySelector('[data-management-errors]');
                    if (box) { box.classList.add('ref-form-error'); box.textContent = 'The device could not be saved. Please try again.'; }
                    if (button) { button.disabled = false; button.textContent = 'Save changes'; }
                });
        }

        rowsEl.addEventListener('click', event => {
            const edit = event.target.closest('[data-ref-edit-device]');
            if (edit) { openEdit(edit.dataset.refEditDevice); return; }
            const protect = event.target.closest('[data-ref-protection]');
            if (protect) { toggleProtection(protect.dataset.refProtection, protect); return; }
            const saveRow = event.target.closest('[data-ref-save-row]');
            if (saveRow) { saveDevice(saveRow.dataset.refSaveRow); return; }
            const cancelRow = event.target.closest('[data-ref-cancel-row]');
            if (cancelRow) { discard(cancelRow.dataset.refCancelRow); return; }
        });

        document.addEventListener('click', event => {
            if (event.target.closest('[data-ref-edit-cancel]')) { closeEdit(); return; }
            if (event.target.closest('[data-ref-save-all]')) { saveAll(); return; }
            if (event.target.closest('[data-ref-discard-all]')) {
                pending.clear();
                render();
            }
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
