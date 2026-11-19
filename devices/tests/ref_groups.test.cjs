// Groups page (reference layout): the sidebar, summary and device table are built in the
// browser from JSON payloads. These tests exercise that rendering with the real payload shape.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', '..', 'monitor', 'static', 'monitor', 'js', 'ref_groups.js'), 'utf8');

function node(tag, attrs = {}) {
    const classes = new Set();
    return {
        tagName: tag, _attrs: attrs, dataset: attrs.dataset || {}, innerHTML: '', textContent: '',
        children: [], classList: {
            add: n => classes.add(n), remove: n => classes.delete(n), contains: n => classes.has(n),
            toggle: (n, on) => { if (on === undefined ? !classes.has(n) : on) classes.add(n); else classes.delete(n); },
        },
        _handlers: {},
        addEventListener(type, fn) { this._handlers[type] = fn; },
        showModal() { this._open = true; },
        close() { this._open = false; },
        querySelector: () => null,
        querySelectorAll: () => [],
    };
}

function build(devices, sidebar, groupOptions, topologyOptions) {
    const rowsEl = node('tbody', { id: 'refRows' });
    const sideEl = node('aside', { id: 'refSide' });
    const summaryEl = node('div', { id: 'refSummary' });
    const byId = {
        refRows: rowsEl, refSide: sideEl, refSummary: summaryEl,
        'ref-devices': { textContent: JSON.stringify(devices) },
        'ref-sidebar': { textContent: JSON.stringify(sidebar) },
        'ref-group-options': { textContent: JSON.stringify(groupOptions) },
        'ref-topology-options': { textContent: JSON.stringify(topologyOptions) },
        'ref-config': { textContent: JSON.stringify({ canAdd: true, canDelete: true }) },
    };
    const document = {
        readyState: 'complete',
        cookie: 'csrftoken=test-token',
        getElementById: id => byId[id] || null,
        // The page script looks up a CSRF token for inline group creation.
        querySelector: sel => (sel === '[name="csrfmiddlewaretoken"]' ? { value: 'test-token' } : null),
        querySelectorAll: () => [],
        addEventListener() {},
    };
    new Function('document', 'window', source)(document, { location: { reload() {} } });
    return { rowsEl, sideEl, summaryEl };
}

// Health is derived from each device's own sensors, not from a connection test.
const DEVICES = [
    { id: 1, name: 'RB-3011', ip: '10.3.15.126', model: 'MikroTik', group_key: '', topology_key: '', cpu: 23, traffic_mbps: 164.85, traffic_in: 100, traffic_out: 64.85, uptime_seconds: 90000, users: null, users_state: '', sensor_count: 3, sensor_active: 3 },
    { id: 2, name: 'Ranya-Connection', ip: '172.21.20.2', model: 'MikroTik', group_key: 'g:1', topology_key: 'd:1', cpu: null, traffic_mbps: null, users: 216, users_state: 'Active', sensor_count: 4, sensor_active: 2 },
    { id: 3, name: 'Kalar', ip: '10.30.1.1', model: 'RB4011', group_key: 'g:1', topology_key: 'd:1', cpu: 91, traffic_mbps: 88.2, users: null, users_state: 'Connection Failed', sensor_count: 2, sensor_active: 0 },
];
const SIDEBAR = [
    { key: 'all', label: 'All devices', counts: { ok: 1, wn: 1, bad: 1, idle: 0 } },
    { key: 'g:1', label: 'Ali', counts: { ok: 0, wn: 1, bad: 1, idle: 0 } },
    { key: 'none', label: 'Ungrouped', counts: { ok: 1, wn: 0, bad: 0, idle: 0 } },
];
const GROUPS = [{ key: '', label: 'Ungrouped' }, { key: 'g:1', label: 'Ali' }];
const TOPO = [{ key: 'd:1', label: 'RB-3011' }, { key: 'd:2', label: 'Ranya-Connection' }];

test('the sidebar lists All devices, every group, and Ungrouped', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS, TOPO);
    const html = ui.sideEl.innerHTML;
    assert.match(html, /All devices/);
    assert.match(html, />Ali</);
    assert.match(html, /Ungrouped/);
    // The delete control is offered for real groups only.
    assert.match(html, /data-ref-delete-group="g:1"/);
    assert.doesNotMatch(html, /data-ref-delete-group="all"/);
});

test('the table renders one row per device with inline selects', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS, TOPO);
    const html = ui.rowsEl.innerHTML;
    assert.strictEqual((html.match(/data-ref-row=/g) || []).length, 3);
    assert.match(html, /data-ref-set-group="1"/);
    assert.match(html, /data-ref-set-topology="1"/);
    // Ungrouped is selected when the device has no group.
    assert.match(html, /<option value="" selected>Ungrouped<\/option>/);
});

test('readings that do not exist render as a dash, never as zero', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS, TOPO);
    const ranya = ui.rowsEl.innerHTML.split('data-ref-row="2"')[1].split('</tr>')[0];
    assert.match(ranya, /—/, 'missing CPU/traffic shows an em dash');
    assert.doesNotMatch(ranya, />0 Mbps</);
    // A genuine zero would be shown as 0; here the reading is simply absent.
    assert.match(ranya, />216</, 'the real user count is shown');
});

test('there is no Status column: health comes from the sensors', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS, TOPO);
    assert.doesNotMatch(ui.rowsEl.innerHTML, /pill (ok|bad|n)">(ONLINE|OFFLINE|NOT TESTED)/);
    // A failed PPPoE sensor names itself instead of leaving a blank cell.
    assert.match(ui.rowsEl.innerHTML, /ref-noread[^>]*>Failed</);
});

test('every device row offers a Delete button beside Edit', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS, TOPO);
    const html = ui.rowsEl.innerHTML;
    assert.strictEqual((html.match(/data-ref-delete-device=/g) || []).length, 3, 'one per device');
    assert.match(html, /data-ref-delete-device="1"/);
    // Edit and Delete sit together in the actions cell.
    const row = html.split('data-ref-row="1"')[1].split('</tr>')[0];
    assert.match(row, /data-ref-edit-device="1"/);
    assert.match(row, /data-ref-delete-device="1"/);
    assert.match(row, /ref-delete/);
});

test('every device row offers a Delete button beside Edit', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS, TOPO);
    const html = ui.rowsEl.innerHTML;
    assert.strictEqual((html.match(/data-ref-delete-device=/g) || []).length, 3, 'one per device');
    assert.match(html, /data-ref-delete-device="1"/);
    // Edit and Delete sit together in the actions cell.
    const row = html.split('data-ref-row="1"')[1].split('</tr>')[0];
    assert.match(row, /data-ref-edit-device="1"/);
    assert.match(row, /data-ref-delete-device="1"/);
    assert.match(row, /ref-delete/);
});

test('sensor readings render in their columns', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS, TOPO);
    const html = ui.rowsEl.innerHTML;
    assert.match(html, /ref-traffic/, 'traffic has an in/out readout');
    assert.match(html, /ref-uptime/, 'uptime is shown');
    assert.match(html, /23%/, 'CPU percentage is shown');
});

test('the summary counts only the selected group', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS, TOPO);
    // Default view is all devices.
    assert.match(ui.summaryEl.innerHTML, /All devices/);
    assert.match(ui.summaryEl.innerHTML, /DEGRADED/, 'a device with no working sensor makes the branch degraded');
    const kv = ui.summaryEl.innerHTML;
    assert.match(kv, /<b>3<\/b>/, 'three devices counted');
    assert.match(kv, /Sensors OK/);
});

test('an empty filter says so instead of rendering a broken table', () => {
    const ui = build([], [{ key: 'all', label: 'All devices', counts: {} }, { key: 'none', label: 'Ungrouped', counts: {} }], GROUPS, TOPO);
    assert.match(ui.rowsEl.innerHTML, /No devices here yet/);
    assert.match(ui.summaryEl.innerHTML, /EMPTY/);
});

test('a device never offers itself as its own topology parent', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS, TOPO);
    const row = ui.rowsEl.innerHTML.split('data-ref-row="1"')[1].split('</tr>')[0];
    assert.doesNotMatch(row, /<option value="d:1"[^>]*selected[^>]*>RB-3011/, 'not its own parent');
    assert.doesNotMatch(row, /d:1" selected/, 'device 1 is not listed as its own parent');
});
