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

const DEVICES = [
    { id: 1, name: 'RB-3011', ip: '10.3.15.126', model: 'MikroTik', group_key: '', topology_key: '', cpu: 23, traffic_mbps: 164.85, users: null, status: 'online', status_label: 'ONLINE' },
    { id: 2, name: 'Ranya-Connection', ip: '172.21.20.2', model: 'MikroTik', group_key: 'g:1', topology_key: 'd:1', cpu: null, traffic_mbps: null, users: 216, status: 'unknown', status_label: 'NOT TESTED' },
    { id: 3, name: 'Kalar', ip: '10.30.1.1', model: 'RB4011', group_key: 'g:1', topology_key: 'd:1', cpu: 91, traffic_mbps: 88.2, users: 121, status: 'offline', status_label: 'OFFLINE' },
];
const SIDEBAR = [
    { key: 'all', label: 'All devices', counts: { online: 1, offline: 1, unknown: 1 } },
    { key: 'g:1', label: 'Ali', counts: { online: 0, offline: 1, unknown: 1 } },
    { key: 'none', label: 'Ungrouped', counts: { online: 1, offline: 0, unknown: 0 } },
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

test('status pills reflect the real device state', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS, TOPO);
    assert.match(ui.rowsEl.innerHTML, /pill ok">ONLINE/);
    assert.match(ui.rowsEl.innerHTML, /pill bad">OFFLINE/);
    assert.match(ui.rowsEl.innerHTML, /pill n">NOT TESTED/);
});

test('the summary counts only the selected group', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS, TOPO);
    // Default view is all devices.
    assert.match(ui.summaryEl.innerHTML, /All devices/);
    assert.match(ui.summaryEl.innerHTML, /CRITICAL/, 'one offline device makes the branch critical');
    const kv = ui.summaryEl.innerHTML;
    assert.match(kv, /<b>3<\/b>/, 'three devices counted');
    assert.match(kv, /Warnings/);
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
