// Save button for Group/Topology edits: changes stage locally, Save writes them, Cancel
// discards. Regression guard for the prefixed field names the edit form actually expects.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', '..', 'monitor', 'static', 'monitor', 'js', 'ref_groups.js'), 'utf8');

function node(tag, attrs = {}) {
    const classes = new Set();
    const el = {
        tagName: tag, dataset: attrs.dataset || {}, innerHTML: '', textContent: '', value: '', hidden: false,
        children: [], classList: {
            add: n => classes.add(n), remove: n => classes.delete(n), contains: n => classes.has(n),
            toggle: (n, on) => { if (on === undefined ? !classes.has(n) : on) classes.add(n); else classes.delete(n); },
        },
        _handlers: {}, attrs,
        addEventListener(type, fn) { this._handlers[type] = fn; },
        close() {}, showModal() {}, focus() {},
        querySelector: () => null, querySelectorAll: () => [],
        insertAdjacentHTML(pos, html) { this.innerHTML += html; },
    };
    return el;
}

function build(devices, groupOptions, topologyOptions) {
    const rowsEl = node('tbody'), sideEl = node('aside'), summaryEl = node('div'), saveBar = node('div');
    saveBar.hidden = true;
    const byId = {
        refRows: rowsEl, refSide: sideEl, refSummary: summaryEl, refSaveBar: saveBar,
        'ref-devices': { textContent: JSON.stringify(devices) },
        'ref-sidebar': { textContent: JSON.stringify([{ key: 'all', label: 'All devices', counts: {} }]) },
        'ref-group-options': { textContent: JSON.stringify(groupOptions) },
        'ref-topology-options': { textContent: JSON.stringify(topologyOptions) },
        'ref-config': { textContent: JSON.stringify({ canAdd: true, canDelete: true }) },
    };
    const posted = [];
    const document = {
        readyState: 'complete', cookie: 'csrftoken=tok',
        getElementById: id => byId[id] || null,
        querySelector: sel => (sel === '[name="csrfmiddlewaretoken"]' ? { value: 'tok' } : null),
        querySelectorAll: () => [], addEventListener() {},
    };
    const editHtml = `<form data-device-edit-form action="/devices/1/edit/">` +
        `<input name="csrfmiddlewaretoken" value="tok">` +
        `<select name="edit-group"><option value="">Top level</option><option value="g:1">Ali</option></select>` +
        `<select name="edit-topology_parent"><option value="">Top level</option></select></form>`;
    const fetchStub = (url, options) => {
        if (!options || !options.method) return Promise.resolve({ ok: true, text: () => Promise.resolve(editHtml) });
        posted.push({ url, body: options.body, accept: options.headers && options.headers.Accept });
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ ok: true }) });
    };
    // The page builds a FormData from the parsed edit form; record what it sets instead of
    // relying on a real DOM implementation.
    class FakeFormData {
        constructor(form) { this.entries = new Map(); if (form && form._fields) form._fields.forEach(([k, v]) => this.entries.set(k, v)); }
        set(k, v) { this.entries.set(k, v); }
        get(k) { return this.entries.get(k); }
    }
    const editForm = { action: '/devices/1/edit/', _fields: [['csrfmiddlewaretoken', 'tok'], ['edit-group', ''], ['edit-topology_parent', '']] };
    new Function('document', 'window', 'fetch', 'DOMParser', 'FormData', source)(
        document, { location: { reload() {} } }, fetchStub,
        class { parseFromString() { return { querySelector: () => editForm }; } }, FakeFormData);
    return { rowsEl, saveBar, posted, document };
}

const DEVICES = [{ id: 1, name: 'NCS', ip: '10.0.0.1', model: 'MikroTik', group_key: '', topology_key: '', cpu: null, traffic_mbps: null, users: null, status: 'online' }];
const GROUPS = [{ key: '', label: 'Ungrouped' }, { key: 'g:1', label: 'Ali' }];
const TOPO = [{ key: 'd:1', label: 'NCS' }];

test('rows show Edit until something changes', () => {
    const ui = build(DEVICES, GROUPS, TOPO);
    assert.match(ui.rowsEl.innerHTML, /data-ref-edit-device="1"/);
    assert.doesNotMatch(ui.rowsEl.innerHTML, /data-ref-save-row/);
    // Editing happens inline now, so no link to the old standalone page.
    assert.doesNotMatch(ui.rowsEl.innerHTML, /href="\/devices\/1\/edit\/"/);
});

test('changing the group reveals a Save button and a save bar', () => {
    const ui = build(DEVICES, GROUPS, TOPO);
    ui.rowsEl._handlers.change({ target: { closest: sel => (sel === '[data-ref-set-group]' ? { dataset: { refSetGroup: '1' }, value: 'g:1' } : null) } });
    assert.match(ui.rowsEl.innerHTML, /data-ref-save-row="1"/);
    assert.strictEqual(ui.saveBar.hidden, false);
    assert.match(ui.saveBar.innerHTML, /unsaved change/);
});

test('nothing is posted until Save is pressed', () => {
    const ui = build(DEVICES, GROUPS, TOPO);
    ui.rowsEl._handlers.change({ target: { closest: sel => (sel === '[data-ref-set-group]' ? { dataset: { refSetGroup: '1' }, value: 'g:1' } : null) } });
    assert.strictEqual(ui.posted.length, 0, 'staging alone must not write');
});

test('Save posts the prefixed field name the edit form expects', async () => {
    const ui = build(DEVICES, GROUPS, TOPO);
    ui.rowsEl._handlers.change({ target: { closest: sel => (sel === '[data-ref-set-group]' ? { dataset: { refSetGroup: '1' }, value: 'g:1' } : null) } });
    ui.rowsEl._handlers.click({ target: { closest: sel => (sel === '[data-ref-save-row]' ? { dataset: { refSaveRow: '1' } } : null) } });
    await new Promise(r => setTimeout(r, 10));
    assert.strictEqual(ui.posted.length, 1);
    assert.strictEqual(ui.posted[0].body.get('edit-group'), 'g:1',
        'the edit form uses Django prefix="edit"; posting "group" silently saved nothing');
    assert.strictEqual(ui.posted[0].accept, 'application/json');
});

test('Cancel discards a staged change without saving', () => {
    const ui = build(DEVICES, GROUPS, TOPO);
    ui.rowsEl._handlers.change({ target: { closest: sel => (sel === '[data-ref-set-group]' ? { dataset: { refSetGroup: '1' }, value: 'g:1' } : null) } });
    ui.rowsEl._handlers.click({ target: { closest: sel => (sel === '[data-ref-cancel-row]' ? { dataset: { refCancelRow: '1' } } : null) } });
    assert.strictEqual(ui.posted.length, 0);
    assert.match(ui.rowsEl.innerHTML, /data-ref-edit-device="1"/, 'back to Edit');
    assert.strictEqual(ui.saveBar.hidden, true);
});

test('selecting the original value again clears the pending change', () => {
    const ui = build(DEVICES, GROUPS, TOPO);
    ui.rowsEl._handlers.change({ target: { closest: sel => (sel === '[data-ref-set-group]' ? { dataset: { refSetGroup: '1' }, value: 'g:1' } : null) } });
    ui.rowsEl._handlers.change({ target: { closest: sel => (sel === '[data-ref-set-group]' ? { dataset: { refSetGroup: '1' }, value: '' } : null) } });
    assert.strictEqual(ui.saveBar.hidden, true, 'no net change, nothing to save');
});
