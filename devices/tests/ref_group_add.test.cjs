// "+ Group" in the sidebar: clicking it reveals an inline name field (reference behaviour),
// Add posts to the create endpoint, Cancel dismisses it.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', '..', 'monitor', 'static', 'monitor', 'js', 'ref_groups.js'), 'utf8');

function node(tag, attrs = {}) {
    const classes = new Set();
    return {
        tagName: tag, dataset: attrs.dataset || {}, innerHTML: '', textContent: '', value: '',
        children: [], classList: {
            add: n => classes.add(n), remove: n => classes.delete(n), contains: n => classes.has(n),
            toggle: (n, on) => { if (on === undefined ? !classes.has(n) : on) classes.add(n); else classes.delete(n); },
        },
        _handlers: {},
        addEventListener(type, fn) { this._handlers[type] = fn; },
        showModal() { this._open = true; }, close() { this._open = false; },
        focus() { this.focused = true; },
        querySelector: () => node('div'), querySelectorAll: () => [],
    };
}

function build(devices, sidebar, groupOptions) {
    const sideEl = node('aside');
    const inputs = {};                 // id -> element, created on demand like a real DOM
    const byId = {
        refRows: node('tbody'), refSide: sideEl, refSummary: node('div'),
        'ref-devices': { textContent: JSON.stringify(devices) },
        'ref-sidebar': { textContent: JSON.stringify(sidebar) },
        'ref-group-options': { textContent: JSON.stringify(groupOptions) },
        'ref-topology-options': { textContent: '[]' },
        'ref-config': { textContent: JSON.stringify({ canAdd: true, canDelete: true, groupCreateUrl: '/devices/groups/' }) },
    };
    const posted = [];
    const document = {
        readyState: 'complete',
        cookie: 'csrftoken=test-token',
        getElementById: id => byId[id] || inputs[id] || null,
        querySelector: sel => (sel === '[name="csrfmiddlewaretoken"]' ? { value: 'test-token' } : null),
        querySelectorAll: () => [],
        addEventListener() {},
    };
    const window = { location: { reload() { document.reloaded = true; } } };
    // Any new input the script looks up (created by the sidebar markup) is materialised here.
    const factory = new Function('document', 'window', 'fetch', source);
    factory(document, window, (url, options) => {
        posted.push({ url, body: options && options.body });
        return Promise.resolve({ ok: true });
    });
    return {
        sideEl, posted, document,
        // materialise the inline input the markup declared
        withInput(value) {
            const input = node('input'); input.value = value;
            byId.refGroupName = input;
            return input;
        },
        click: (target) => sideEl._handlers.click({ target: { closest: sel => (sel === target ? {} : null) } }),
    };
}

const DEVICES = [{ id: 1, name: 'RB-3011', ip: '10.0.0.1', model: 'MikroTik', group_key: '', topology_key: '', cpu: null, traffic_mbps: null, users: null, status: 'online' }];
const SIDEBAR = [{ key: 'all', label: 'All devices', counts: { online: 1 } }, { key: 'none', label: 'Ungrouped', counts: { online: 1 } }];
const GROUPS = [{ key: '', label: 'Ungrouped' }];

test('the sidebar offers a + Group button', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS);
    assert.match(ui.sideEl.innerHTML, /data-ref-add-group/);
});

test('clicking + Group reveals an inline name field with Add and Cancel', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS);
    assert.doesNotMatch(ui.sideEl.innerHTML, /id="refGroupName"/, 'hidden initially');
    ui.click('[data-ref-add-group]');
    const html = ui.sideEl.innerHTML;
    assert.match(html, /id="refGroupName"/, 'the input appears');
    assert.match(html, /data-ref-save-group>Add</);
    assert.match(html, /data-ref-cancel-group/);
    assert.doesNotMatch(html, /addGroupDialog/, 'no modal dialog is used');
});

test('Cancel hides the inline field again', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS);
    ui.click('[data-ref-add-group]');
    ui.click('[data-ref-cancel-group]');
    assert.doesNotMatch(ui.sideEl.innerHTML, /id="refGroupName"/);
});

test('Add posts the typed name to the create endpoint', async () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS);
    ui.click('[data-ref-add-group]');
    ui.withInput('Ahmad');
    ui.click('[data-ref-save-group]');
    assert.strictEqual(ui.posted.length, 1);
    assert.strictEqual(ui.posted[0].url, '/devices/groups/');
    assert.strictEqual(ui.posted[0].body.get('group_name'), 'Ahmad');
    assert.strictEqual(ui.posted[0].body.get('parent'), '', 'created at top level');
});

test('an empty name is refused without calling the server', () => {
    const ui = build(DEVICES, SIDEBAR, GROUPS);
    ui.click('[data-ref-add-group]');
    ui.withInput('   ');
    ui.click('[data-ref-save-group]');
    assert.strictEqual(ui.posted.length, 0, 'nothing sent for a blank name');
});

test('a duplicate name is refused without calling the server', () => {
    const ui = build(DEVICES, SIDEBAR, [{ key: '', label: 'Ungrouped' }, { key: 'g:1', label: 'Ali' }]);
    ui.click('[data-ref-add-group]');
    ui.withInput('ali');
    ui.click('[data-ref-save-group]');
    assert.strictEqual(ui.posted.length, 0, 'names must be unique');
});
