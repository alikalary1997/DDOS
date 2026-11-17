// Inline device editing: Edit opens the server's form as an in-page card (no navigation),
// Cancel closes it, Save posts JSON and reports errors in place.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', '..', 'monitor', 'static', 'monitor', 'js', 'ref_groups.js'), 'utf8');

function node(tag, attrs = {}) {
    const classes = new Set();
    return {
        tagName: tag, dataset: attrs.dataset || {}, innerHTML: '', textContent: '', value: '', hidden: false,
        className: '', style: {}, children: [], classList: {
            add: n => classes.add(n), remove: n => classes.delete(n), contains: n => classes.has(n),
            toggle: (n, on) => { if (on === undefined ? !classes.has(n) : on) classes.add(n); else classes.delete(n); },
        },
        _handlers: {}, addEventListener(t, f) { this._handlers[t] = f; },
        replaceChildren(...k) { this.children = k; },
        insertAdjacentHTML(p, h) { this.innerHTML += h; },
        scrollIntoView() {}, focus() {},
        querySelector: () => null, querySelectorAll: () => [],
    };
}

// A stand-in for the server's edit form with just the hooks the page script rewrites.
function serverForm() {
    const form = node('form');
    form.action = '/devices/1/edit/';
    const errors = node('div', { 'data-management-errors': '' });
    const submit = node('button');
    form.querySelector = sel => {
        if (sel === '[data-management-errors]') return errors;
        if (sel === 'button[type=submit]') return submit;
        return null;
    };
    form.querySelectorAll = () => ({ forEach: () => {} });
    form._errors = errors;
    form._submit = submit;
    return form;
}

function build({ failSave = false } = {}) {
    const rowsEl = node('tbody'), sideEl = node('aside'), summaryEl = node('div');
    const editHost = node('div'); editHost.hidden = true;
    const saveBar = node('div'); saveBar.hidden = true;
    const form = serverForm();
    // The page imports the parsed form into the host and then queries it back.
    editHost.querySelector = sel => (sel === 'form' ? editHost.children[0] || null
        : sel === '[data-management-errors]' ? form._errors
        : sel === 'input[name$="name"]' ? node('input') : null);
    const byId = {
        refRows: rowsEl, refSide: sideEl, refSummary: summaryEl, refSaveBar: saveBar, refEditDevice: editHost,
        'ref-devices': { textContent: JSON.stringify([{ id: 1, name: 'NCS', ip: '10.0.0.1', model: 'MikroTik', group_key: '', topology_key: '', cpu: null, traffic_mbps: null, users: null, status: 'online', protection: false }]) },
        'ref-sidebar': { textContent: JSON.stringify([{ key: 'all', label: 'All devices', counts: {} }]) },
        'ref-group-options': { textContent: '[]' },
        'ref-topology-options': { textContent: '[]' },
        'ref-config': { textContent: JSON.stringify({ canAdd: true, canDelete: true }) },
    };
    const calls = [];
    const documentHandlers = {};
    const document = {
        readyState: 'complete', cookie: 'csrftoken=t',
        getElementById: id => byId[id] || null,
        querySelector: sel => (sel === '[name="csrfmiddlewaretoken"]' ? { value: 't' } : null),
        querySelectorAll: () => [],
        addEventListener(t, f) { documentHandlers[t] = f; },
        importNode: n => n,
    };
    const fetchStub = (url, options) => {
        if (!options || !options.method) {
            calls.push({ kind: 'load', url });
            return Promise.resolve({ ok: true, text: () => Promise.resolve('') });
        }
        calls.push({ kind: 'save', url, accept: options.headers && options.headers.Accept });
        if (failSave) return Promise.resolve({ ok: false, status: 400, json: () => Promise.resolve({ ok: false, error: 'Device was not saved.', errors: { 'edit-name': [{ message: 'This field is required.' }] } }) });
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ ok: true, device: { id: 1, name: 'NCS-2', management_ip: '10.0.0.9', model: 'MikroTik' } }) });
    };
    new Function('document', 'window', 'fetch', 'DOMParser', 'FormData', source)(
        document, { location: { assign: () => calls.push({ kind: 'navigate' }), reload() {} } },
        fetchStub, class { parseFromString() { return { querySelector: () => form }; } },
        class { constructor() {} });
    return { rowsEl, editHost, calls, saveBar, documentHandlers, form };
}

const clickEdit = ui => ui.rowsEl._handlers.click({ target: { closest: sel => (sel === '[data-ref-edit-device]' ? { dataset: { refEditDevice: '1' } } : null) } });

test('Edit is a button, not a link to the old page', () => {
    const ui = build();
    assert.match(ui.rowsEl.innerHTML, /data-ref-edit-device="1"/);
    assert.doesNotMatch(ui.rowsEl.innerHTML, /href="\/devices\/1\/edit\/"/);
});

test('clicking Edit loads the form inline and never navigates away', async () => {
    const ui = build();
    clickEdit(ui);
    await new Promise(r => setTimeout(r, 20));
    assert.ok(ui.calls.some(c => c.kind === 'load' && c.url === '/devices/1/edit/'));
    assert.ok(!ui.calls.some(c => c.kind === 'navigate'), 'must stay on the Devices page');
    assert.strictEqual(ui.editHost.hidden, false);
});

test('Cancel closes the inline card', async () => {
    const ui = build();
    clickEdit(ui);
    await new Promise(r => setTimeout(r, 20));
    ui.documentHandlers.click({ target: { closest: sel => (sel === '[data-ref-edit-cancel]' ? {} : null) } });
    assert.strictEqual(ui.editHost.hidden, true);
    assert.ok(!ui.calls.some(c => c.kind === 'navigate'));
});

test('saving posts JSON and updates the row', async () => {
    const ui = build();
    clickEdit(ui);
    await new Promise(r => setTimeout(r, 20));
    const form = ui.editHost.children[0];
    await form._handlers.submit({ preventDefault() {}, currentTarget: form });
    await new Promise(r => setTimeout(r, 20));
    const save = ui.calls.find(c => c.kind === 'save');
    assert.ok(save, 'the save request was sent');
    assert.strictEqual(save.accept, 'application/json');
    assert.strictEqual(ui.editHost.hidden, true, 'card closes after a successful save');
    assert.match(ui.rowsEl.innerHTML, /NCS-2/, 'the row shows the saved name');
});

test('a rejected save keeps the card open and shows the error', async () => {
    const ui = build({ failSave: true });
    clickEdit(ui);
    await new Promise(r => setTimeout(r, 20));
    const form = ui.editHost.children[0];
    await form._handlers.submit({ preventDefault() {}, currentTarget: form });
    await new Promise(r => setTimeout(r, 20));
    assert.strictEqual(ui.editHost.hidden, false, 'stays open so nothing is lost');
    assert.match(form._errors.innerHTML, /This field is required/);
});
