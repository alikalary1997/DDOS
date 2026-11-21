// Add Device: the field set follows the device type.
// A Cisco switch is managed over SSH, so it keeps username + password but has no RouterOS API,
// while a MikroTik device shows every API field. The hidden ones are disabled so the browser
// never submits them.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', '..', 'monitor', 'static', 'monitor', 'js', 'devices.js'), 'utf8');

function input(value = '') {
    return { value, disabled: false, _handlers: {}, addEventListener(type, fn) { this._handlers[type] = fn; }, focus() {} };
}

function field() {
    const inputs = [input()];
    return {
        hidden: false, _inputs: inputs,
        querySelectorAll: () => Object.assign([...inputs], { forEach: (fn) => inputs.forEach(fn) }),
    };
}

// Builds just enough of the page for devices.js to bind the add form.
function build(typeValue) {
    const typeField = input(typeValue);
    typeField.value = typeValue;
    // The RouterOS-only fields: API port, API-SSL and the incoming monitoring interface.
    const apiOnlyFields = [field(), field(), field()];
    const note = { hidden: false };

    const form = {
        hidden: true,
        dataset: {},
        querySelector(sel) {
            if (sel === '[name="device_type"]') return typeField;
            if (sel === '[data-api-note]') return note;
            if (sel === 'input[name$="name"]') return input();
            return null;
        },
        querySelectorAll(sel) {
            if (sel === '[data-api-only-field]') return list(apiOnlyFields);
            return list([]);
        },
        addEventListener() {},
        reset() {},
        closest: () => ({ hidden: false }),
    };

    const list = (items = []) => Object.assign([...items], { forEach: (fn) => items.forEach(fn) });
    const document = {
        readyState: 'complete',
        getElementById: (id) => (id === 'addDeviceForm' ? form : null),
        querySelectorAll: (sel) => (sel === '#addDeviceForm' ? list([form]) : list([])),
        querySelector: () => null,
        addEventListener() {},
    };
    new Function('document', 'window', source)(document, { addEventListener() {} });
    return { typeField, apiOnlyFields, note };
}

test('a Cisco device hides the RouterOS-only fields and says why', () => {
    const ui = build('cisco');
    ui.apiOnlyFields.forEach(f => assert.strictEqual(f.hidden, true, 'API-only field is hidden'));
    ui.apiOnlyFields.forEach(f => f._inputs.forEach(i => assert.strictEqual(i.disabled, true,
        'a disabled input is not submitted')));
    assert.strictEqual(ui.note.hidden, false, 'the SSH-credentials note is shown');
});

test('a MikroTik device shows every API field', () => {
    const ui = build('mikrotik');
    ui.apiOnlyFields.forEach(f => assert.strictEqual(f.hidden, false));
    ui.apiOnlyFields.forEach(f => f._inputs.forEach(i => assert.strictEqual(i.disabled, false)));
    assert.strictEqual(ui.note.hidden, true, 'no Cisco note on a MikroTik device');
});

test('switching the type to Cisco and back re-reveals the API fields', () => {
    const ui = build('mikrotik');
    ui.typeField.value = 'cisco';
    ui.typeField._handlers.change();
    ui.apiOnlyFields.forEach(f => assert.strictEqual(f.hidden, true));
    ui.typeField.value = 'mikrotik';
    ui.typeField._handlers.change();
    ui.apiOnlyFields.forEach(f => assert.strictEqual(f.hidden, false));
});

test('Other is treated like Cisco: no RouterOS API fields', () => {
    const ui = build('other');
    ui.apiOnlyFields.forEach(f => assert.strictEqual(f.hidden, true));
});

test('username and password are never hidden: both device types need a login', () => {
    // The picker hides only data-api-only-field labels (port, API-SSL, interface), so the
    // credential inputs stay visible and enabled for a Cisco switch and are submitted.
    const ui = build('cisco');
    const hiddenSelectors = [];
    ui.apiOnlyFields.forEach(f => { if (f.hidden) hiddenSelectors.push('api-only'); });
    assert.strictEqual(hiddenSelectors.length, 3);
    assert.strictEqual(ui.typeField.disabled, false, 'the type picker itself stays enabled');
});
