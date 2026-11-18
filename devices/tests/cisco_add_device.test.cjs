// Add Device: choosing the Cisco device type leaves only name + IP address.
// The RouterOS API fields (port/SSL/user/password/interface) are hidden and disabled, so the
// browser never submits them and the server stores a credential-less record.
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
    const apiFields = [field(), field(), field(), field(), field()];
    const note = { hidden: false };

    const form = {
        hidden: true,
        dataset: {},
        querySelector(sel) {
            if (sel === '[name="device_type"]') return typeField;
            if (sel === 'input[name$="name"]') return input();
            return null;
        },
        querySelectorAll(sel) {
            if (sel === '[data-api-field]') return list(apiFields);
            if (sel === '[data-api-note]') return list([note]);
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
    return { typeField, apiFields, note };
}

test('a Cisco device hides and disables every RouterOS API field', () => {
    const ui = build('cisco');
    ui.apiFields.forEach(f => assert.strictEqual(f.hidden, true, 'API field is hidden'));
    ui.apiFields.forEach(f => f._inputs.forEach(i => assert.strictEqual(i.disabled, true,
        'a disabled input is not submitted')));
});

test('a MikroTik device shows every API field', () => {
    const ui = build('mikrotik');
    ui.apiFields.forEach(f => assert.strictEqual(f.hidden, false));
    ui.apiFields.forEach(f => f._inputs.forEach(i => assert.strictEqual(i.disabled, false)));
});

test('switching the type to Cisco and back re-reveals the API fields', () => {
    const ui = build('mikrotik');
    ui.typeField.value = 'cisco';
    ui.typeField._handlers.change();
    ui.apiFields.forEach(f => assert.strictEqual(f.hidden, true));
    ui.typeField.value = 'mikrotik';
    ui.typeField._handlers.change();
    ui.apiFields.forEach(f => assert.strictEqual(f.hidden, false));
});

test('Other is treated like Cisco: no RouterOS credentials', () => {
    const ui = build('other');
    ui.apiFields.forEach(f => assert.strictEqual(f.hidden, true));
});
