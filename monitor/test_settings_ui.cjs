const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

test('settings preview script leaves persistent threshold and polling forms to native POST', () => {
    const elements = new Map();
    const get = id => {
        if (!elements.has(id)) elements.set(id, {events: {}, textContent: '', reset() {},
            addEventListener(name, callback) { this.events[name] = callback; }, querySelectorAll() { return []; }});
        return elements.get(id);
    };
    get('ddosSettingsForm'); get('rawMonitoringSettingsForm'); get('detectionPolicyForm');
    vm.runInNewContext(fs.readFileSync('monitor/static/monitor/js/settings.js', 'utf8'), {
        document: {getElementById: get, querySelectorAll: () => []}, window: {},
    });
    assert.equal(get('ddosSettingsForm').events.submit, undefined);
    assert.equal(get('rawMonitoringSettingsForm').events.submit, undefined);
    assert.equal(get('detectionPolicyForm').events.submit, undefined);
    let prevented = false;
    get('settingsPreviewForm').events.submit({preventDefault() { prevented = true; }});
    assert.equal(prevented, true);
});
