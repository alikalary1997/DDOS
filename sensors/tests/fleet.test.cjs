const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

class Element {
    constructor(dataset = {}) { this.dataset = dataset; this.children = []; this.text = ''; this.hidden = false; this.className = ''; }
    set textContent(value) { this.text = String(value); this.children = []; }
    get textContent() { return this.text + this.children.map(child => child.textContent).join(' '); }
    append(child) { this.children.push(child); }
    replaceChildren() { this.children = []; this.text = ''; }
}

function fixture(fetchResponse) {
    const cpu = new Element({deviceSensor: 'cpu'}), uptime = new Element({deviceSensor: 'uptime'}), traffic = new Element({deviceSensor: 'traffic'});
    const badge = new Element(), api = new Element(), row = new Element({deviceId: '12'});
    row.querySelector = selector => ({'[data-api-cpu]': api, '[data-fleet-sensor-health]': badge}[selector]);
    row.querySelectorAll = selector => selector === '[data-device-sensor]' ? [cpu, uptime, traffic] : [];
    const root = new Element({sensorFleetUrl: '/sensors/fleet/'});
    root.querySelectorAll = selector => ({'[data-device-row]': [row], '[data-device-sensor]': [cpu, uptime, traffic], '[data-fleet-sensor-health]': [badge]}[selector] || []);
    const total = new Element(), active = new Element(), attention = new Element();
    const document = {
        querySelector: selector => selector === '[data-sensor-fleet-url]' ? root : null,
        querySelectorAll: selector => ({'[data-fleet-sensor-count]': [total], '[data-fleet-active-count]': [active], '[data-fleet-needs-attention]': [attention], '[data-fleet-active-count], [data-fleet-needs-attention]': [active, attention]}[selector] || []),
        createElement: () => new Element(),
    };
    let tick, calls = 0;
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../static/sensors/fleet.js'), 'utf8'), {
        document, AbortController,
        setTimeout: () => 1, clearTimeout: () => {}, setInterval: callback => { tick = callback; },
        fetch: async (...args) => { calls++; return fetchResponse(...args); },
    });
    return {cpu, uptime, traffic, badge, api, total, active, attention, tick: () => tick(), calls: () => calls};
}
const flush = () => new Promise(resolve => setImmediate(resolve));
const reading = overrides => ({id: 1, name: 'CPU', kind: 'cpu', enabled: true, status: 'Active', status_tone: 'active', interval: 10,
    cpu: 0, uptime: null, in_mbps: null, out_mbps: null, sample_at: '2026-10-12T09:00:00Z', ...overrides});
const reply = devices => ({ok: true, json: async () => ({devices})});

test('fleet shows separate live metrics, real zero, health counts and safe interface names', async () => {
    const f = fixture(async (url, options) => {
        assert.equal(url, '/sensors/fleet/');
        assert.equal(options.credentials, 'same-origin');
        assert.equal(options.method, undefined);
        return reply({12: [reading({}), reading({id: 2, kind: 'uptime', name: 'Uptime', cpu: null, uptime: '1d 02h 03m 04s'}),
            reading({id: 3, kind: 'traffic', name: 'Uplink', cpu: null, interface_name: '<ether5>', interface_status: 'Up', in_mbps: 0, out_mbps: 1.25})]});
    });
    await flush();
    assert.equal(f.total.textContent, '3'); assert.equal(f.active.textContent, '3'); assert.equal(f.attention.textContent, '0');
    assert.match(f.cpu.textContent, /0%.*Live SNMP/);
    assert.equal(f.api.hidden, true);
    assert.match(f.uptime.textContent, /1d 02h 03m 04s/);
    const trafficBlock = f.traffic.children[0];
    assert.equal(trafficBlock.children[0].children[0].textContent, '<ether5>');
    assert.deepEqual(trafficBlock.children[1].children.map(rate => rate.textContent), ['In 0 Mbps', 'Out 1.25 Mbps']);
    assert.equal(f.badge.textContent, '3 active');
});

test('stale saved readings, first traffic baseline and stopped values remain explicit', async () => {
    const f = fixture(async () => reply({12: [reading({status: 'Stale', status_tone: 'attention', cpu: 22, error: '<No SNMP reply>'}),
        reading({id: 2, name: 'Uptime', kind: 'uptime', enabled: false, status: 'Stopped', status_tone: 'idle', cpu: null, uptime: null, sample_at: null}),
        reading({id: 3, name: 'Traffic', kind: 'traffic', cpu: null, interface_name: 'ether5'})]}));
    await flush();
    assert.match(f.cpu.textContent, /22%.*Stale.*saved reading/);
    const error = f.cpu.children[0].children.find(element => element.className === 'fleet-sensor-error');
    assert.equal(error.children[0].textContent, 'View error');
    assert.equal(error.children[1].textContent, '<No SNMP reply>');
    assert.match(f.uptime.textContent, /\u2014.*Stopped/);
    assert.match(f.traffic.textContent, /In \u2014 Mbps.*Out \u2014 Mbps.*Waiting for rate/);
    assert.equal(f.badge.textContent, 'Needs attention');
    assert.equal(f.active.textContent, '1'); assert.equal(f.attention.textContent, '1');
});

test('failed refresh removes live claims and overlapping refreshes are prevented', async () => {
    let finish, fail = false;
    const f = fixture(() => fail ? Promise.reject(Error('offline')) : new Promise(resolve => { finish = resolve; }));
    await f.tick();
    assert.equal(f.calls(), 1);
    finish(reply({12: [reading({})]})); await flush();
    fail = true; await f.tick();
    assert.equal(f.active.textContent, '\u2014'); assert.equal(f.attention.textContent, '\u2014');
    assert.equal(f.badge.textContent, 'Data unavailable');
    assert.match(f.cpu.textContent, /Sensor data unavailable/);
    assert.doesNotMatch(f.cpu.textContent, /Live SNMP|0%/);
});
