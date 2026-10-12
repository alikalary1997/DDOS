// Exercise the real page script against a small DOM fixture, without network access.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

class Element {
    constructor(dataset = {}) { this.dataset = dataset; this.value = ''; this.textContent = ''; this.events = {}; this.hidden = false; }
    addEventListener(name, fn) { this.events[name] = fn; }
    closest() { return null; }
    removeAttribute() {}
    setAttribute() {}
    replaceChildren() {}
    insertRow() { return { insertCell: () => new Element() }; }
    before() {}
    remove() { this.removed = true; }
}

async function fixture() {
    const ids = new Map();
    const get = id => { if (!ids.has(id)) ids.set(id, new Element()); return ids.get(id); };
    const card = new Element({ ipId: '15', address: '5.5.5.55', deviceId: '8',
        monitoringStatus: 'No Data', monitoringEnabled: 'true', provisioningStatus: 'verified' });
    const provision = new Element();
    const message = new Element();
    const monitoringMessage = new Element();
    const detectionBadge = new Element(), detectionMetrics = new Element(), detectionMessage = new Element();
    const detectionEnable = new Element(), detectionDisable = new Element();
    const start = new Element(), stop = new Element(), retained = new Element();
    const metrics = ['status', 'packets', 'pps', 'bytes', 'mbps', 'last_update', 'syn_pps', 'udp_pps'].map(raw => new Element({ raw }));
    card.querySelector = selector => selector === '[data-provisioning-label]' ? provision
        : selector === '[data-ddos-status]' ? detectionBadge : selector === '[data-ddos-metrics]' ? detectionMetrics
        : selector === '[data-ddos-message]' ? detectionMessage
        : selector === '[data-detection-enable]' ? detectionEnable : selector === '[data-detection-disable]' ? detectionDisable
        : selector === '[data-provisioning-message]' ? message
        : selector === '[data-monitoring-message]' ? monitoringMessage
        : selector === '[data-monitor-start]' ? start : selector === '[data-monitor-stop]' ? stop
        : selector === '[data-retained-note]' ? retained
        : selector === '[data-raw="status"]' ? metrics[0] : null;
    card.querySelectorAll = selector => selector.includes(':not') ? metrics.slice(1) : metrics;
    const panel = new Element({ rawDataUrl: '/public-ips/monitoring-data/' });
    const summaries = [new Element({ rawSummary: 'monitoring' }), new Element({ rawSummary: 'unmonitored' })];
    let payload = { rows: [{ id: 15, status: 'Not monitored', monitoring_enabled: true,
        provisioning_status: 'verified', provisioning_code: 'verified', packets: null, pps: null,
        bytes: null, mbps: null, last_update: null }] };
    let fail = false;
    let interval;
    const requests = [];
    const browserIntervals = [];
    const document = {
        getElementById: id => ['addIpDialog', 'id_device', 'rawProvisioningDevices'].includes(id) ? null : get(id),
        querySelector: selector => selector === '[data-raw-data-url]' ? panel : null,
        querySelectorAll: selector => selector === '[data-ip-row]' ? [card]
            : selector === '[data-raw-summary]' ? summaries : selector === '[data-polling-interval]' ? [get('pollingInterval')] : [],
        addEventListener() {}, createElement: () => new Element(),
    };
    const context = { document, window: { addEventListener() {} }, AbortController,
        setTimeout: () => 0, clearTimeout() {}, setInterval: (fn, milliseconds) => { interval = fn; browserIntervals.push(milliseconds); },
        fetch: async (url, options) => {
            requests.push({ url, options });
            if (fail) throw new Error('offline');
            return { ok: true, json: async () => payload };
        },
    };
    vm.runInNewContext(fs.readFileSync('monitor/static/monitor/js/detection_ui.js', 'utf8'), context);
    vm.runInNewContext(fs.readFileSync('monitor/static/monitor/js/public_ips.js', 'utf8'), context);
    await new Promise(resolve => setImmediate(resolve));
    return { card, provision, message, monitoringMessage, metrics, summaries, ids, requests, browserIntervals,
        start, stop, retained, detectionBadge, detectionMetrics, detectionMessage, detectionEnable, detectionDisable,
        poll: async (sample, offline = false, pollingInterval) => {
            if (sample) payload = { rows: [sample], polling_interval: pollingInterval };
            fail = offline;
            await interval();
        } };
}

test('detection severity and independent monitoring health update in place without inventing status', async () => {
    const f = await fixture();
    const sample = {id: 15, status: 'Monitoring', monitoring_enabled: true, provisioning_status: 'verified',
        monitoring_health: 'Active', ddos_status: 'Under Attack', ddos_metrics: [{metric: 'udp_pps'}], pps: 21000};
    await f.poll(sample);
    assert.equal(f.detectionBadge.textContent, 'Under Attack');
    assert.equal(f.detectionBadge.dataset.state, 'under-attack');
    assert.equal(f.detectionMetrics.textContent, 'UDP PPS');
    for (const status of ['Normal', 'Warning', 'Unknown']) {
        await f.poll({...sample, ddos_status: status});
        assert.equal(f.detectionBadge.textContent, status);
    }
    await f.poll({...sample, monitoring_health: 'Stale', retained: true});
    assert.equal(f.card.dataset.monitoringStatus, 'Stale');
    assert.equal(f.detectionBadge.textContent, 'Unknown');
    assert.equal(f.detectionMetrics.textContent, '');
    await f.poll({...sample, monitoring_health: 'Connection Failed'});
    assert.equal(f.detectionBadge.textContent, 'Unknown');
    await f.poll(sample);
    await f.poll(null, true);
    assert.equal(f.detectionBadge.textContent, 'Unknown');
});

test('per-IP detection controls follow persisted preference without changing monitoring', async () => {
    const f = await fixture();
    const sample = {id:15, status:'Monitoring', monitoring_enabled:true, provisioning_status:'verified',
        monitoring_health:'Active', detection_enabled:false, ddos_status:'Unknown', pps:12};
    await f.poll(sample);
    assert.equal(f.detectionEnable.hidden, false);
    assert.equal(f.detectionDisable.hidden, true);
    assert.equal(f.card.dataset.monitoringEnabled, 'true');
    assert.equal(f.metrics.find(metric => metric.dataset.raw === 'pps').textContent, '12');
    await f.poll({...sample, detection_enabled:true, ddos_status:'Normal'});
    assert.equal(f.detectionEnable.hidden, true);
    assert.equal(f.detectionDisable.hidden, false);
    assert.ok(f.requests.every(request => !request.options.method || request.options.method === 'GET'));
});

test('configured RAW interval updates from cache responses without changing browser refresh scheduling', async () => {
    const f = await fixture();
    const sample = {id: 15, status: 'Not monitored', monitoring_enabled: true, provisioning_status: 'verified'};
    const initialScheduling = [...f.browserIntervals];
    await f.poll(sample, false, 60);
    assert.equal(f.ids.get('pollingInterval').textContent, 60);
    await f.poll(sample, false, 2);
    assert.equal(f.ids.get('pollingInterval').textContent, 2);
    assert.deepEqual(f.browserIntervals, initialScheduling);
});

test('missing data renders dashes, separate badges and combined search/device/status filters', async () => {
    const f = await fixture();
    assert.equal(f.card.dataset.monitoringStatus, 'No Data');
    assert.equal(f.provision.textContent, 'Provisioned');
    assert.ok(f.metrics.slice(1).every(metric => metric.textContent === '—'));
    const search = f.ids.get('ipSearch');
    search.value = '9.9'; search.events.input();
    assert.equal(f.card.hidden, true);
    assert.equal(f.ids.get('noMatchingIPs').hidden, false);
    search.value = '5.5'; search.events.input();
    assert.equal(f.card.hidden, false);
    const device = f.ids.get('ipDeviceFilter');
    device.value = '9'; device.events.change(); assert.equal(f.card.hidden, true);
    device.value = '8'; device.events.change(); assert.equal(f.card.hidden, false);
    const status = f.ids.get('ipStatusFilter');
    status.value = 'Active'; status.events.change(); assert.equal(f.card.hidden, true);
    status.value = 'No Data'; status.events.change(); assert.equal(f.card.hidden, false);
    assert.equal(f.ids.get('ipVisibleCount').textContent, 1);
    assert.ok(f.requests.every(request => !request.options.method || request.options.method === 'GET'));
});

test('real zero traffic is preserved and fetch failures label retained metrics', async () => {
    const f = await fixture();
    await f.poll({ id: 15, status: 'Monitoring', monitoring_enabled: true,
        provisioning_status: 'verified', packets: 0, pps: 0, bytes: 0, mbps: 0,
        last_update: '2026-10-10T19:00:00Z' });
    assert.equal(f.metrics[0].textContent, 'Active');
    assert.ok(f.metrics.slice(1, 5).every(metric => metric.textContent === '0'));
    assert.equal(f.summaries[0].textContent, 1);
    await f.poll(null, true);
    assert.equal(f.metrics[0].textContent, 'Stale');
    assert.ok(f.metrics.slice(1, 5).every(metric => metric.textContent === '0'));
    assert.equal(f.summaries[0].textContent, 0);
});

test('conflicts stay separate from monitoring and disabled monitoring never shows traffic', async () => {
    const f = await fixture();
    await f.poll({ id: 15, status: 'Monitoring', monitoring_enabled: false,
        provisioning_status: 'failed', provisioning_code: 'rule_conflict',
        provisioning_message: 'Conflicting destination', packets: 123, mbps: 9 });
    assert.equal(f.provision.textContent, 'Conflict');
    assert.equal(f.provision.dataset.state, 'conflict');
    assert.equal(f.message.textContent, 'Conflicting destination');
    assert.equal(f.metrics[0].textContent, 'Not Monitored');
    assert.ok(f.metrics.slice(1).every(metric => metric.textContent === '—'));
});

test('protocol rates, low Mbps, zero and unavailable samples render without invented traffic', async () => {
    const f = await fixture();
    const metric = name => f.metrics.find(item => item.dataset.raw === name);
    const sample = { id: 15, status: 'Monitoring', monitoring_enabled: true,
        provisioning_status: 'verified', pps: 9.92329, mbps: 0.002222817,
        syn_pps: 0, udp_pps: 9.92329, last_update: '2026-10-11T12:30:00Z' };
    await f.poll(sample);
    assert.equal(metric('syn_pps').textContent, '0');
    assert.equal(metric('udp_pps').textContent, '9.92');
    assert.equal(metric('mbps').textContent, '0.002223');
    await f.poll({ ...sample, syn_pps: null, udp_pps: 0 });
    assert.equal(metric('syn_pps').textContent, '—');
    assert.equal(metric('udp_pps').textContent, '0');
    for (const status of ['Not monitored', 'Connection error', 'No matching RAW rule']) {
        await f.poll({ ...sample, status, monitoring_message: 'Unavailable sample' });
        assert.equal(f.card.dataset.monitoringStatus, 'No Data');
        assert.ok(f.metrics.slice(1).every(item => item.textContent === '—'));
        assert.equal(f.monitoringMessage.textContent, 'Unavailable sample');
    }
});

test('metrics update in place and retain the same displayed values when stopped', async () => {
    const f = await fixture();
    const sample = {id: 15, status: 'Monitoring', monitoring_enabled: true, monitoring_running: true,
        provisioning_status: 'verified', pps: 100, mbps: 0.00224, syn_pps: 100, udp_pps: 0, bytes: 85712,
        last_update: '2026-10-11T12:30:00Z', last_traffic: {pps: 10, mbps: 0.00224, syn_pps: 0, udp_pps: 10,
        last_update: '2026-10-11T12:29:50Z'}};
    await f.poll(sample);
    assert.equal(f.start.hidden, true);
    assert.equal(f.stop.hidden, false);
    const byteField = f.metrics.find(item => item.dataset.raw === 'bytes');
    const synField = f.metrics.find(item => item.dataset.raw === 'syn_pps');
    assert.equal(byteField.textContent, '85,712');
    assert.equal(synField.textContent, '100');
    const next = {...sample, bytes: 955712, syn_pps: 125, last_update: '2026-10-11T12:30:10Z'};
    await f.poll(next);
    assert.equal(byteField.textContent, '955,712');
    assert.equal(synField.textContent, '125');
    await f.poll({...next, status: 'Not monitored', monitoring_enabled: false, monitoring_running: false, retained: true});
    assert.equal(f.start.hidden, false);
    assert.equal(f.stop.hidden, true);
    assert.equal(f.retained.hidden, false);
    assert.equal(f.metrics[0].textContent, 'Saved Sample');
    assert.equal(byteField.textContent, '955,712');
    assert.equal(synField.textContent, '125');
});
