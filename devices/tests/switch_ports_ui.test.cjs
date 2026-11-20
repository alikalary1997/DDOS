// Topology map: selecting a Cisco switch opens its live port panel.
// The grid is the reference's port square — green when the link is up, red when nothing is
// plugged in, hatched when an operator shut the port. These tests pin that mapping and the
// honest failure path, because a wrong colour here misreports live customer cabling.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', '..', 'monitor', 'static', 'monitor', 'js', 'topology_map.js'), 'utf8');

// A tiny DOM stand-in. Every innerHTML write anywhere in the tree is recorded on `writes` so a
// test can assert what the panel rendered without modelling full HTML parsing.
const writes = [];
function el(tag, dataset = {}) {
    let html = '';
    const node = {
        tagName: tag, dataset: { ...dataset }, children: [], textContent: '', hidden: false,
        classList: { add() {}, remove() {}, contains: () => false, toggle() {} },
        addEventListener() {}, replaceChildren(...kids) { this.children = kids; },
        querySelector(sel) { return findIn(this, sel); },
        querySelectorAll(sel) { return findAllIn(this, sel); },
        scrollIntoView() {},
    };
    Object.defineProperty(node, 'innerHTML', {
        get() { return html; },
        set(value) {
            html = value;
            writes.push(value);
            // Port squares, so a test can read each one's rendered state.
            node.children = [...value.matchAll(/class="tmap-port"[^>]*data-port="(\d+)"[^>]*data-state="([a-z]+)"/g)]
                .map(m => el('button', { port: m[1], state: m[2] }));
        },
    });
    return node;
}

function matches(node, sel) {
    if (sel.startsWith('[data-') && sel.endsWith(']')) {
        const attr = sel.slice(6, -1);
        const key = attr.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        return key in node.dataset;
    }
    return false;
}
function findAllIn(root, sel) {
    const out = [];
    (function walk(node) { node.children?.forEach(child => { if (matches(child, sel)) out.push(child); walk(child); }); })(root);
    return out;
}
function findIn(root, sel) { return findAllIn(root, sel)[0] || null; }

function buildPanel() {
    const host = el('div', {});
    host.dataset.portsUrlTemplate = '/devices/topology/map/switch/0/ports/';
    host.hidden = true;
    // The script looks these up after writing the shell HTML; a real DOM would have parsed it,
    // so the stub returns stand-in children that record their own renders.
    // The Back button records the handler the script binds to it.
    const backButton = { _handler: null, addEventListener(type, fn) { if (type === 'click') this._handler = fn; } };
    host._shell = { '.tmap-sw-head': el('div', {}), '.tmap-sw-state': el('span', {}),
        '[data-sw-state]': el('span', {}), '.tmap-sw-body': el('div', {}),
        '[data-switch-back]': backButton };
    const base = host.querySelector.bind(host);
    host.querySelector = (sel) => host._shell[sel] || base(sel);
    return host;
}

// The panel's body is filled with innerHTML; the last write is the rendered panel.
const lastWrite = () => writes[writes.length - 1] || '';

function run(payload) {
    const nodes = [{ key: 36, name: 'Sarchl', ip: '10.10.10.15', device_type: 'cisco', level: 'tower', readings: {} }];
    const handlers = {};
    const nodeEl = el('g', { node: '36' });
    nodeEl.dataset.node = '36';
    nodeEl.classList.contains = () => false;
    nodeEl.addEventListener = (type, fn) => { handlers[type] = fn; };
    const linkList = [];
    const svg = el('svg', { topoSvg: '' }, [nodeEl]);
    svg.querySelectorAll = (sel) => (sel === '[data-node]' ? [nodeEl] : linkList);
    const panelHost = buildPanel();
    const detail = el('div', { inspectDetail: '' });
    const title = el('h2', { inspectTitle: '' });
    const mapView = el('div', { topoView: '', 'topo-view': '' });
    mapView.hidden = false;
    const bySelector = { '[data-topo-view]': mapView, '[data-topo-svg]': svg, '[data-topo-map]': el('section', {}),
        '[data-topo-inspect]': el('aside', {}, [title]),
        '[data-inspect-title]': title, '[data-inspect-hint]': el('p', {}), '[data-inspect-detail]': detail };
    const document = {
        readyState: 'complete',
        getElementById: (id) => (id === 'topo-nodes-data' ? { textContent: JSON.stringify(nodes) }
            : id === 'tmapSwitch' ? panelHost : null),
        querySelector: sel => bySelector[sel] || null,
        createElement: tag => el(tag),
        addEventListener() {},
    };
    const fetchCalls = [];
    const window = { matchMedia: () => ({ matches: false }) };
    const fetchImpl = (url) => {
        fetchCalls.push(url);
        return Promise.resolve({ json: () => Promise.resolve(payload) });
    };
    new Function('document', 'window', 'fetch', source)(document, window, fetchImpl);
    return { click: () => handlers.click(), panelHost, fetchCalls, mapView };
}

const PAYLOAD = {
    ok: true, name: 'Sarchl', ip: '10.10.10.15', total: 3, connected: 1, disabled: 1,
    ports: [
        { index: 10101, name: 'GigabitEthernet0/1', oper: 'up', admin: 'up', speed_mbps: 1000, alias: '' },
        { index: 10102, name: 'GigabitEthernet0/2', oper: 'down', admin: 'up', speed_mbps: 0, alias: '' },
        { index: 10103, name: 'GigabitEthernet0/3', oper: 'down', admin: 'down', speed_mbps: 0, alias: '' },
    ],
};

test("selecting a switch opens its panel and requests that switch's ports", () => {
    writes.length = 0;
    const ui = run(PAYLOAD);
    ui.click();
    assert.strictEqual(ui.panelHost.hidden, false);
    assert.deepEqual(ui.fetchCalls, ['/devices/topology/map/switch/36/ports/'],
        'the URL is built from the page template with the real device id');
});

test('green means the link is up, red means not connected, hatched means disabled', async () => {
    writes.length = 0;
    const ui = run(PAYLOAD);
    ui.click();
    await new Promise(r => setTimeout(r, 0));
    const html = lastWrite();
    assert.match(html, /data-port="10101" data-state="up"/);
    assert.match(html, /data-port="10102" data-state="down"/);
    assert.match(html, /data-port="10103" data-state="disabled"/);
});

test('the port square shows the port number and is labelled by its full name', async () => {
    writes.length = 0;
    const ui = run(PAYLOAD);
    ui.click();
    await new Promise(r => setTimeout(r, 0));
    const html = lastWrite();
    assert.match(html, />0\/1</, 'the square reads 0/1, not GigabitEthernet0/1');
    assert.match(html, /title="GigabitEthernet0\/1 — up"/);
});

test('the header reports connected and not-connected counts', async () => {
    writes.length = 0;
    const ui = run(PAYLOAD);
    ui.click();
    await new Promise(r => setTimeout(r, 0));
    assert.strictEqual(ui.panelHost._shell['[data-sw-state]'].textContent, '1 connected · 2 not connected');
});

test('an SNMP failure says so instead of drawing a made-up grid', async () => {
    writes.length = 0;
    const ui = run({ ok: false, error: 'Test and save SNMP credentials for this device first.' });
    ui.click();
    await new Promise(r => setTimeout(r, 0));
    const html = lastWrite();
    assert.doesNotMatch(html, /class="tmap-port"/, 'no port squares are drawn');
    assert.match(html, /SNMP credentials/);
    assert.match(html, /unavailable/i);
});

test('a switch with no physical ports says so', async () => {
    writes.length = 0;
    const ui = run({ ok: true, total: 0, connected: 0, ports: [] });
    ui.click();
    await new Promise(r => setTimeout(r, 0));
    assert.match(lastWrite(), /no physical ports/i);
});

test('selecting a switch hides the topology table and shows the switch view', () => {
    writes.length = 0;
    const ui = run(PAYLOAD);
    ui.click();
    assert.strictEqual(ui.mapView.hidden, true, 'the topology table is hidden');
    assert.strictEqual(ui.panelHost.hidden, false, 'the switch view is shown');
    assert.match(lastWrite(), /SWITCH/, 'the switch header is rendered');
});

test('the switch view carries a button back to the topology', () => {
    writes.length = 0;
    const ui = run(PAYLOAD);
    ui.click();
    const shell = writes[0] || '';
    assert.match(shell, /data-switch-back/, 'the Back button is part of the switch view');
    assert.match(shell, /Back to topology/);
    assert.match(shell, />Sarchl</, 'the switch name is the view heading');
});

test('going back restores the topology table and closes the switch view', async () => {
    writes.length = 0;
    const ui = run(PAYLOAD);
    ui.click();
    await new Promise(r => setTimeout(r, 0));
    assert.strictEqual(ui.mapView.hidden, true, 'the map is hidden while the switch is open');
    // Invoke the bound Back handler, as a click would.
    ui.panelHost._shell['[data-switch-back]']._handler();
    assert.strictEqual(ui.mapView.hidden, false, 'the topology table is shown again');
    assert.strictEqual(ui.panelHost.hidden, true, 'the switch view is closed');
});

const WITH_NEIGHBOURS = {
    ok: true, name: 'Sarchl', ip: '10.10.10.15', total: 2, connected: 2, disabled: 0, neighbor_count: 3,
    readings: { ping_ms: 11.5, packet_loss: 0, bandwidth_in: 400.2, bandwidth_out: 120.5,
                uptime: '1d 03h 10m', neighbors: 3, cpu: null, users: null },
    ports: [
        { index: 10101, name: 'GigabitEthernet0/1', oper: 'up', admin: 'up', speed_mbps: 1000,
          alias: '', neighbors: [{ name: 'RB-tower', port: 'ether1', platform: 'RouterOS 7' }] },
        { index: 10102, name: 'GigabitEthernet0/2', oper: 'up', admin: 'up', speed_mbps: 1000,
          alias: '', neighbors: [] },
    ],
};

test('the switch view shows the sensor readings as tiles', async () => {
    writes.length = 0;
    const ui = run(WITH_NEIGHBOURS);
    ui.click();
    await new Promise(r => setTimeout(r, 0));
    const html = lastWrite();
    assert.match(html, /<span>Ping<\/span>/);
    assert.match(html, /11\.5/, 'ping value is shown');
    assert.match(html, /<span>Bandwidth<\/span>/);
    assert.match(html, /400\.2/, 'inbound bandwidth is shown');
    assert.match(html, /<span>Uptime<\/span>/);
    assert.match(html, /1d 03h 10m/);
    assert.match(html, /<span>Neighbours<\/span>/);
});

test('a missing reading is a dash, never a fabricated zero', async () => {
    writes.length = 0;
    const data = { ...WITH_NEIGHBOURS, readings: { ...WITH_NEIGHBOURS.readings, ping_ms: null } };
    const ui = run(data);
    ui.click();
    await new Promise(r => setTimeout(r, 0));
    // The Ping tile falls back to an em dash rather than 0.0 ms.
    assert.match(lastWrite(), /<span>Ping<\/span><b>—/);
});

test('a port with a neighbour is marked so it can be found at a glance', async () => {
    writes.length = 0;
    const ui = run(WITH_NEIGHBOURS);
    ui.click();
    await new Promise(r => setTimeout(r, 0));
    const html = lastWrite();
    assert.match(html, /tmap-port-dot/, 'the linked port carries a marker');
    assert.match(html, /1 neighbour/);
});
