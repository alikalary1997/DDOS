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
    host._shell = { '.tmap-sw-head': el('div', {}), '.tmap-sw-state': el('span', {}), '.tmap-sw-body': el('div', {}) };
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
    const bySelector = { '[data-topo-svg]': svg, '[data-topo-map]': el('section', {}),
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
    return { click: () => handlers.click(), panelHost, fetchCalls };
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
    assert.strictEqual(ui.panelHost._shell['.tmap-sw-state'].textContent, '1 connected · 2 not connected');
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
