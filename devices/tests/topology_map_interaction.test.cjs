// Topology map interaction: selecting a node traces its branch and fills the detail panel.
// Verified with a DOM stub so the behaviour is checked deterministically (headless
// screenshots do not reliably run post-load click handlers).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', '..', 'monitor', 'static', 'monitor', 'js', 'topology_map.js'), 'utf8');

function classesFor(name) {
    const set = new Set(name ? name.split(' ').filter(Boolean) : []);
    return {
        add: (...names) => names.forEach(n => set.add(n)),
        remove: (...names) => names.forEach(n => set.delete(n)),
        contains: name => set.has(name),
        toggle: (name, on) => { if (on === undefined ? !set.has(name) : on) set.add(name); else set.delete(name); },
        all: () => [...set],
    };
}

function el(name, dataset = {}, children = []) {
    const node = {
        tagName: name, dataset, children, _classes: classesFor(),
        classList: null, textContent: '', innerHTML: '', hidden: false,
        replaceChildren(...kids) { this.children = kids; },
        append(...kids) { this.children.push(...kids); },
        addEventListener(type, fn) { (this._handlers ||= {})[type] = fn; },
        querySelector(sel) { return findIn(this, sel); },
        querySelectorAll(sel) { return findAllIn(this, sel); },
        scrollIntoView() {},
    };
    node.classList = node._classes;
    return node;
}

function matches(node, sel) {
    if (sel.startsWith('[data-') && sel.endsWith(']')) {
        // data-foo-bar -> dataset.fooBar
        const attr = sel.slice(6, -1);
        const key = attr.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        return key in node.dataset;
    }
    if (sel === '.tmap-link') return node.tagName === 'path' && node.dataset.link !== undefined;
    return false;
}

function findAllIn(root, sel) {
    const out = [];
    (function walk(node) {
        node.children?.forEach(child => { if (matches(child, sel)) out.push(child); walk(child); });
    })(root);
    return out;
}
function findIn(root, sel) { return findAllIn(root, sel)[0] || null; }

function build(nodes, links) {
    const nodeEls = nodes.map(n => el('g', { node: String(n.key) }));
    const linkEls = links.map(l => {
        const p = el('path');
        p.dataset.link = `${l.from}-${l.to}`;
        p.dataset.from = String(l.from);
        p.dataset.to = String(l.to);
        return p;
    });
    const svg = el('svg', { topoSvg: '' }, [...linkEls, ...nodeEls]);
    const map = el('section', { topoMap: '' }, [svg]);
    const title = el('h2', { inspectTitle: '' });
    const hint = el('p', { inspectHint: '' });
    const detail = el('dl', { inspectDetail: '' });
    detail.hidden = true;
    const panel = el('aside', { topoInspect: '' }, [title, hint, detail]);

    const bySelector = {
        '[data-topo-svg]': svg, '[data-topo-map]': map, '[data-topo-inspect]': panel,
        '[data-inspect-title]': title, '[data-inspect-hint]': hint, '[data-inspect-detail]': detail,
    };
    const document = {
        readyState: 'complete',
        getElementById: id => (id === 'topo-nodes-data' ? { textContent: JSON.stringify(nodes) } : null),
        querySelector: sel => bySelector[sel] || null,
        createElement: tag => el(tag),
        addEventListener() {},
    };
    new Function('document', 'window', source)(document, { matchMedia: () => ({ matches: false }) });
    return { nodeEls, linkEls, title, hint, detail };
}

const NODES = [
    { key: 1, name: 'NCS', ip: '10.0.0.1', level: 'core', label: 'Network throughput', summary: '100 Mbps', note: 'root' },
    { key: 2, name: 'Limit-1', ip: '10.0.1.1', level: 'limit', label: 'PPPoE servers', summary: '1', note: 'ok' },
    { key: 3, name: 'Limit-6', ip: '10.0.6.1', level: 'limit', label: 'PPPoE servers', summary: '0', note: 'ok' },
    { key: 4, name: 'Kalar', ip: '10.0.4.1', level: 'pppoe', label: 'Towers', summary: '2 towers', note: 'ok' },
    { key: 5, name: 'Tower-A', ip: '10.0.5.1', level: 'tower', label: 'Site', summary: 'No data', note: 'No data' },
];
const LINKS = [{ from: 1, to: 2 }, { from: 1, to: 3 }, { from: 2, to: 4 }, { from: 4, to: 5 }];

test('selecting a node highlights its branch and dims the rest', () => {
    const ui = build(NODES, LINKS);
    ui.nodeEls[3]._handlers.click();          // Kalar (key 4)
    assert.ok(ui.nodeEls[3].classList.contains('is-selected'));
    // Ancestors and descendants stay lit.
    assert.ok(!ui.nodeEls[0].classList.contains('is-dim'), 'root is on the path');
    assert.ok(!ui.nodeEls[1].classList.contains('is-dim'), 'Limit-1 is on the path');
    assert.ok(!ui.nodeEls[4].classList.contains('is-dim'), 'Tower-A is below');
    // Unrelated sibling branch is dimmed.
    assert.ok(ui.nodeEls[2].classList.contains('is-dim'), 'Limit-6 is unrelated');
});

test('only the cables touching the selected device glow', () => {
    // Lighting the whole branch made two limits look identical, so the cable actually belonging
    // to the device you clicked was impossible to pick out.
    const ui = build(NODES, LINKS);
    ui.nodeEls[3]._handlers.click();          // Kalar (key 4), links 1-2, 1-3, 2-4, 4-5
    assert.ok(!ui.linkEls[0].classList.contains('is-active'), 'NCS to Limit-1 does not touch Kalar');
    assert.ok(!ui.linkEls[1].classList.contains('is-active'), 'NCS to Limit-6 does not touch Kalar');
    assert.ok(ui.linkEls[2].classList.contains('is-active'), 'Limit-1 to Kalar is an upstream cable');
    assert.ok(ui.linkEls[3].classList.contains('is-active'), 'Kalar to Tower-A is a downstream cable');
});

test('the detail panel shows the selected device', () => {
    const ui = build(NODES, LINKS);
    ui.nodeEls[3]._handlers.click();
    assert.strictEqual(ui.title.textContent, 'Kalar');
    assert.strictEqual(ui.detail.hidden, false);
    const text = panelMarkup(ui);
    assert.match(text, /Limit-1/, 'reports its upstream');
    assert.match(text, /10\.0\.4\.1/, 'reports its address');
});

test('clicking the selected node again clears the highlight', () => {
    const ui = build(NODES, LINKS);
    ui.nodeEls[3]._handlers.click();
    ui.nodeEls[3]._handlers.click();
    assert.ok(!ui.nodeEls[3].classList.contains('is-selected'));
    assert.ok(!ui.nodeEls[2].classList.contains('is-dim'), 'nothing stays dimmed');
    assert.strictEqual(ui.title.textContent, 'Network overview');
    assert.strictEqual(ui.detail.hidden, true);
});

test('a leaf node has no downstream children counted', () => {
    const ui = build(NODES, LINKS);
    ui.nodeEls[4]._handlers.click();          // Tower-A
    const text = panelMarkup(ui);
    assert.match(text, /Downstream 0 devices/);
    assert.match(text, /Upstream Kalar/);
});

test('a root reports top level as its upstream', () => {
    const ui = build(NODES, LINKS);
    ui.nodeEls[0]._handlers.click();
    assert.match(panelMarkup(ui), /Top level/);
});

test('a graph with no links still renders without throwing', () => {
    const ui = build([NODES[0], NODES[1]], []);
    ui.nodeEls[0]._handlers.click();
    assert.strictEqual(ui.title.textContent, 'NCS');
});

// --- Sensor readings in the detail panel -------------------------------------

function panelMarkup(ui) {
    const parts = [];
    (function walk(node) {
        if (node.innerHTML) parts.push(node.innerHTML);
        if (node.textContent) parts.push(node.textContent);
        node.children?.forEach(walk);
    })(ui.detail);
    return parts.join(' ');
}

const READINGS = [
    {
        key: 1, name: 'NCS', ip: '10.0.0.1', level: 'core', label: 'Network throughput', summary: '100 Mbps', note: 'root',
        readings: { cpu: 82.4, bandwidth_in: 4057.7, bandwidth_out: 3966.96, users: 1700, uptime: '5d 14h 05m 46s', ping_ms: 76.34, packet_loss: 0 },
    },
    {
        key: 2, name: 'Limit-1', ip: '10.0.1.1', level: 'limit', label: 'PPPoE servers', summary: '1', note: 'ok',
        readings: { cpu: 41, bandwidth_in: 12.5, bandwidth_out: 0.5, users: null, uptime: null, ping_ms: null, packet_loss: null },
    },
];

test('the detail panel shows CPU, Bandwidth, Users and Uptime for the selected device', () => {
    const ui = build(READINGS, [{ from: 1, to: 2 }]);
    ui.nodeEls[0]._handlers.click();
    const text = panelMarkup(ui);
    ['CPU', 'Bandwidth', 'Users', 'Uptime'].forEach(label => assert.match(text, new RegExp(label), `${label} stat is shown`));
    assert.match(text, /82<em>%/, 'CPU is rounded and unit-suffixed');
    assert.match(text, /8024\.66<em>Mbps/, 'bandwidth is in + out');
    assert.match(text, /1700/, 'user count is shown');
    assert.match(text, /5d 14h 05m 46s/, 'uptime is shown verbatim');
    assert.match(text, /data-tone="bad"/, 'high CPU uses the bad tone');
});

test('missing readings render as an em dash, never a fabricated zero', () => {
    const ui = build(READINGS, [{ from: 1, to: 2 }]);
    ui.nodeEls[1]._handlers.click();          // Limit-1: no users/uptime sample
    const text = panelMarkup(ui);
    assert.match(text, /is-empty[^>]*>\s*<span>Users<\/span><b>\u2014/, 'users shows a dash, not 0');
    assert.match(text, /is-empty[^>]*>\s*<span>Uptime<\/span><b>\u2014/, 'uptime shows a dash');
    assert.ok(!/Users<\/span><b>0</.test(text), 'a missing user count is not reported as zero');
    assert.match(text, /data-tone="ok"/, 'moderate CPU uses the ok tone');
});

test('a node with no readings at all keeps the panel usable', () => {
    const ui = build([{ key: 9, name: 'Bare', ip: '10.0.9.1', level: 'tower', label: 'Site', summary: 'No data', note: 'No data' }], []);
    ui.nodeEls[0]._handlers.click();
    const text = panelMarkup(ui);
    assert.match(text, /CPU/);
    assert.match(text, /10\.0\.9\.1/, 'connection facts still render');
});
