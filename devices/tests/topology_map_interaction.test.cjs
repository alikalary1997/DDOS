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
        classList: null, textContent: '', hidden: false,
        replaceChildren(...kids) { this.children = kids; },
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

test('the detail panel shows the selected device', () => {
    const ui = build(NODES, LINKS);
    ui.nodeEls[3]._handlers.click();
    assert.strictEqual(ui.title.textContent, 'Kalar');
    assert.strictEqual(ui.detail.hidden, false);
    assert.ok(ui.detail.children.length >= 8, 'label/value pairs rendered');
    const text = ui.detail.children.map(child => child.textContent).join(' ');
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
    const text = ui.detail.children.map(child => child.textContent).join(' ');
    assert.match(text, /No data/);
});

test('a root reports top level as its upstream', () => {
    const ui = build(NODES, LINKS);
    ui.nodeEls[0]._handlers.click();
    const text = ui.detail.children.map(child => child.textContent).join(' ');
    assert.match(text, /Top level/);
});

test('a graph with no links still renders without throwing', () => {
    const ui = build([NODES[0], NODES[1]], []);
    ui.nodeEls[0]._handlers.click();
    assert.strictEqual(ui.title.textContent, 'NCS');
});
