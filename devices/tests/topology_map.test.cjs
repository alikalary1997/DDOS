// Topology map connectors. The lines must run edge-to-edge: from the parent card's right edge
// to the child card's left edge, using the real rendered boxes. Tests that only counted paths
// once passed while a 16px floating fragment was all that rendered, so these assert the
// actual start/end coordinates against the card geometry.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', '..', 'monitor', 'static', 'monitor', 'js', 'topology_map.js'), 'utf8');

function buildDom(links, boxes) {
    const svg = {
        attrs: {}, children: [],
        setAttribute(name, value) { this.attrs[name] = value; },
        replaceChildren() { this.children = []; },
        appendChild(node) { this.children.push(node); },
    };
    const cards = boxes.map(box => ({
        // Real browsers expose `data-topo-card` as `dataset.topoCard`.
        dataset: { topoCard: box.key },
        getBoundingClientRect: () => ({ left: box.left, right: box.right, top: box.top, height: box.height }),
    }));
    const grid = {
        getBoundingClientRect: () => ({ left: 0, top: 0, width: 1000, height: 500 }),
        querySelectorAll: () => cards,
    };
    return {
        document: {
            readyState: 'complete',
            getElementById: id => (id === 'topo-links-data' ? { textContent: JSON.stringify(links) } : null),
            querySelector: sel => (sel === '[data-topo-links]' ? svg : sel === '[data-topo-map]' ? {} : sel === '.topo-columns' ? grid : null),
            createElementNS: () => ({ attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } }),
            addEventListener() {},
        },
        svg,
    };
}

function run(links, boxes) {
    const env = buildDom(links, boxes);
    const factory = new Function('document', 'window', 'requestAnimationFrame', 'cancelAnimationFrame', 'ResizeObserver', source);
    factory(env.document, { addEventListener() {} }, fn => fn(), () => {}, undefined);
    return env.svg;
}

// Parses "M x y L x y" into endpoints.
function segment(d) {
    const m = /^M ([\d.-]+) ([\d.-]+) L ([\d.-]+) ([\d.-]+)$/.exec(d);
    assert.ok(m, `unexpected path syntax: ${d}`);
    return { x1: +m[1], y1: +m[2], x2: +m[3], y2: +m[4] };
}

const all = svg => svg.children.map(node => segment(node.attrs.d));
const byLink = (svg, id) => svg.children.filter(node => node.attrs['data-link'] === id).map(node => segment(node.attrs.d));

test('a single child connects edge-to-edge with no gap at either card', () => {
    const svg = run(
        [{ id: '1-2' }],
        [{ key: '1', left: 0, right: 200, top: 10, height: 80 },
         { key: '2', left: 250, right: 450, top: 10, height: 80 }]);
    const segments = all(svg);
    // The drawing must start exactly on the parent's right edge and end on the child's left edge.
    assert.strictEqual(segments[0].x1, 200, 'starts on the parent card edge');
    assert.strictEqual(segments[segments.length - 1].x2, 250, 'ends on the child card edge');
    // Nothing floats short of the child.
    assert.ok(segments.every(s => s.x1 >= 200 && s.x2 <= 250));
});

test('a skip-level link reaches across the empty columns', () => {
    const svg = run(
        [{ id: '1-4' }],
        [{ key: '1', left: 0, right: 200, top: 10, height: 80 },
         { key: '4', left: 750, right: 950, top: 190, height: 80 }]);
    const segments = all(svg);
    assert.strictEqual(segments[0].x1, 200, 'starts on the parent edge');
    assert.strictEqual(segments[segments.length - 1].x2, 750, 'ends on the far child edge');
    // The vertical trunk is needed because the child is on a different row.
    assert.ok(segments.some(s => s.x1 === s.x2 && s.y1 !== s.y2), 'a trunk connects the two rows');
});

test('multiple children fan out from one shared stub', () => {
    const svg = run(
        [{ id: '1-2' }, { id: '1-3' }],
        [{ key: '1', left: 0, right: 200, top: 10, height: 80 },
         { key: '2', left: 250, right: 450, top: 10, height: 80 },
         { key: '3', left: 250, right: 450, top: 150, height: 80 }]);
    const segments = all(svg);
    // One stub leaves the parent edge only once, not one per child.
    const fromEdge = segments.filter(s => s.x1 === 200);
    assert.strictEqual(fromEdge.length, 1, 'a shared stub, not overlapping lines');
    // Each child still gets a branch landing exactly on its left edge.
    const ends = segments.filter(s => s.x2 === 250).map(s => s.y2).sort((a, b) => a - b);
    assert.deepEqual(ends, [50, 190], 'both children are reached');
    // A single vertical trunk joins the rows.
    assert.strictEqual(segments.filter(s => s.x1 === s.x2).length, 1);
});

test('a card with no children draws nothing', () => {
    const svg = run([], [{ key: '1', left: 0, right: 200, top: 10, height: 80 }]);
    assert.strictEqual(svg.children.length, 0);
});

test('missing cards are skipped instead of throwing', () => {
    const svg = run([{ id: '1-99' }], [{ key: '1', left: 0, right: 200, top: 10, height: 80 }]);
    assert.strictEqual(svg.children.length, 0);
});

test('a child to the left of its parent is not connected', () => {
    const svg = run(
        [{ id: '1-2' }],
        [{ key: '1', left: 400, right: 600, top: 10, height: 80 },
         { key: '2', left: 100, right: 300, top: 10, height: 80 }]);
    assert.strictEqual(svg.children.length, 0);
});

test('malformed link payload never breaks the page', () => {
    const svg = run([{ id: 'nonsense' }], [{ key: '1', left: 0, right: 200, top: 10, height: 80 }]);
    assert.strictEqual(svg.children.length, 0);
});

test('every drawn segment stays inside the parent-to-child span', () => {
    // A busy branch: three children at different rows.
    const svg = run(
        [{ id: '1-2' }, { id: '1-3' }, { id: '1-4' }],
        [{ key: '1', left: 0, right: 200, top: 10, height: 80 },
         { key: '2', left: 300, right: 500, top: 10, height: 80 },
         { key: '3', left: 300, right: 500, top: 150, height: 80 },
         { key: '4', left: 300, right: 500, top: 290, height: 80 }]);
    all(svg).forEach(s => {
        assert.ok(s.x1 >= 200 && s.x2 <= 300, `segment escapes the gutter: ${JSON.stringify(s)}`);
    });
    const ends = svg.children.filter(n => segment(n.attrs.d).x2 === 300).map(n => segment(n.attrs.d).y2);
    assert.strictEqual(ends.length, 3, 'all three children reached');
});
