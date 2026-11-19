const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
class Element {
    constructor(tag) { this.tag = tag; this.dataset = {}; this.children = []; this.attributes = {}; this._text = ''; this.classList = {toggle() {}}; }
    set textContent(v) { this._text = String(v); this.children = []; }
    get textContent() { return this._text + this.children.map(c => typeof c === 'string' ? c : c.textContent).join(''); }
    setAttribute(k, v) { this.attributes[k] = v; }
    addEventListener() {}
    get parentNode() { return this._p || (this._p = new Element('p')); }
    append(...items) { this.children.push(...items); }
    replaceChildren(...items) { this.children = items; }
    find(pred, out = []) { if (pred(this)) out.push(this); this.children.forEach(c => c.find && c.find(pred, out)); return out; }
}
// A <select> stand-in: enough for replaceChildren(options) plus reading .options/.value.
class Select extends Element {
    constructor() { super('select'); this._value = ''; this.disabled = false; this.onchange = null; }
    get options() { return this.children; }
    get value() { return this._value; }
    set value(v) { this._value = String(v); }
    addEventListener(type, fn) { if (type === 'change') this.onchange = fn; }
    choose(value) { this.value = value; this.onchange && this.onchange({target: this}); }
}
const metrics = (cpu, mode) => ({
    cpu: {state: 'ok', value: cpu, mode, age_seconds: 3700},
    uptime: {state: 'ok', value: 460853, mode, age_seconds: 3700},
    traffic: {state: 'ok', value: 31.36, mode, age_seconds: 3700, in_mbps: 18.781, out_mbps: 12.582,
              interfaces: [{interface: 'ether1', in_mbps: 18.781, out_mbps: 12.582}], skipped: 0}});
function render(devices, extra = {}) {
    const els = new Map(); const get = id => { if (!els.has(id)) els.set(id, id === 'ddGroup' ? new Select() : new Element('x')); return els.get(id); };
    const data = {can_control: true, bandwidth_scale_mbps: 500, high_cpu: 80, warn_cpu: 65, devices, ...extra};
    get('ddPage').dataset = {dataUrl: '/d/', controlUrl: '/ddos-detection/all/start/'};
    get('ddInitial').textContent = JSON.stringify(data);
    const ctx = {document: {getElementById: get, createElement: t => new Element(t), querySelector: () => new Element('x'), querySelectorAll: () => [], hidden: false},
        window: {setInterval() {}, confirm: () => true}, fetch: async () => ({ok: false}), JSON};
    vm.runInNewContext(fs.readFileSync('monitor/static/monitor/js/ddos_detection.js', 'utf8'), ctx);
    return {grid: get('ddGrid'), get, group: get('ddGroup'), empty: get('ddEmpty')};
}
const device = (cpu, mode) => ({id: 20, name: 'RB-3011', management_ip: '10.0.0.1', enabled: true, monitored: false, attacked: false,
    metrics: metrics(cpu, mode), sensors_url: '/devices/#inspect-20', ips: []});

// --- Group scope ----------------------------------------------------------
// The page is scoped server-side: the payload only ever contains the scoped group's devices,
// and the picker is a read-only readout of that scope.
const scoped = (id, name) => ({...device(20, 'paused'), id, name, group: 'INT'});
const scopedData = () => [scoped(31, 'INT-16'), scoped(34, 'limit-2')];

test('every device the page receives is rendered, and nothing else is requested', () => {
    const ui = render(scopedData(), {scope_group: 'INT'});
    const cards = ui.grid.find(e => e.className === 'dd-device');
    assert.equal(cards.length, 2);
    const text = ui.grid.textContent;
    assert.match(text, /INT-16/); assert.match(text, /limit-2/);
    assert.doesNotMatch(text, /NCS/);
    assert.doesNotMatch(text, /Kalar/);
});

test('summary counts describe the scoped group only', () => {
    const ui = render(scopedData(), {scope_group: 'INT'});
    assert.equal(ui.get('sumMonitored').textContent, '0 / 2');
    assert.equal(ui.get('sumUnmonitored').textContent, '2');
    assert.equal(ui.get('sumIps').textContent, '0 / 0');
});

test('an empty scope says no device is tagged with the group', () => {
    const ui = render([], {scope_group: 'INT'});
    assert.equal(ui.grid.find(e => e.className === 'dd-device').length, 0);
    assert.match(ui.empty.textContent, /No devices are tagged INT/);
});

test('paused saved readings show values with caption, no bar and no warnings', () => {
    const {grid, get} = render([device(95, 'paused')]);
    const text = grid.textContent;
    assert.match(text, /95%/); assert.match(text, /Paused · saved reading/);
    assert.match(text, /31\.4 Mbps/); assert.match(text, /5 days 8 h/);
    assert.equal(grid.find(e => e.className === 'dd-warn').length, 0);
    assert.equal(grid.find(e => e.className === 'dd-bar').length, 0);
    assert.equal(get('sumCpu').textContent, '0');
    const tip = grid.find(e => e.className === 'dd-val' && e.title)[0].title;
    assert.match(tip, /In 18\.781 Mbps \/ Out 12\.582 Mbps.*ether1/);
});
test('stale readings carry a time-ago caption; live readings drive warnings and the High CPU count', () => {
    assert.match(render([device(50, 'stale')]).grid.textContent, /Stale · last reading 62 min ago/);
    const live = render([device(85, 'live')]);
    assert.equal(live.grid.find(e => e.className === 'dd-warn').length, 1);
    assert.equal(live.get('sumCpu').textContent, '1');
    assert.doesNotMatch(live.grid.textContent, /saved reading/);
});
