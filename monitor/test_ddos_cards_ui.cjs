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
const metrics = (cpu, mode) => ({
    cpu: {state: 'ok', value: cpu, mode, age_seconds: 3700},
    uptime: {state: 'ok', value: 460853, mode, age_seconds: 3700},
    traffic: {state: 'ok', value: 31.36, mode, age_seconds: 3700, in_mbps: 18.781, out_mbps: 12.582,
              interfaces: [{interface: 'ether1', in_mbps: 18.781, out_mbps: 12.582}], skipped: 0}});
function render(devices) {
    const els = new Map(); const get = id => { if (!els.has(id)) els.set(id, new Element('x')); return els.get(id); };
    const data = {can_control: true, bandwidth_scale_mbps: 500, high_cpu: 80, warn_cpu: 65, devices};
    get('ddPage').dataset = {dataUrl: '/d/', controlUrl: '/ddos-detection/all/start/'};
    get('ddInitial').textContent = JSON.stringify(data);
    const ctx = {document: {getElementById: get, createElement: t => new Element(t), querySelector: () => new Element('x'), querySelectorAll: () => [], hidden: false},
        window: {setInterval() {}, confirm: () => true}, fetch: async () => ({ok: false}), JSON};
    vm.runInNewContext(fs.readFileSync('monitor/static/monitor/js/ddos_detection.js', 'utf8'), ctx);
    return {grid: get('ddGrid'), get};
}
const device = (cpu, mode) => ({id: 20, name: 'RB-3011', management_ip: '10.0.0.1', enabled: true, monitored: false, attacked: false,
    metrics: metrics(cpu, mode), sensors_url: '/devices/#inspect-20', ips: []});

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
