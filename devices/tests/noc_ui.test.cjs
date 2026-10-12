const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class Element {
    constructor(dataset = {}) { this.dataset = dataset; this.events = {}; this.value = ''; this.textContent = ''; this.hidden = false; this.attributes = {}; this.one = {}; this.many = {}; }
    addEventListener(event, fn) { this.events[event] = fn; }
    querySelector(selector) { return this.one[selector] || null; }
    querySelectorAll(selector) { return this.many[selector] || []; }
    setAttribute(key, value) { this.attributes[key] = value; }
    removeAttribute(key) { delete this.attributes[key]; }
    showModal() { this.open = true; }
    close() { this.open = false; }
    focus() { this.focused = true; }
    replaceChildren() {}
    closest() { return null; }
}
function fixture() {
    const ids = new Map();
    const get = key => { if (!ids.has(key)) ids.set(key, new Element()); return ids.get(key); };
    const rows = [new Element({deviceId:'12', deviceStatus:'online', connectionStatus:'online', deviceType:'mikrotik', rawStatus:'Enabled'}),
                  new Element({deviceId:'10', deviceStatus:'not_tested', connectionStatus:'not_tested', deviceType:'mikrotik', rawStatus:'Disabled'})];
    rows[0].cells = ['Company', '10.3.15.122', 'CCR2004'].map(textContent => ({textContent}));
    rows[1].cells = ['Home', '192.168.32.1', 'RB5009'].map(textContent => ({textContent}));
    const views = [new Element({inventoryView:'grid'}), new Element({inventoryView:'matrix'})];
    const inspect = new Element({inspectDevice:'12'});
    const inspector = get('deviceInspector12'); inspector.dataset.deviceInspector = '12';
    const tabs = ['overview','ips','raw','connection','audit'].map(inspectorTab => new Element({inspectorTab}));
    const panels = tabs.map(tab => new Element({inspectorPanel:tab.dataset.inspectorTab}));
    inspector.many['[data-inspector-tab]'] = tabs;
    inspector.many['[data-inspector-panel]'] = panels;
    const summary = new Element({summary:'raw'});
    const button = new Element();
    const form = new Element(); form.action = '/devices/12/test-connection/';
    form.one.button = button; form.one['[name=csrfmiddlewaretoken]'] = {value:'csrf-token'};
    form.closest = () => rows[0];
    const cell = new Element(); rows[0].one['[data-cell="status"]'] = cell;
    const meter = new Element(); rows[0].one['[data-meter="cpu"]'] = meter;
    const document = {
        getElementById: id => ['addDeviceDialog','addDeviceForm'].includes(id) ? null : get(id),
        querySelector: () => inspect,
        querySelectorAll: selector => ({'[data-device-row]':rows,'[data-inventory-view]':views,
            '[data-inspect-device]':[inspect],'[data-device-inspector]':[inspector],
            '[data-test-connection]':[form],'[data-summary]':[summary]})[selector] || [],
        addEventListener() {}, createElement: () => new Element(),
    };
    const requests = [];
    const context = {document, window:{addEventListener(){}}, AbortController,
        setTimeout:()=>0,clearTimeout(){},FormData:class {},
        fetch: async(url, options)=>{requests.push({url,options}); return {headers:{get:()=> 'application/json'},json:async()=>({device:{id:12,status_filter:'offline',connection_status:'offline',test_label:'Last Test Failed',raw_status:'Enabled',cpu_usage:null,ram_usage_percent:null,last_connection_test_succeeded:false},error:'API timeout'})};},
    };
    vm.runInNewContext(fs.readFileSync('monitor/static/monitor/js/devices.js','utf8'),context);
    return {get,rows,views,inspect,inspector,tabs,panels,form,cell,meter,requests,summary};
}
test('grid/matrix switching and combined name/IP/status/RAW filters',()=>{
    const f=fixture();
    f.views[1].events.click(); assert.equal(f.get('inventoryView').dataset.view,'matrix');
    assert.equal(f.views[1].attributes['aria-pressed'],'true');
    f.get('deviceSearch').value='company'; f.get('deviceSearch').events.input();
    assert.equal(f.rows[0].hidden,false); assert.equal(f.rows[1].hidden,true);
    f.get('rawFilter').value='Disabled'; f.get('rawFilter').events.change();
    assert.equal(f.rows[0].hidden,true); assert.equal(f.get('noMatchingDevices').hidden,false);
    f.get('deviceSearch').value='192.168'; f.get('deviceSearch').events.input();
    assert.equal(f.rows[1].hidden,false);
});
test('inspector opens without API requests and tabs support arrow-key navigation',()=>{
    const f=fixture(); f.inspect.events.click(); assert.equal(f.inspector.open,true);
    f.tabs[0].events.keydown({key:'End',preventDefault(){}});
    assert.equal(f.tabs[4].attributes['aria-selected'],'true'); assert.equal(f.panels[4].hidden,false);
    assert.equal(f.panels[0].hidden,true); assert.equal(f.requests.length,0);
});

test('device row clicks do not open the inspector; Actions opens it and regains focus',()=>{
    const f=fixture();
    for (const row of f.rows) row.events.click?.({target:new Element()});
    assert.notEqual(f.inspector.open,true);
    f.inspect.events.click();
    assert.equal(f.inspector.open,true);
    f.inspector.close(); f.inspector.events.close();
    assert.equal(f.inspect.focused,true);
    assert.equal(f.requests.length,0);
});
test('Test Connection keeps saved-ID POST and CSRF, clears stale meters and updates summary',async()=>{
    const f=fixture(); await f.form.events.submit({preventDefault(){}});
    assert.equal(f.requests[0].url,'/devices/12/test-connection/');
    assert.equal(f.requests[0].options.method,'POST');
    assert.equal(f.requests[0].options.headers['X-CSRFToken'],'csrf-token');
    assert.equal(f.cell.textContent,'Last Test Failed'); assert.equal(f.meter.hidden,true);
    assert.equal(f.rows[0].dataset.connectionStatus,'offline'); assert.equal(f.summary.textContent,1);
});
