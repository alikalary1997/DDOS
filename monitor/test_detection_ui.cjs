const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
class Element {
    constructor() { this.dataset={}; this.children=[]; this.textContent=''; this.attributes={}; this.cells=[]; this.events={}; this.value=''; }
    setAttribute(key,value) { this.attributes[key]=value; }
    addEventListener(name,fn) { this.events[name]=fn; }
    append(...items) { this.children.push(...items); }
    replaceChildren() { this.children=[]; this.textContent=''; }
    insertRow() { const row=new Element(); this.children.push(row); return row; }
    insertCell() { const cell=new Element(); this.cells.push(cell); this.children.push(cell); return cell; }
    querySelector(selector) { const key=selector.slice(1,-1); return this.children.find(child=>key in child.attributes) || this.children.map(child=>child.querySelector(selector)).find(Boolean) || null; }
}
const content = node => node.textContent+node.children.map(content).join(' ');
const base = () => ({monitoring:true,polling_interval:2,summary:{devices:1,monitored_devices:1,public_ips:1},
    overview:{total_pps:12,total_mbps:0.001,monitored_ips:1,active_detections:1,attack_ips:0,warning_ips:1,unknown_ips:0},
    system:{worker_running:true,detection_enabled:true,sampled_devices:1},
    devices:[{name:'Test',management_ip:'192.0.2.1',monitored_ips:1,assigned_ips:1,monitoring_health:'Receiving samples',mbps:0.001}],
    rules:[{address:'8.8.8.8',device_name:'Test',management_ip:'192.0.2.1',provisioning_status:'verified',
        monitoring_health:'Active',ddos_status:'Warning',ddos_metrics:[{metric:'syn_pps'}],pps:12,syn_pps:12,udp_pps:0,mbps:0.001,inspect_url:'/public-ips/#ipAddress1'}],
    incidents:[],recent_events:[]});
async function fixture(initial=base()) {
    const elements=new Map(); const get=id=>{if(!elements.has(id)) elements.set(id,new Element());return elements.get(id);};
    const filters=['all','Under Attack'].map(value=>{const button=new Element();button.dataset.eventFilter=value;return button;});
    let payload=initial, fail=false, tick, hold=null; const requests=[];
    const context={document:{getElementById:get,createElement:()=>new Element(),querySelector:()=>({value:'csrf'}),
        querySelectorAll:selector=>selector==='[data-event-filter]'?filters:[],body:{dataset:{monitoringUrl:'/monitoring-data/'}}},
        window:{setTimeout:()=>0,clearTimeout(){},setInterval(fn,ms){assert.equal(ms,2000);tick=fn;}},AbortController,
        fetch:async(url,options)=>{requests.push({url,options}); if(hold) await hold; if(fail) throw new Error('offline');return {ok:true,json:async()=>payload};}};
    vm.runInNewContext(fs.readFileSync('monitor/static/monitor/js/dashboard.js','utf8'),context);
    await new Promise(resolve=>setImmediate(resolve));
    return {get,filters,requests,poll:async(data,offline=false)=>{payload=data;fail=offline;await tick();},
        holdNext(promise){hold=promise;},tick:()=>tick()};
}

test('dashboard shows real traffic and independent detection health beside the correct IP',async()=>{
    const f=await fixture(); const row=f.get('rulesTable').children[0];
    assert.match(content(row.cells[0]),/8.8.8.8/);
    assert.equal(row.cells[0].children[0].href,'/public-ips/#ipAddress1');
    assert.equal(row.querySelector('[data-ddos-status]').textContent,'Warning');
    assert.equal(row.cells[1].dataset.label,'UDP PPS');
    assert.equal(row.cells[1].textContent,'0');
    assert.equal(row.cells[2].dataset.label,'TCP SYN PPS');
    assert.equal(row.cells[2].textContent,'12');
    assert.equal(f.get('overview-total_mbps').textContent,'0.001');
    assert.match(content(f.get('savedDevices')),/Receiving samples/);
});

test('search filters IPs/devices and retained or missing data never becomes live zero',async()=>{
    const f=await fixture(); const search=f.get('dashboardSearch');search.value='other';search.events.input();
    assert.match(content(f.get('rulesTable')),/No matching IPs/);
    search.value='test';search.events.input();assert.match(content(f.get('rulesTable')),/8.8.8.8/);
    const data=base();data.rules[0].monitoring_health='Stale';data.rules[0].ddos_status='Normal';
    await f.poll(data);
    assert.equal(f.get('rulesTable').children[0].querySelector('[data-ddos-status]').textContent,'Unknown');
    assert.equal(f.get('rulesTable').children[0].cells[1].textContent,'\u2014');
    assert.equal(f.get('rulesTable').children[0].cells[2].textContent,'\u2014');
});

test('active incidents, duration, history filters and safe text render from real event payloads',async()=>{
    const data=base();data.incidents=[{...data.rules[0],ddos_status:'Under Attack',duration_seconds:75,started_at:'2026-10-11T10:00:00Z'}];
    data.recent_events=[{address:'<script>bad()</script>',device_name:'Test',severity:'Under Attack',status:'Recovered',
        metrics:[{metric:'udp_pps'}],peak_pps:50,peak_mbps:0.01,duration_seconds:75,history_url:'/ddos-detection/'}];
    const f=await fixture(data);
    assert.equal(f.get('incidentPanel').dataset.state,'under-attack');
    assert.match(content(f.get('incidentsTable')),/01:15/);
    assert.match(content(f.get('incidentsTable')),/TCP SYN PPS/);
    assert.match(content(f.get('recentEvents')),/<script>bad/);
    assert.equal(f.get('recentEvents').children[0].dataset.state,'recovered');
    f.filters[1].events.click();assert.equal(f.filters[1].attributes['aria-pressed'],'true');
    assert.match(content(f.get('recentEvents')),/UDP PPS/);
    data.recent_events[0].severity='Warning';await f.poll(data);
    assert.match(content(f.get('recentEvents')),/No attack events/);
});

test('failed refresh clears live rates, incident status and health instead of retaining green indicators',async()=>{
    const f=await fixture();await f.poll(null,true);
    assert.equal(f.get('status').textContent,'DATA UNAVAILABLE');
    assert.equal(f.get('overview-total_pps').textContent,'\u2014');
    assert.equal(f.get('healthWorker').textContent,'Unknown');
    assert.match(content(f.get('incidentsTable')),/unavailable/);
    assert.equal(f.get('dashboardRefresh').disabled,false);
});

test('refresh does not overlap and retry provisioning retains its existing CSRF POST',async()=>{
    const data=base();data.rules[0].provisioning_status='failed';data.rules[0].retry_url='/public-ips/1/provision/';
    const f=await fixture(data);
    const identity=f.get('rulesTable').children[0].cells[0];const form=identity.children.find(node=>node.method==='POST');
    assert.equal(form.action,'/public-ips/1/provision/');assert.equal(form.children[0].value,'csrf');
    let release;f.holdNext(new Promise(resolve=>release=resolve));
    const pending=f.tick();await f.tick();assert.equal(f.requests.length,2);release();await pending;
    assert.ok(f.requests.every(request=>request.url==='/monitoring-data/' && !request.options.method));
});
