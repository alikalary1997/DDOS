const test = require('node:test');
const assert = require('node:assert/strict');
const {segments, format, rate} = require('../static/sensors/sensors.js');
test('zero remains zero; missing rates stay unavailable', () => {
    assert.equal(format(0), '0'); assert.equal(format(null), '—'); assert.equal(format(NaN), '—');
    assert.equal(rate(0), '0 bps'); assert.equal(rate(.1), '100 Kbps'); assert.equal(rate(2), '2 Mbps'); assert.equal(rate(2000), '2 Gbps');
});
test('graphs break across failures, missing baselines and polling gaps', () => {
    const sample = (t, value, valid=true) => ({timestamp:new Date(t*1000).toISOString(), in_mbps:value, valid});
    const groups = segments([sample(0,0), sample(10,1), sample(20,null), sample(30,2), sample(40,0,false), sample(50,3), sample(100,4)], 'in_mbps', 10);
    assert.deepEqual(groups.map(g=>g.map(p=>p.value)), [[0,1],[2],[3],[4]]);
});
test('graph retains actual sample timestamps for elapsed-time axis', () => {
    const history = [{timestamp:'2026-10-11T10:00:00Z',cpu:20,valid:true}, {timestamp:'2026-10-11T10:00:17Z',cpu:40,valid:true}];
    const points = segments(history,'cpu',10)[0];
    assert.equal(points[1].time-points[0].time,17000);
    assert.deepEqual(points.map(p=>p.value),[20,40]);
});
