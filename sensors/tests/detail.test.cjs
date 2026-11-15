/* Sensor detail helpers: reading formatting and gauge arcs. No DOM, no npm deps. */
const test = require('node:test');
const assert = require('node:assert');
const detail = require('../static/sensors/detail.js');

test('format rounds to the requested digits and shows an em dash for missing data', () => {
    assert.strictEqual(detail.format(1.23456), '1.235');
    assert.strictEqual(detail.format(1.23456, 1), '1.2');
    assert.strictEqual(detail.format(null), '—');
    assert.strictEqual(detail.format(undefined), '—');
});

test('rate switches units without inventing precision', () => {
    assert.strictEqual(detail.rate(1500), '1.5 Gbps');
    assert.strictEqual(detail.rate(12.5), '12.5 Mbps');
    assert.strictEqual(detail.rate(0.002), '2 Kbps');
    assert.strictEqual(detail.rate(null), '—');
});

test('duration renders days/hours/minutes from stored seconds', () => {
    assert.strictEqual(detail.duration(3725), '0d 1h 2m');
    assert.strictEqual(detail.duration(null), '—');
});

test('reading describes the latest point for every sensor kind', () => {
    assert.strictEqual(detail.reading(null), '—');
    assert.strictEqual(detail.reading({cpu: 42.5}, 'cpu'), '42.5 %');
    assert.ok(detail.reading({in_mbps: 1, out_mbps: 2}, 'traffic').includes('In 1 Mbps'));
    assert.ok(detail.reading({ping_ms: 12, packet_loss: 3}, 'ping').includes('12 ms'));
});

test('gauge arc is proportional to the percentage and clamped to the dial', () => {
    const full = detail.arcPath(100);
    assert.ok(Math.abs(detail.arcPath(50) - full / 2) < 1e-9);
    assert.strictEqual(detail.arcPath(0), 0);
    assert.strictEqual(detail.arcPath(150), full);
    assert.strictEqual(detail.arcPath(-20), 0);
});
