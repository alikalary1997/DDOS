/* Sensor detail: tabs, range picker, gauges and graph. Reads stored samples only. */
(() => {
    'use strict';
    // Exported before the DOM guard so the helpers are testable without a browser.
    if (typeof module !== 'undefined') module.exports = {format, rate, duration, reading, arcPath};
    const root = typeof document === 'undefined' ? null : document.querySelector('[data-sensor-history-url]');
    if (!root) return;
    const kind = root.dataset.sensorKind;
    const interval = Number(root.dataset.interval) || 10;
    const seedElement = document.getElementById('sensorHistorySeed');
    let payload = seedElement ? JSON.parse(seedElement.textContent) : null;
    const SVGNS = 'http://www.w3.org/2000/svg';

    function format(value, digits = 3) {
        return Number.isFinite(value) ? value.toLocaleString(undefined, {maximumFractionDigits: digits}) : '—';
    }
    function rate(mbps) {
        if (!Number.isFinite(mbps)) return '—';
        if (mbps >= 1000) return format(mbps / 1000) + ' Gbps';
        if (mbps >= 1) return format(mbps) + ' Mbps';
        if (mbps >= .001) return format(mbps * 1000) + ' Kbps';
        return format(mbps * 1000000) + ' bps';
    }
    function duration(seconds) {
        if (!Number.isFinite(seconds)) return '—';
        const days = Math.floor(seconds / 86400), hours = Math.floor(seconds % 86400 / 3600);
        const minutes = Math.floor(seconds % 3600 / 60);
        return `${days}d ${hours}h ${minutes}m`;
    }
    // Pure: the sensor kind is passed in so this is testable without a page.
    function reading(point, sensorKind) {
        if (!point) return '—';
        if (sensorKind === 'cpu') return format(point.cpu, 1) + ' %';
        if (sensorKind === 'uptime') return duration(point.uptime_seconds);
        if (sensorKind === 'ping') return format(point.ping_ms, 1) + ' ms / ' + format(point.packet_loss, 1) + '% loss';
        if (sensorKind === 'pppoe') return (Number.isFinite(point.pppoe_users) ? point.pppoe_users : '—') + ' users';
        if (sensorKind === 'neighbors') return (Number.isFinite(point.neighbor_count) ? point.neighbor_count : '—') + ' neighbours';
        return 'In ' + rate(point.in_mbps) + ' / Out ' + rate(point.out_mbps);
    }
    /* ---- tabs ---- */
    const tabs = [...document.querySelectorAll('[data-tab]')];
    const panels = [...document.querySelectorAll('[data-panel]')];
    function selectTab(name) {
        tabs.forEach(tab => {
            const active = tab.dataset.tab === name;
            tab.setAttribute('aria-selected', String(active));
            tab.tabIndex = active ? 0 : -1;
        });
        panels.forEach(panel => { panel.hidden = panel.dataset.panel !== name; });
        if (window.location.hash !== '#' + name) window.history.replaceState(null, '', '#' + name);
    }
    tabs.forEach(tab => tab.addEventListener('click', () => selectTab(tab.dataset.tab)));
    const initial = (window.location.hash || '').replace('#', '');
    selectTab(tabs.some(tab => tab.dataset.tab === initial) ? initial : 'overview');

    /* ---- range control (one control drives both graph and table) ---- */
    const controls = document.createElement('div');
    controls.className = 'range-control';
    controls.setAttribute('role', 'group');
    controls.setAttribute('aria-label', 'Time range');
    const known = [['30m', '30m'], ['2h', '2h'], ['24h', '24h'], ['7d', '7d'], ['30d', '30d']];
    for (const [key, label] of known) {
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = label;
        button.dataset.range = key;
        controls.append(button);
    }
    document.querySelectorAll('[data-range-slot]').forEach(slot => slot.append(controls.cloneNode(true)));

    function markRange(key, label) {
        document.querySelectorAll('[data-range]').forEach(button => {
            button.setAttribute('aria-pressed', String(button.dataset.range === key));
        });
        document.querySelectorAll('[data-chart-caption]').forEach(caption => {
            caption.textContent = (kind === 'traffic' ? 'Inbound / outbound Mbps' : kind === 'ping' ? 'Latency ms'
                : kind === 'cpu' ? 'CPU %' : kind === 'pppoe' ? 'Active PPPoE users'
                : kind === 'neighbors' ? 'Neighbours seen' : 'Uptime') + ' · ' + label;
        });
        document.querySelectorAll('[data-detail-legend]').forEach(legend => {
            legend.textContent = kind === 'traffic' ? 'Blue: inbound · Green: outbound'
                : kind === 'ping' ? 'Blue: latency' : kind === 'cpu' ? 'Blue: CPU'
                : kind === 'pppoe' ? 'Blue: active users' : kind === 'neighbors' ? 'Blue: neighbours' : 'Blue: uptime';
        });
    }

    /* ---- charts ---- */
    function node(tag, attrs = {}) {
        const element = document.createElementNS(SVGNS, tag);
        for (const [key, value] of Object.entries(attrs)) element.setAttribute(key, value);
        return element;
    }
    function segments(points, key) {
        const groups = [], within = Math.max(30, interval * 3) * 1000;
        let current = [], previous = null;
        for (const point of points) {
            const time = Date.parse(point.t), value = point[key];
            if (!point.valid || !Number.isFinite(value) || !Number.isFinite(time)) {
                if (current.length) groups.push(current);
                current = []; previous = null; continue;
            }
            if (previous !== null && time - previous > within) {
                if (current.length) groups.push(current);
                current = [];
            }
            current.push({time, value}); previous = time;
        }
        if (current.length) groups.push(current);
        return groups;
    }
    const METRICS = {traffic: ['in_mbps', 'out_mbps'], cpu: ['cpu'], ping: ['ping_ms'],
                     uptime: ['uptime_seconds'], pppoe: ['pppoe_users'], neighbors: ['neighbor_count']};
    function drawChart() {
        const svg = document.querySelector('[data-detail-chart]');
        if (!svg || !payload) return;
        svg.replaceChildren();
        const points = payload.points || [];
        const keys = METRICS[kind] || [];
        const sets = keys.map(key => segments(points, key));
        const flat = sets.flat(2);
        const note = document.querySelector('[data-detail-chart-note]');
        if (note) note.textContent = flat.length
            ? `${flat.length} readings in the last ${payload.range_label || payload.range}. Gaps indicate missing readings.`
            : `No stored readings in the last ${payload.range_label || payload.range}.`;
        if (!flat.length) return;
        const low = Math.min(...flat.map(p => p.time)), high = Math.max(...flat.map(p => p.time));
        const scaleMax = Math.max(kind === 'traffic' || kind === 'uptime' ? .001 : 100, ...flat.map(p => p.value));
        // Faint horizontal gridlines behind the series.
        for (const fraction of [0, .25, .5, .75, 1]) {
            const y = 195 - fraction * 175;
            svg.append(node('line', {x1: 55, y1: y, x2: 655, y2: y, class: 'grid-line'}));
        }
        const toXY = group => group.map(p => [55 + (p.time - low) / Math.max(1, high - low) * 600, 195 - p.value / scaleMax * 175]);
        // Primary series: line plus a soft area fill. Secondary series: a thin accent line.
        for (const [index, groups] of sets.entries()) {
            for (const group of groups) {
                const xy = toXY(group);
                const drawn = xy.map(p => p.join(',')).join(' ');
                if (!index && xy.length > 1) {
                    svg.append(node('polygon', {
                        points: `${drawn} ${xy[xy.length - 1][0]},195 ${xy[0][0]},195`, class: 'series-area'}));
                }
                svg.append(node('polyline', {points: drawn, fill: 'none', class: index ? 'outbound' : 'inbound'}));
                if (xy.length === 1) svg.append(node('circle', {cx: xy[0][0], cy: xy[0][1], r: 3, fill: 'none', 'stroke-width': 2,
                    class: index ? 'outbound' : 'inbound'}));
            }
        }
        const label = value => kind === 'uptime' ? duration(value) : kind === 'pppoe' || kind === 'neighbors' ? format(value, 0) : format(value, 1);
        for (const [x, y, text, anchor] of [[50, 22, label(scaleMax), 'end'], [50, 199, '0', 'end'],
            [55, 220, new Date(low).toLocaleString(), 'start'], [655, 220, new Date(high).toLocaleString(), 'end']]) {
            const element = node('text', {x, y, 'text-anchor': anchor});
            element.textContent = text;
            svg.append(element);
        }
    }

    /* ---- historic table ---- */
    function drawTable() {
        const body = document.querySelector('[data-history-body]');
        if (!body || !payload) return;
        body.replaceChildren();
        const points = [...(payload.points || [])].reverse();
        for (const point of points) {
            const row = body.insertRow();
            row.insertCell().textContent = new Date(point.t).toLocaleString();
            row.insertCell().textContent = reading(point.valid ? point : null, kind);
            row.insertCell().textContent = point.valid ? (point.restart_detected ? 'Uptime reset' : 'Valid') : 'Read failed';
        }
        if (!points.length) {
            const cell = body.insertRow().insertCell();
            cell.colSpan = 3;
            cell.textContent = 'No stored samples in this range.';
        }
        const summary = document.querySelector('[data-history-note]');
        if (summary) {
            summary.textContent = payload.stats
                ? `${payload.stats.total} stored sample${payload.stats.total === 1 ? '' : 's'} in the last ${payload.range_label || payload.range}.`
                : `${points.length} stored sample${points.length === 1 ? '' : 's'}.`;
        }
    }

    /* ---- gauges ---- */
    const CIRCUMFERENCE = 2 * Math.PI * 50;
    const CIRCULAR = new Set(['cpu', 'packet_loss']);
    function arcPath(percent) {
        const clamped = Math.max(0, Math.min(100, percent));
        return 2 * Math.PI * 50 * clamped / 100;
    }
    function applyArc(gauge, element, percent) {
        element.setAttribute('stroke-dasharray', `${arcPath(percent)} ${CIRCUMFERENCE}`);
        element.setAttribute('stroke-dashoffset', '0');
    }
    function gaugePercent(gauge, point) {
        // Only percentage metrics have a meaningful 0-100 arc; others show the reading in the dial.
        const key = gauge.dataset.gauge;
        if (!point || !CIRCULAR.has(key)) return key === 'ping_ms' && point?.ping_ms != null ? Math.min(100, point.ping_ms) : 0;
        return key === 'cpu' ? (point.cpu ?? 0) : (point.packet_loss ?? 0);
    }
    function updateGauges(point) {
        document.querySelectorAll('[data-gauge]').forEach(gauge => {
            const arc = gauge.querySelector('[data-arc]');
            const label = gauge.querySelector('[data-gauge-value]');
            if (!label) return;
            const plain = !arc;                 // no ring for count metrics: update the number only
            const key = gauge.dataset.gauge;
            if (!point) { label.textContent = '—'; if (!plain) applyArc(gauge, arc, 0); return; }
            if (key === 'total') label.textContent = format((point.in_mbps ?? 0) + (point.out_mbps ?? 0), 2);
            else if (key === 'in_mbps') label.textContent = format(point.in_mbps, 2);
            else if (key === 'out_mbps') label.textContent = format(point.out_mbps, 2);
            else if (key === 'cpu') label.textContent = format(point.cpu, 1);
            else if (key === 'ping_ms') label.textContent = format(point.ping_ms, 1);
            else if (key === 'packet_loss') label.textContent = format(point.packet_loss, 1);
            else if (key === 'uptime_seconds') label.textContent = duration(point.uptime_seconds);
            else if (key === 'pppoe_users') label.textContent = Number.isFinite(point.pppoe_users) ? point.pppoe_users : '—';
            else if (key === 'neighbor_count') label.textContent = Number.isFinite(point.neighbor_count) ? point.neighbor_count : '—';
            if (!plain) applyArc(gauge, arc, gaugePercent(gauge, point));
        });
    }
    // Draw the server-rendered current reading on first paint.
    updateGauges(payload.points && payload.points.length ? payload.points[payload.points.length - 1] : null);

    /* ---- range switching ---- */
    async function loadRange(key) {
        document.querySelectorAll('[data-range]').forEach(button => { button.disabled = true; });
        try {
            const response = await fetch(root.dataset.sensorHistoryUrl + '?range=' + encodeURIComponent(key),
                {credentials: 'same-origin', headers: {Accept: 'application/json'}});
            if (!response.ok) throw Error('read');
            payload = await response.json();
            markRange(payload.range, payload.range_label);
            drawChart();
            drawTable();
            updateGauges(payload.latest);
        } catch (_) {
            const note = document.querySelector('[data-detail-chart-note]');
            if (note) note.textContent = 'Saved readings unavailable for this range. Try another range.';
        } finally {
            document.querySelectorAll('[data-range]').forEach(button => { button.disabled = false; });
        }
    }
    document.addEventListener('click', event => {
        const button = event.target.closest('[data-range]');
        if (!button) return;
        loadRange(button.dataset.range);
    });

    markRange(payload.range, payload.range_label);
    drawChart();
    drawTable();
})();
