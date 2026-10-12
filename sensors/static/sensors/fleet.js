(() => {
    const root = document.querySelector('[data-sensor-fleet-url]');
    if (!root) return;
    const number = value => Number.isFinite(value) ? value.toLocaleString(undefined, {maximumFractionDigits: 3}) : '\u2014';
    const attention = sensor => ['Paused', 'Stale', 'Connection Failed'].includes(sensor.status);

    function line(parent, tag, value, className = '') {
        const element = document.createElement(tag);
        element.textContent = value;
        element.className = className;
        parent.append(element);
        return element;
    }

    function readingState(parent, sensor) {
        let label = sensor.status;
        if (sensor.status === 'Active') {
            label = 'Live SNMP';
            if (sensor.kind === 'traffic' && (sensor.in_mbps === null || sensor.out_mbps === null)) label = 'Waiting for rate';
        } else if (sensor.sample_at && [sensor.cpu, sensor.uptime, sensor.in_mbps, sensor.out_mbps].some(value => value !== null)) {
            label += ' \u00b7 saved reading';
        }
        if (sensor.restart_detected && sensor.kind === 'uptime') label += ' \u00b7 restart detected';
        const state = line(parent, 'small', label, 'fleet-reading-state');
        state.dataset.state = sensor.status_tone || (sensor.status === 'Active' ? 'active' : attention(sensor) ? 'attention' : 'idle');
        const details = ['Poll interval: ' + sensor.interval + ' seconds'];
        if (sensor.last_success) details.push('Last successful reading: ' + new Date(sensor.last_success).toLocaleString());
        if (sensor.error) details.push(sensor.error);
        state.title = details.join('\n');
    }

    function renderCell(cell, sensors) {
        const kind = cell.dataset.deviceSensor;
        const selected = sensors.filter(sensor => sensor.kind === kind);
        cell.replaceChildren();
        for (const sensor of selected) {
            const block = document.createElement('div');
            block.className = kind === 'traffic' ? 'fleet-traffic-sensor' : 'fleet-sensor-reading';
            cell.append(block);
            if (kind === 'cpu') {
                line(block, 'strong', number(sensor.cpu) + (Number.isFinite(sensor.cpu) ? '%' : ''), 'fleet-sensor-value');
            } else if (kind === 'uptime') {
                line(block, 'strong', sensor.uptime || '\u2014', 'fleet-sensor-value');
            } else if (kind === 'traffic') {
                const heading = line(block, 'div', '', 'fleet-traffic-interface');
                line(heading, 'span', sensor.interface_name);
                if (sensor.interface_status) {
                    const status = line(heading, 'small', sensor.interface_status, 'fleet-interface-state');
                    status.dataset.state = sensor.interface_status === 'Up' ? 'active' : 'idle';
                }
                const rates = line(block, 'div', '', 'fleet-traffic-rates');
                for (const [label, value] of [['In', sensor.in_mbps], ['Out', sensor.out_mbps]]) {
                    const rate = line(rates, 'div', '', 'fleet-traffic-rate');
                    line(rate, 'span', label);
                    line(rate, 'strong', number(value), 'fleet-sensor-value');
                    line(rate, 'small', 'Mbps');
                }
            }
            readingState(block, sensor);
            if (sensor.error) {
                const details = line(block, 'details', '', 'fleet-sensor-error');
                line(details, 'summary', 'View error');
                line(details, 'p', sensor.error);
            }
            const inspector = document.querySelector('[data-integrated-sensor="' + sensor.id + '"]');
            if (inspector) {
                const summary = inspector.querySelector('[data-sensor-summary]');
                if (summary) summary.textContent = sensor.status;
                const schedule = inspector.querySelector('[data-sensor-schedule]');
                if (schedule) schedule.textContent = 'Every ' + sensor.interval + ' seconds \u00b7 Last reading: ' +
                    (sensor.last_success ? new Date(sensor.last_success).toLocaleString() : 'No readings yet');
                const start = inspector.querySelector('[data-sensor-start]');
                if (start) {
                    start.disabled = Boolean(sensor.enabled) && sensor.status !== 'Paused';
                    start.textContent = sensor.status === 'Paused' ? 'Resume' : 'Start';
                }
                const stop = inspector.querySelector('[data-sensor-stop]');
                if (stop) stop.disabled = !sensor.enabled;
            }
        }
        if (!selected.length && kind !== 'cpu') {
            line(cell, 'strong', '\u2014', 'fleet-sensor-value');
            line(cell, 'small', kind === 'traffic' ? 'No traffic sensor' : 'No uptime sensor', 'fleet-reading-state');
        }
    }

    function renderHealth(row, sensors) {
        const badge = row.querySelector('[data-fleet-sensor-health]');
        if (!badge) return;
        const active = sensors.filter(sensor => sensor.status === 'Active').length;
        const needsAttention = sensors.filter(attention).length;
        badge.textContent = !sensors.length ? 'No sensors' : needsAttention ? 'Needs attention' : active ? active + ' active' : sensors.some(sensor => sensor.enabled) ? 'Waiting for data' : 'Stopped';
        badge.dataset.state = needsAttention ? 'attention' : active ? 'active' : 'idle';
        badge.title = sensors.map(sensor => sensor.name + ': ' + sensor.status).join('\n');
    }

    function render(groups) {
        const all = Object.values(groups).flat();
        const totals = {
            '[data-fleet-sensor-count]': all.length,
            '[data-fleet-active-count]': all.filter(sensor => sensor.status === 'Active').length,
            '[data-fleet-needs-attention]': all.filter(attention).length,
        };
        Object.entries(totals).forEach(([selector, value]) => document.querySelectorAll(selector).forEach(element => { element.textContent = number(value); }));
        root.querySelectorAll('[data-device-row]').forEach(row => {
            const sensors = groups[row.dataset.deviceId] || [];
            const api = row.querySelector('[data-api-cpu]');
            if (api) api.hidden = sensors.some(sensor => sensor.kind === 'cpu');
            row.querySelectorAll('[data-device-sensor]').forEach(cell => renderCell(cell, sensors));
            renderHealth(row, sensors);
        });
    }

    let busy = false;
    async function refresh() {
        if (busy) return;
        busy = true;
        const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 10000);
        try {
            const response = await fetch(root.dataset.sensorFleetUrl, {credentials: 'same-origin', signal: controller.signal});
            if (!response.ok) throw Error('read');
            const payload = await response.json();
            if (!payload.devices || typeof payload.devices !== 'object' || Object.values(payload.devices).some(value => !Array.isArray(value))) throw Error('data');
            render(payload.devices);
        } catch (_) {
            document.querySelectorAll('[data-fleet-active-count], [data-fleet-needs-attention]').forEach(element => { element.textContent = '\u2014'; });
            root.querySelectorAll('[data-device-sensor]').forEach(cell => {
                if (cell.textContent.trim()) {
                    cell.replaceChildren();
                    line(cell, 'strong', '\u2014', 'fleet-sensor-value');
                    line(cell, 'small', 'Sensor data unavailable', 'fleet-reading-state');
                }
            });
            root.querySelectorAll('[data-fleet-sensor-health]').forEach(badge => {
                badge.textContent = 'Data unavailable'; badge.dataset.state = 'attention';
            });
        } finally { clearTimeout(timeout); busy = false; }
    }
    refresh(); setInterval(refresh, 5000);
})();

