/* Browser refresh reads cached history only; it never initiates an SNMP poll. */
(() => {
    'use strict';
    function segments(history, key, interval) {
        const groups = []; let current = [], previous = null;
        for (const sample of history) {
            const time = Date.parse(sample.timestamp), value = sample[key];
            if (!sample.valid || !Number.isFinite(value) || !Number.isFinite(time)) {
                if (current.length) groups.push(current);
                current = []; previous = null; continue;
            }
            if (previous !== null && time - previous > Math.max(30, interval * 3) * 1000) {
                if (current.length) groups.push(current);
                current = [];
            }
            current.push({time, value}); previous = time;
        }
        if (current.length) groups.push(current);
        return groups;
    }
    function format(value) { return Number.isFinite(value) ? value.toLocaleString(undefined, {maximumFractionDigits: 3}) : '—'; }
    function rate(mbps) {
        if (!Number.isFinite(mbps)) return '—';
        if (mbps >= 1000) return format(mbps / 1000) + ' Gbps';
        if (mbps >= 1) return format(mbps) + ' Mbps';
        if (mbps >= .001) return format(mbps * 1000) + ' Kbps';
        return format(mbps * 1000000) + ' bps';
    }
    if (typeof module !== 'undefined') module.exports = {segments, format, rate};
    if (typeof document === 'undefined') return;
    const root = document.querySelector('[data-sensor-data]');
    function bindWizard(wizard, embedded = false) {
    let wizardBusy = false, wizardOpener = null;
    function openWizard(button) {
        if (!wizard) return;
        wizardOpener = button || document.querySelector('[data-open-sensor]');
        if (!wizard.open) wizard.showModal();
    }
    document.querySelectorAll('[data-open-sensor]').forEach(button => button.addEventListener('click', () => openWizard(button)));
    wizard?.addEventListener('click', event => {
        if (event.target.closest('[data-close-sensor]')) wizard.close();
    });
    wizard?.addEventListener('close', () => {
        wizard.querySelectorAll('input[type="password"]').forEach(input => input.value = '');
        wizardOpener?.focus();
    });
    wizard?.addEventListener('submit', async event => {
        const form = event.target;
        if (!form.matches('[data-wizard-form]')) return;
        event.preventDefault();
        if (wizardBusy) return;
        wizardBusy = true;
        const button = event.submitter;
        const data = new FormData(form);
        if (button?.name) data.set(button.name, button.value);
        const endpoint = button?.getAttribute('formaction') || form.action;
        const feedback = wizard.querySelector('[data-wizard-feedback]');
        feedback.hidden = false;
        feedback.textContent = form.dataset.wizardForm === 'profile' ? 'Testing SNMP connection…' : form.dataset.wizardForm === 'detect' ? 'Reading sensor information from this device…' : 'Saving sensors…';
        wizard.setAttribute('aria-busy', 'true');
        const enabledButtons = [...wizard.querySelectorAll('button[type="submit"]')].filter(item => !item.disabled);
        enabledButtons.forEach(item => item.disabled = true);
        const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 30000);
        try {
            const response = await fetch(endpoint, {method: 'POST', body: data, credentials: 'same-origin', signal: controller.signal, headers: {Accept: 'text/html'}});
            if (form.dataset.wizardForm === 'add' && response.ok && response.redirected) {
                if (embedded) window.location.reload(); else window.location.assign(response.url); return;
            }
            const page = new DOMParser().parseFromString(await response.text(), 'text/html');
            const updated = page.getElementById('addSensor');
            if (!updated) throw Error('request');
            wizard.replaceChildren(...Array.from(updated.childNodes).map(child => document.importNode(child, true)));
            wizard.querySelector('[role="alert"], .wizard-success, .wizard-step:last-of-type')?.scrollIntoView({block: 'nearest'});
        } catch (_) {
            feedback.hidden = false;
            feedback.textContent = 'The request could not be completed. Check your session and connection, then retry. Refresh the sensor list before retrying a save.';
        } finally {
            clearTimeout(timer); wizardBusy = false; wizard.removeAttribute('aria-busy');
            enabledButtons.forEach(item => item.disabled = false);
            wizard.querySelectorAll('input[type="password"]').forEach(input => input.value = '');
        }
    });
    if (embedded || window.location.hash === '#addSensor' || wizard?.dataset.reopen === 'true') openWizard();
    }
    bindWizard(document.getElementById('addSensor'));
    let loadingWizard = false;
    document.querySelectorAll('[data-device-add-sensor]').forEach(link => link.addEventListener('click', async event => {
        event.preventDefault();
        if (loadingWizard) return;
        loadingWizard = true;
        const label = link.textContent; link.textContent = 'Opening?';
        const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 10000);
        try {
            const response = await fetch(link.href, {credentials: 'same-origin', signal: controller.signal});
            if (!response.ok) throw Error('request');
            const page = new DOMParser().parseFromString(await response.text(), 'text/html');
            const source = page.getElementById('addSensor');
            if (!source) throw Error('session');
            document.getElementById('addSensor')?.remove();
            const dialog = document.importNode(source, true);
            document.body.append(dialog);
            dialog.addEventListener('close', () => dialog.remove());
            bindWizard(dialog, true);
        } catch (_) {
            const feedback = document.getElementById('connectionFeedback');
            if (feedback) { feedback.hidden = false; feedback.textContent = 'Sensor setup could not be opened. Check your session and retry.'; }
        } finally { clearTimeout(timer); loadingWizard = false; link.textContent = label; }
    }));
    if (!root) return;
    function node(tag, attrs = {}) {
        const item = document.createElementNS('http://www.w3.org/2000/svg', tag);
        for (const [key, value] of Object.entries(attrs)) item.setAttribute(key, value);
        return item;
    }
    function graph(card, sensor) {
        const svg = card.querySelector('[data-chart]');
        if (!svg) return;
        svg.replaceChildren();
        const keys = sensor.kind === 'cpu' ? ['cpu'] : ['in_mbps', 'out_mbps'];
        const sets = keys.map(key => segments(sensor.history, key, sensor.interval));
        const points = sets.flat(2);
        card.querySelector('[data-chart-note]').textContent = points.length ? 'Time along the horizontal axis; gaps indicate missing readings.' : 'No valid historical rates yet.';
        if (!points.length) return;
        const low = Math.min(...points.map(p => p.time)), high = Math.max(...points.map(p => p.time));
        const peak = Math.max(sensor.kind === 'cpu' ? 100 : .001, ...points.map(p => p.value));
        svg.append(node('path', {d: 'M45 15V145H580', fill: 'none', stroke: 'currentColor', opacity: '.2'}));
        for (const [index, groups] of sets.entries()) {
            for (const group of groups) {
                const xy = group.map(p => [45 + (p.time - low) / Math.max(1, high - low) * 535, 145 - p.value / peak * 120]);
                svg.append(node('polyline', {points: xy.map(p => p.join(',')).join(' '), fill: 'none', 'stroke-width': '2', class: index ? 'outbound' : 'inbound'}));
                if (xy.length === 1) svg.append(node('circle', {cx: xy[0][0], cy: xy[0][1], r: 3, fill: 'none', 'stroke-width': 2, class: index ? 'outbound' : 'inbound'}));
            }
        }
        for (const [x, y, label, anchor] of [[40, 25, format(peak), 'end'], [40, 145, '0', 'end'], [45, 170, new Date(low).toLocaleTimeString(), 'start'], [580, 170, new Date(high).toLocaleTimeString(), 'end']]) {
            const text = node('text', {x, y, 'text-anchor': anchor}); text.textContent = label; svg.append(text);
        }
    }
    function update(sensor) {
        const card = document.querySelector('[data-sensor-id="' + sensor.id + '"]');
        if (!card) return;
        card.querySelectorAll('[data-value]').forEach(el => {
            const key = el.dataset.value, value = sensor[key];
            el.textContent = key === 'last_success' ? (value ? new Date(value).toLocaleString() : '—') :
                typeof value === 'number' ? format(value) : value ?? '—';
            if (key === 'status') el.dataset.state = value;
        });
        let note = sensor.status === 'Active' ? 'Latest successful reading.' : 'Historical readings retained; values are not live.';
        if (sensor.counter_reset) note += ' Counter reset detected; calculating a new baseline.';
        if (sensor.restart_detected) note += ' Device uptime reset detected.';
        if (sensor.kind === 'traffic') note += ' In ' + rate(sensor.in_mbps) + ' / Out ' + rate(sensor.out_mbps);
        card.querySelector('[data-sample-note]').textContent = note;
        const body = card.querySelector('[data-history]'); body.replaceChildren();
        for (const sample of [...sensor.history].reverse()) {
            const row = body.insertRow();
            row.insertCell().textContent = new Date(sample.timestamp).toLocaleString();
            row.insertCell().textContent = sensor.kind === 'cpu' ? format(sample.cpu) + ' %' :
                sensor.kind === 'uptime' ? sample.uptime ?? '—' : 'In ' + rate(sample.in_mbps) + ' / Out ' + rate(sample.out_mbps);
            row.insertCell().textContent = sample.valid ? (sample.restart_detected ? 'Uptime reset' : 'Valid') : 'Read failed';
        }
        if (!sensor.history.length) { const cell = body.insertRow().insertCell(); cell.colSpan = 3; cell.textContent = 'No samples.'; }
        graph(card, sensor);
    }
    let busy = false;
    async function refresh() {
        if (busy) return;
        busy = true;
        const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 10000);
        try {
            const response = await fetch(root.dataset.sensorData, {credentials: 'same-origin', signal: controller.signal, headers: {Accept: 'application/json'}});
            if (!response.ok) throw Error('read');
            const result = await response.json();
            result.sensors.forEach(update);
            document.getElementById('sensorWorkerStatus').textContent = !result.polling_authorized ? 'SNMP monitoring is stopped. Add a sensor or press Start to begin.' : result.worker_running ? 'SNMP worker running. Only individually started sensors are polled.' : 'SNMP worker stopped. Displaying saved readings.';
        } catch (_) {
            document.getElementById('sensorWorkerStatus').textContent = 'Sensor data unavailable. Displayed readings may be out of date.';
            root.querySelectorAll('[data-value="status"]').forEach(el => { el.textContent = 'Unknown'; el.dataset.state = 'Unknown'; });
            root.querySelectorAll('[data-sample-note]').forEach(el => el.textContent = 'Saved readings; live status unavailable.');
        } finally { clearTimeout(timeout); busy = false; }
    }
    refresh(); setInterval(refresh, 5000);
})();
