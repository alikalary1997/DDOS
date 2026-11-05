(() => {
    "use strict";
    // Renders saved monitoring data only. The browser never contacts a router.
    const page = document.getElementById("ddPage");
    if (!page) return;
    const grid = document.getElementById("ddGrid"), empty = document.getElementById("ddEmpty"), status = document.getElementById("ddStatus");
    const csrf = () => document.querySelector('[name="csrfmiddlewaretoken"]')?.value || "";
    const REFRESH_MS = 5000;
    let data = JSON.parse(document.getElementById("ddInitial").textContent);
    let filter = "all", busy = false;
    const expanded = new Set();

    const cpuLevel = (cpu) => cpu >= data.high_cpu ? "red" : cpu >= data.warn_cpu ? "orange" : "green";
    const view = (d) => {
        // Only a live (running, fresh) reading may drive warnings, filters and counts.
        const live = d.metrics.cpu.state === "ok" && d.metrics.cpu.mode === "live";
        const cpu = live ? d.metrics.cpu.value : null;
        const known = cpu !== null;
        const state = d.attacked ? (d.monitored ? ["UNDER ATTACK", "red"] : ["ATTACK - UNMONITORED", "red"])
            : d.monitored ? ["MONITORING", "green"] : ["NOT MONITORED", "gray"];
        const highCpu = known && cpu >= data.high_cpu, warnCpu = known && cpu >= data.warn_cpu && !highCpu;
        const unprotected = d.monitored ? [] : d.ips.filter((ip) => ip.attacked);
        const border = highCpu ? "red" : (warnCpu || unprotected.length) ? "orange" : "";
        return {known, cpu, state, highCpu, warnCpu, unprotected, border};
    };
    const matches = (d) => {
        const v = view(d);
        return filter === "all" || (filter === "cpu" && v.highCpu) || (filter === "attack" && d.attacked) || (filter === "unmonitored" && !d.monitored);
    };

    function el(tag, props = {}, ...kids) {
        const node = document.createElement(tag);
        for (const [key, value] of Object.entries(props)) {
            if (key === "text") node.textContent = value;
            else if (key === "dataset") Object.assign(node.dataset, value);
            else if (key === "className" || key === "disabled") node[key] = value;
            else node.setAttribute(key, value);
        }
        node.append(...kids.filter(Boolean));
        return node;
    }
    const STATE_TEXT = {no_sensor: "No sensor", stopped: "Sensor stopped", stale: "Stale", unknown: "Unknown"};
    // Missing, stopped, stale or invalid data renders as text only: no bar, never a 0 or a normal-looking value.
    function ago(seconds) {
        if (seconds < 90) return `${seconds} s ago`;
        if (seconds < 5400) return `${Math.round(seconds / 60)} min ago`;
        if (seconds < 172800) return `${Math.round(seconds / 3600)} h ago`;
        return `${Math.round(seconds / 86400)} days ago`;
    }
    // Saved or stale readings keep their value but always carry a caption and never a live-looking bar.
    function metric(label, entry, sensorsUrl, format, percent, tone, tip) {
        const ok = entry.state === "ok", live = ok && entry.mode === "live";
        const value = el("span", {className: "dd-val", text: ok ? format(entry) : STATE_TEXT[entry.state] || "Unknown"});
        if (ok && tip) value.title = tip;
        const caption = ok && !live ? el("small", {className: "dd-cap", text: entry.mode === "stale"
            ? `Stale · last reading ${ago(entry.age_seconds)}` : "Paused · saved reading"}) : null;
        const link = entry.state === "no_sensor" ? el("a", {className: "dd-add", href: sensorsUrl, text: "Add sensor"}) : null;
        const bar = live && percent !== null ? el("div", {className: "dd-bar", dataset: {tone: tone || ""}}, el("i", {style: `width:${Math.max(0, Math.min(100, percent))}%`})) : el("span");
        return el("div", {className: "dd-row", dataset: {unknown: live ? "0" : "1"}}, el("span", {text: label}), bar,
            el("span", {className: "dd-val-wrap"}, value, caption, link));
    }
    function rate(mbps) { return mbps >= 1000 ? `${(mbps / 1000).toFixed(2)} Gbps` : `${mbps < 10 ? mbps.toFixed(2) : mbps.toFixed(1)} Mbps`; }
    function trafficTip(entry) {
        const names = entry.interfaces.map((i) => i.interface).join(", ");
        const note = entry.skipped ? ` (${entry.skipped} sensor${entry.skipped > 1 ? "s" : ""} without a fresh reading not included)` : "";
        const exact = (v) => (v >= 1000 ? `${(v / 1000).toFixed(3)} Gbps` : `${v.toFixed(3)} Mbps`);
        return `In ${exact(entry.in_mbps)} / Out ${exact(entry.out_mbps)}. Interfaces: ${names}${note}`;
    }
    function uptimeText(seconds) {
        if (seconds === null || seconds === undefined) return "Unknown";
        const days = Math.floor(seconds / 86400), hours = Math.floor((seconds % 86400) / 3600);
        return days ? `${days} days ${hours} h` : `${hours} h ${Math.floor((seconds % 3600) / 60)} min`;
    }
    function ipTag(ip) {
        if (ip.attacked) return ip.monitored ? ["UNDER ATTACK", "red"] : ["UNPROTECTED", "red"];
        return ip.monitored ? ["PROTECTED", "green"] : ["NOT MONITORED", "gray"];
    }
    const deviceUrl = (id, action) => `${page.dataset.controlUrl.replace(/all\/start\/$/, "")}devices/${id}/${action}/`;
    const bulkUrl = (action) => page.dataset.controlUrl.replace(/start\/$/, `${action}/`);

    function card(d) {
        const v = view(d);
        const node = el("article", {className: "dd-device", dataset: {border: v.border, deviceId: d.id}});
        node.append(el("div", {className: "dd-head"},
            el("div", {className: "dd-name"}, el("b", {text: d.name}), el("span", {className: "dd-badge", dataset: {tone: v.state[1]}, text: v.state[0]})),
            el("span", {className: "dd-ip", text: d.management_ip})));
        if (v.highCpu) node.append(el("p", {className: "dd-warn", dataset: {tone: "red"}, text: `CPU at ${Math.round(v.cpu)}%. High load can hide or worsen an attack. Check this device.`}));
        else if (v.warnCpu) node.append(el("p", {className: "dd-warn", dataset: {tone: "orange"}, text: `CPU is above ${data.warn_cpu}%. Keep an eye on this device.`}));
        for (const ip of v.unprotected) node.append(el("p", {className: "dd-warn", dataset: {tone: "red"}},
            el("b", {text: ip.address}), " is under attack but this device is not monitored. Start monitoring."));
        const m = d.metrics, scale = data.bandwidth_scale_mbps;
        node.append(metric("CPU", m.cpu, d.sensors_url, (e) => `${Math.round(e.value)}%`, v.known ? v.cpu : null, v.known ? cpuLevel(v.cpu) : ""));
        node.append(metric("Bandwidth", m.traffic, d.sensors_url, (e) => rate(e.value), scale ? (m.traffic.value / scale) * 100 : null, "", m.traffic.state === "ok" ? trafficTip(m.traffic) : ""));
        node.append(metric("Uptime", m.uptime, d.sensors_url, (e) => uptimeText(e.value), null));
        const actions = el("div", {className: "dd-actions"});
        if (data.can_control) {
            const action = d.monitored ? "stop" : "start";
            const button = el("button", {type: "button", className: d.monitored ? "dd-btn" : "dd-btn dd-btn-start", disabled: busy,
                text: d.monitored ? "Stop monitoring" : "Start monitoring"});
            button.dataset.action = action;
            button.addEventListener("click", () => send(deviceUrl(d.id, action), action, false));
            actions.append(button);
        }
        const open = expanded.has(d.id);
        const toggle = el("button", {type: "button", className: "dd-btn dd-toggle", "aria-expanded": String(open)},
            el("span", {text: `IPs (${d.ips.length})`}), el("span", {className: "dd-chev", text: "▼", "aria-hidden": "true"}));
        toggle.addEventListener("click", () => { if (open) expanded.delete(d.id); else expanded.add(d.id); render(); });
        actions.append(toggle);
        if (open) {
            const list = el("ul", {className: "dd-iplist"});
            if (!d.ips.length) list.append(el("li", {className: "dd-none", text: "No public IPs assigned"}));
            for (const ip of d.ips) {
                const [label, tone] = ipTag(ip);
                list.append(el("li", {}, el("span", {className: "dd-mono", text: ip.address}),
                    el("span", {className: "dd-tag", dataset: {tone}, text: label, title: ip.health || ""})));
            }
            actions.append(list);
        }
        node.append(actions);
        return node;
    }

    function summary() {
        const devices = data.devices, ips = devices.flatMap((d) => d.ips);
        const set = (id, text, active) => {
            const node = document.getElementById(id);
            node.textContent = text;
            if (active !== undefined) node.parentNode.dataset.active = active ? "1" : "0";
        };
        const monitored = devices.filter((d) => d.monitored).length;
        const highCpu = devices.filter((d) => view(d).highCpu).length, attacked = devices.filter((d) => d.attacked).length;
        set("sumMonitored", `${monitored} / ${devices.length}`);
        set("sumUnmonitored", String(devices.length - monitored));
        set("sumCpu", String(highCpu), highCpu > 0);
        set("sumAttack", String(attacked), attacked > 0);
        set("sumIps", `${ips.filter((ip) => ip.monitored).length} / ${ips.length}`);
        document.querySelector('[data-count="all"]').textContent = String(devices.length);
    }
    function render() {
        summary();
        document.querySelectorAll("[data-bulk]").forEach((button) => { button.disabled = busy; });
        const shown = data.devices.filter(matches);
        grid.replaceChildren(...shown.map(card));
        empty.hidden = shown.length > 0;
        empty.textContent = data.devices.length ? "No devices match this filter." : "No MikroTik devices have been added yet.";
    }
    function say(text, error) { status.textContent = text; status.dataset.tone = error ? "error" : ""; }

    async function send(url, action, bulk) {
        if (busy) return;
        if (bulk && !window.confirm(`${action === "start" ? "Start" : "Stop"} monitoring on all devices?`)) return;
        busy = true; render();
        try {
            const response = await fetch(url, {method: "POST", headers: {"X-CSRFToken": csrf(), "Accept": "application/json"}, credentials: "same-origin"});
            const body = await response.json().catch(() => ({}));
            if (!response.ok) say(body.error || "The request could not be completed.", true);
            else { data = body.data; say(body.message, false); }
        } catch (_) { say("The server could not be reached.", true); }
        busy = false; render();
    }
    async function refresh() {
        if (busy || document.hidden) return;
        try {
            const response = await fetch(page.dataset.dataUrl, {headers: {"Accept": "application/json"}, credentials: "same-origin", cache: "no-store"});
            if (response.ok) { data = await response.json(); render(); }
        } catch (_) { /* Keep the last saved view; the next tick retries. */ }
    }

    document.querySelectorAll("[data-filter]").forEach((button) => button.addEventListener("click", () => {
        filter = button.dataset.filter;
        document.querySelectorAll("[data-filter]").forEach((other) => {
            const on = other === button;
            other.classList.toggle("is-active", on);
            other.setAttribute("aria-pressed", String(on));
        });
        render();
    }));
    document.querySelectorAll("[data-bulk]").forEach((button) => button.addEventListener("click", () => {
        send(bulkUrl(button.dataset.bulk), button.dataset.bulk, true);
    }));
    render();
    window.setInterval(refresh, REFRESH_MS);
})();
