(() => {
    "use strict";
    const states = {Normal: "normal", Warning: "warning", "Under Attack": "under-attack", Unknown: "unknown"};
    const labels = {total_pps: "Total PPS", bandwidth_mbps: "Bandwidth (Mbps)", syn_pps: "TCP SYN PPS", udp_pps: "UDP PPS"};
    function render(root, data) {
        const status = data.monitoring_health === "Active" && states[data.ddos_status] ? data.ddos_status : "Unknown";
        const badge = root.querySelector("[data-ddos-status]");
        if (badge) { badge.textContent = status; badge.dataset.state = states[status]; }
        const metrics = root.querySelector("[data-ddos-metrics]");
        if (metrics) metrics.textContent = status !== "Unknown" && Array.isArray(data.ddos_metrics)
            ? data.ddos_metrics.map(item => labels[item.metric]).filter(Boolean).join(" · ") : "";
        const note = root.querySelector("[data-ddos-message]");
        if (note) note.textContent = data.ddos_message || "";
    }
    function mount(root, data) {
        const box = document.createElement("div"); box.className = "detection-inline";
        const badge = document.createElement("span"); badge.className = "detection-badge"; badge.setAttribute("data-ddos-status", "");
        const metrics = document.createElement("small"); metrics.setAttribute("data-ddos-metrics", "");
        box.append(badge, metrics); root.append(box); render(box, data);
    }
    window.NetShieldDetection = {render, mount};
})();
