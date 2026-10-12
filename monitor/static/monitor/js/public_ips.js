(() => {
    "use strict";
    // Add uses a native CSRF-protected POST. Future monitoring previews stay local.
    const dialogs = document.querySelectorAll(".ip-dialog");
    const openers = new Map();
    const changeDialog = document.getElementById("changeIpDialog");
    const current = document.getElementById("currentPublicIp");
    const next = document.getElementById("newPublicIp");
    const rules = document.getElementById("associatedRules");
    const ruleBody = document.getElementById("rulePreviewBody");
    const source = document.getElementById("previewSource");
    const validation = document.getElementById("changeValidation");
    let illustrative = false;
    const deviceSelect = document.getElementById("id_device");
    const authorization = document.getElementById("id_authorize_provisioning");
    const approvalData = document.getElementById("rawProvisioningDevices");
    const approvedDevices = approvalData ? JSON.parse(approvalData.textContent) : [];
    function updateProvisioningNotice() {
        const selected = approvedDevices.find(device => String(device.id) === deviceSelect?.value);
        const enabled = selected?.provisioning_enabled;
        const authorizationLabel = authorization?.closest("label");
        if (authorizationLabel) authorizationLabel.hidden = !selected || Boolean(enabled);
        const authorizing = Boolean(selected && authorization?.checked);
        const notice = document.getElementById("addIpNotice");
        if (notice) notice.textContent = enabled
            ? "Save retains the assignment, connects using saved API credentials, and adds and verifies missing RAW monitoring rules. Failures retain the assignment for Retry Provisioning."
            : authorizing
                ? "Save validates the saved API connection and interface, checks existing RAW rules, then enables this device and creates and verifies the three missing rules. Failed validation retains the assignment without enabling writes."
                : "Check the authorization option to validate and enable automatic RAW provisioning for this device. Otherwise Save retains the assignment pending approval.";
        const button = document.getElementById("savePublicIPButton");
        if (button && !button.disabled) button.textContent = enabled || authorizing ? "Save and Provision" : "Save";
    }
    deviceSelect?.addEventListener("change", updateProvisioningNotice);
    authorization?.addEventListener("change", updateProvisioningNotice);
    updateProvisioningNotice();

    function validIPv4(value) {
        const parts = value.split(".");
        return parts.length === 4 && parts.every((part) =>
            /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
    }

    function updatePreview() {
        const oldIp = current.value.trim();
        const newIp = next.value.trim();
        const enteredRules = rules.value.split(/\r?\n/).map((rule) => rule.trim()).filter(Boolean);
        const addressesValid = validIPv4(oldIp) && validIPv4(newIp);
        document.getElementById("previewCurrentIp").textContent = oldIp || "No data available";
        document.getElementById("previewNewIp").textContent = newIp || "No data available";
        source.textContent = illustrative
            ? "Illustrative example only. These addresses and comments are not inventory or live MikroTik data."
            : oldIp || newIp || enteredRules.length
                ? "User-entered visual preview only. No device or firewall rules have been queried."
                : "No data available. Enter addresses and rule comments to preview a change.";
        validation.textContent = "";
        if ((oldIp || newIp) && !addressesValid) {
            validation.textContent = "Enter valid current and new IPv4 addresses to preview replacements.";
        } else if (addressesValid && oldIp === newIp) {
            validation.textContent = "The new IP matches the current IP. No address replacement is planned.";
        }
        ruleBody.replaceChildren();
        if (!enteredRules.length) {
            const cell = ruleBody.insertRow().insertCell();
            cell.colSpan = 2;
            cell.textContent = "No data available";
        } else {
            enteredRules.forEach((comment) => {
                const row = ruleBody.insertRow();
                row.insertCell().textContent = comment;
                const knownPrefix = ["MONITOR-", "MONITOR-SYN-", "MONITOR-UDP-"]
                    .find((prefix) => comment === prefix + oldIp);
                row.insertCell().textContent = !addressesValid ? "Enter valid IPv4 addresses"
                    : knownPrefix ? knownPrefix + newIp
                    : "Unchanged: no matching MONITOR comment";
            });
        }
        // Confirmation is a visual control; it can never authorize a router change.
        document.getElementById("applyIpChange").disabled = true;
    }

    document.querySelectorAll("[data-open-ip]").forEach((button) => {
        if (!document.getElementById(button.dataset.openIp)) { button.disabled = true; return; }
        button.disabled = false;
        button.addEventListener("click", () => {
            const dialog = document.getElementById(button.dataset.openIp);
            document.querySelectorAll(".public-ip-actions").forEach((menu) => menu.open = false);
            openers.set(dialog, button);
            dialog.querySelector("form").reset();
            if (dialog.id === "addIpDialog") updateProvisioningNotice();
            dialog.querySelectorAll('[role="alert"]').forEach((alert) => alert.remove());
            if (dialog === changeDialog) { illustrative = false; updatePreview(); }
            dialog.showModal();
        });
    });
    dialogs.forEach((dialog) => {
        dialog.querySelectorAll("[data-close-ip]").forEach((button) => {
            button.addEventListener("click", () => dialog.close());
        });
        dialog.querySelector("form").addEventListener("submit", (event) => {
            if (!["addIpDialog", "editIpDialog", "deleteIpDialog"].includes(dialog.id)) event.preventDefault();
            else { if (dialog.id === "addIpDialog") { const notice = document.getElementById("addIpNotice"); notice.setAttribute("role", "status"); notice.textContent = "Pending: saving the assignment and checking the selected device's provisioning approval."; } const save = dialog.querySelector('button[type="submit"]'); if (save) { save.dataset.idleText = save.textContent; save.disabled = true; save.textContent = dialog.id === "deleteIpDialog" ? "Deleting…" : "Saving…"; } }
        });
        dialog.addEventListener("close", () => {
            dialog.querySelector("form").reset();
            if (dialog === changeDialog) { illustrative = false; updatePreview(); }
            const opener = openers.get(dialog);
            // Buttons inside the closed Actions menu are hidden; focus its summary instead.
            const menu = opener?.closest(".public-ip-actions");
            if (menu) menu.querySelector("summary").focus();
            else opener?.focus();
        });
        dialog.addEventListener("click", (event) => {
            if (event.target !== dialog) return;
            const bounds = dialog.getBoundingClientRect();
            if (event.clientX < bounds.left || event.clientX > bounds.right ||
                event.clientY < bounds.top || event.clientY > bounds.bottom) dialog.close();
        });
    });
    [current, next, rules].forEach((field) => field.addEventListener("input", () => {
        // Keep the illustrative label after loading an example, even if the user edits it.
        document.getElementById("confirmIpChange").checked = false;
        updatePreview();
    }));
    document.getElementById("confirmIpChange").addEventListener("change", updatePreview);
    document.getElementById("loadIpExample").addEventListener("click", () => {
        illustrative = true;
        current.value = "185.166.26.16";
        next.value = "185.166.27.222";
        rules.value = ["MONITOR-", "MONITOR-SYN-", "MONITOR-UDP-"]
            .map((prefix) => prefix + current.value).join("\n");
        document.getElementById("confirmIpChange").checked = false;
        updatePreview();
    });
    const search = document.getElementById("ipSearch");
    const deviceFilter = document.getElementById("ipDeviceFilter");
    const statusFilter = document.getElementById("ipStatusFilter");
    const rows = [...document.querySelectorAll("[data-ip-row]")];
    function updateEmptyState() {
        let visible = 0;
        rows.forEach((row) => {
            row.hidden = Boolean(!row.dataset.address.includes(search.value.trim()) ||
                (deviceFilter.value && row.dataset.deviceId !== deviceFilter.value) ||
                (statusFilter.value && row.dataset.monitoringStatus !== statusFilter.value));
            if (!row.hidden) visible++;
        });
        document.getElementById("noMatchingIPs").hidden = rows.length === 0 || visible > 0;
        const count = document.getElementById("ipVisibleCount");
        if (count) count.textContent = visible;
    }
    const addDialog = document.getElementById("addIpDialog");
    if (addDialog?.dataset.hasErrors === "true") {
        addDialog.removeAttribute("open");
        addDialog.showModal();
        addDialog.querySelector('[aria-invalid="true"]')?.focus();
    }
    document.querySelectorAll('[data-auto-open="true"]').forEach((dialog) => {
        dialog.removeAttribute("open"); dialog.showModal();
        dialog.querySelector('[aria-invalid="true"]')?.focus();
    });
    window.addEventListener("pageshow", () => {
        document.querySelectorAll('.ip-dialog button[type="submit"]').forEach((save) => { save.disabled = false; if (save.dataset.idleText) save.textContent = save.dataset.idleText; });
        const save = document.getElementById("savePublicIPButton");
        if (save) { save.disabled = false; save.textContent = "Save"; }
        updateProvisioningNotice();
    });
    search.addEventListener("input", updateEmptyState);
    [deviceFilter, statusFilter].forEach((filter) => filter.addEventListener("change", updateEmptyState));
    document.addEventListener("click", (event) => {
        document.querySelectorAll(".public-ip-actions").forEach((menu) => {
            if (!menu.contains(event.target) || event.target.closest("a")) menu.open = false;
        });
    });
    document.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") return;
        document.querySelectorAll(".public-ip-actions[open]").forEach((menu) => {
            menu.open = false;
            menu.querySelector("summary").focus();
        });
    });

    const monitoringPanel = document.querySelector("[data-raw-data-url]");
    function monitoringLabel(sample, row) {
        if (sample.monitoring_health) return sample.monitoring_health;
        if (sample.retained === true) return "Saved Sample";
        if (sample.provisioning_status !== "verified" || row.dataset.monitoringEnabled !== "true") return "Not Monitored";
        return sample.status === "Monitoring" ? "Active" : "No Data";
    }
    function provisioningLabel(sample) {
        if (sample.provisioning_code === "rule_conflict") return "Conflict";
        if (sample.provisioning_status === "verified") return "Provisioned";
        if (sample.provisioning_status === "failed") return "Failed";
        return "Pending";
    }
    function updateMonitoringBadge(row, status) {
        row.dataset.monitoringStatus = status;
        const badge = row.querySelector('[data-raw="status"]');
        if (badge) { badge.textContent = status; badge.dataset.state = status.toLowerCase().replaceAll(" ", "-"); }
    }
    function clearMetrics(row) {
        row.querySelectorAll('[data-raw]:not([data-raw="status"])').forEach(element => {
            element.textContent = "—";
            element.removeAttribute("datetime");
        });
    }
    function updateSummaries(total, monitored) {
        const totalElement = document.getElementById("publicIPTotal");
        if (totalElement) totalElement.textContent = total;
        document.querySelectorAll("[data-raw-summary]").forEach(element => {
            element.textContent = element.dataset.rawSummary === "monitoring" ? monitored : total - monitored;
        });
    }
    let readingCounters = false;
    async function readCounters() {
        if (readingCounters) return;
        readingCounters = true;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 10000);
        try {
            const response = await fetch(monitoringPanel.dataset.rawDataUrl, {
                credentials: "same-origin", cache: "no-store", signal: controller.signal
            });
            if (!response.ok) throw new Error("request");
            const result = await response.json();
            if ([2, 5, 10, 15, 30, 60].includes(result.polling_interval)) {
                document.querySelectorAll("[data-polling-interval]").forEach(element => element.textContent = result.polling_interval);
            }
            const savedIds = new Set(result.rows.map(sample => String(sample.id)));
            for (let index = rows.length - 1; index >= 0; index--) {
                if (!savedIds.has(rows[index].dataset.ipId)) { rows[index].remove(); rows.splice(index, 1); }
            }
            const total = document.getElementById("publicIPTotal"); if (total) total.textContent = result.rows.length;
            if (!rows.length && !result.rows.length && !document.querySelector(".device-empty-content")) {
                const empty = document.createElement("div");
                empty.className = "ip-empty-state device-empty-content";
                empty.textContent = "No public IPs configured";
                document.getElementById("noMatchingIPs").before(empty);
            }
            for (const sample of result.rows) {
                const row = rows.find((item) => item.dataset.ipId === String(sample.id));
                if (row) {
                    row.dataset.hasSample = String(sample.status === 'Monitoring' || sample.retained === true);
                    if (typeof sample.monitoring_enabled === "boolean") row.dataset.monitoringEnabled = String(sample.monitoring_enabled);
                    row.dataset.provisioningStatus = sample.provisioning_status;
                    updateMonitoringBadge(row, monitoringLabel(sample, row));
                    window.NetShieldDetection?.render(row, sample);
                    if (typeof sample.detection_enabled === "boolean") {
                        const enableDetection = row.querySelector('[data-detection-enable]');
                        const disableDetection = row.querySelector('[data-detection-disable]');
                        if (enableDetection) enableDetection.hidden = sample.detection_enabled;
                        if (disableDetection) disableDetection.hidden = !sample.detection_enabled;
                    }
                    const monitoringMessage = row.querySelector('[data-monitoring-message]');
                    if (monitoringMessage) monitoringMessage.textContent = sample.monitoring_message || '';
                    const retainedNote = row.querySelector('[data-retained-note]');
                    if (retainedNote) retainedNote.hidden = !sample.retained;
                    const start = row.querySelector('[data-monitor-start]');
                    const stop = row.querySelector('[data-monitor-stop]');
                    if (start) start.hidden = sample.monitoring_running === true;
                    if (stop) stop.hidden = sample.monitoring_running !== true;
                    const label = row.querySelector("[data-provisioning-label]");
                    const message = row.querySelector("[data-provisioning-message]");
                    if (label) {
                        label.textContent = provisioningLabel(sample);
                        label.dataset.state = label.textContent.toLowerCase();
                        label.title = sample.provisioning_status === "verified" ? "Provisioned: RAW rules verified"
                            : sample.provisioning_code === "approval_required" ? "Pending: approval required" : label.textContent;
                    }
                    if (message) message.textContent = sample.provisioning_message || "";
                }
                row?.querySelectorAll("[data-raw]").forEach((element) => {
                    if (element.dataset.raw === "status") return;
                    const value = sample[element.dataset.raw];
                    const hasSample = row.dataset.monitoringStatus === "Active" || sample.retained === true;
                    element.textContent = !hasSample || value === null || value === undefined ? "—"
                        : element.dataset.raw === "last_update" ? (Number.isNaN(Date.parse(value)) ? "—" : new Date(value).toLocaleString())
                        : typeof value === "number" ? (Number.isFinite(value) ? value.toLocaleString(undefined, {
                            maximumFractionDigits: element.dataset.raw === "mbps" ? 6
                                : ["pps", "syn_pps", "udp_pps"].includes(element.dataset.raw) ? 2 : 0
                        }) : "—") : String(value);
                    if (element.dataset.raw === "last_update" && hasSample && value && !Number.isNaN(Date.parse(value))) element.dateTime = value;
                    else element.removeAttribute("datetime");
                });
            }
            const monitored = rows.filter(row => row.dataset.monitoringStatus === "Active").length;
            updateSummaries(result.rows.length, monitored);
            updateEmptyState();
        } catch (_) {
            rows.forEach(row => {
                window.NetShieldDetection?.render(row, {ddos_status: "Unknown", ddos_message: "Current detection data is unavailable."});
                const saved = row.dataset.hasSample === 'true';
                updateMonitoringBadge(row, row.dataset.monitoringEnabled === "true" && row.dataset.provisioningStatus === "verified" ? "Stale" : "Not Monitored");
                if (!saved) clearMetrics(row);
                const note = row.querySelector('[data-retained-note]');
                if (note) note.hidden = !saved;
                const message = row.querySelector('[data-monitoring-message]');
                if (message) message.textContent = 'Connection to NetShield unavailable. Displaying the last received sample where available.';
            });
            updateSummaries(rows.length, 0);
            updateEmptyState();
        } finally {
            clearTimeout(timer);
            readingCounters = false;
        }
    }
    // This endpoint reads only NetShield database/cache; it never contacts routers.
    if (monitoringPanel) {
        readCounters();
        setInterval(readCounters, 2000);
    }
    updatePreview();
})();
