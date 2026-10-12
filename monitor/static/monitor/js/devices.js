(() => {
    "use strict";
    const dialog = document.getElementById("addDeviceDialog");
    const form = document.getElementById("addDeviceForm");
    let opener = null;
    if (dialog && form) {
        document.querySelectorAll("[data-open-device]").forEach((button) => {
            button.disabled = false;
            button.addEventListener("click", () => {
                opener = button;
                form.querySelectorAll('[role="alert"]').forEach((alert) => alert.remove());
                form.reset();
                form.querySelector('[name="password"]').value = "";
                dialog.showModal();
            });
        });
        document.getElementById("closeDeviceDialog").addEventListener("click", () => dialog.close());
        document.getElementById("cancelDeviceDialog").addEventListener("click", () => dialog.close());
        dialog.addEventListener("close", () => {
            form.reset();
            form.querySelector('[name="password"]').value = "";
            opener?.focus();
        });
        dialog.addEventListener("click", (event) => {
            if (event.target !== dialog) return;
            const bounds = dialog.getBoundingClientRect();
            if (event.clientX < bounds.left || event.clientX > bounds.right ||
                event.clientY < bounds.top || event.clientY > bounds.bottom) dialog.close();
        });
        // Native same-origin POST includes Django's CSRF token. No browser storage.
        form.addEventListener("submit", () => {
            const save = document.getElementById("saveDeviceButton");
            save.disabled = true;
            save.textContent = "Saving…";
        });
        if (dialog.dataset.hasErrors === "true") {
            // Upgrade the server-rendered open dialog to a modal without losing errors.
            dialog.removeAttribute("open");
            dialog.showModal();
            form.querySelector('[aria-invalid="true"]')?.focus();
        }
    }
    const search = document.getElementById("deviceSearch");
    const status = document.getElementById("statusFilter");
    const type = document.getElementById("typeFilter");
    const raw = document.getElementById("rawFilter");
    const rows = [...document.querySelectorAll("[data-device-row]")];
    const noMatches = document.getElementById("noMatchingDevices");
    function filterRows() {
        const query = search.value.trim().toLowerCase();
        let visible = 0;
        rows.forEach((row) => {
            const searchable = [...row.cells].slice(0, 2).map((cell) => cell.textContent).join(" ").toLowerCase();
            row.hidden = Boolean(!searchable.includes(query) ||
                (status.value && row.dataset.deviceStatus !== status.value) ||
                (type.value && row.dataset.deviceType !== type.value) ||
                (raw?.value && row.dataset.rawStatus !== raw.value));
            if (!row.hidden) visible += 1;
        });
        noMatches.hidden = rows.length === 0 || visible > 0;
    }
    search.addEventListener("input", filterRows);
    status.addEventListener("change", filterRows);
    type.addEventListener("change", filterRows);
    raw?.addEventListener("change", filterRows);
    const inventoryView = document.getElementById("inventoryView");
    document.querySelectorAll("[data-inventory-view]").forEach(button => {
        button.addEventListener("click", () => {
            inventoryView.dataset.view = button.dataset.inventoryView;
            document.querySelectorAll("[data-inventory-view]").forEach(item => item.setAttribute("aria-pressed", String(item === button)));
        });
    });
    document.querySelectorAll("[data-inspect-device]").forEach(button => {
        button.addEventListener("click", () => document.getElementById("deviceInspector" + button.dataset.inspectDevice)?.showModal());
    });
    document.querySelectorAll("[data-device-inspector]").forEach(inspector => {
        inspector.querySelectorAll("[data-close-inspector]").forEach(button => button.addEventListener("click", () => inspector.close()));
        inspector.addEventListener("close", () => document.querySelector('[data-inspect-device="' + inspector.dataset.deviceInspector + '"]')?.focus());
        const tabs = [...inspector.querySelectorAll("[data-inspector-tab]")];
        function selectTab(tab) {
            tabs.forEach(item => { item.setAttribute("aria-selected", String(item === tab)); item.tabIndex = item === tab ? 0 : -1; });
            inspector.querySelectorAll("[data-inspector-panel]").forEach(panel => panel.hidden = panel.dataset.inspectorPanel !== tab.dataset.inspectorTab);
        }
        tabs.forEach((tab, index) => {
            tab.addEventListener("click", () => selectTab(tab));
            tab.addEventListener("keydown", event => {
                const position = event.key === "ArrowRight" ? (index + 1) % tabs.length
                    : event.key === "ArrowLeft" ? (index + tabs.length - 1) % tabs.length
                    : event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : null;
                if (position !== null) { event.preventDefault(); selectTab(tabs[position]); tabs[position].focus(); }
            });
        });
    });

    const feedback = document.getElementById("connectionFeedback");
    function updateDeviceRow(row, device) {
        row?.querySelectorAll("[data-raw-provisioning-state]").forEach(element => {
            element.textContent = device.raw_status || (device.raw_provisioning_enabled ? "Enabled" : "Disabled");
        });
        if (!row) return;
        row.dataset.deviceStatus = device.status_filter;
        row.dataset.connectionStatus = device.connection_status;
        row.dataset.rawStatus = device.raw_status || (device.raw_provisioning_enabled ? "Enabled" : "Disabled");
        for (const [cell, value] of [["name", device.name], ["management_ip", device.management_ip], ["model", device.model || "Not available"], ["cpu", device.cpu_display], ["ram", device.ram_display]]) {
            const element = row.querySelector('[data-cell="' + cell + '"]');
            if (element) element.textContent = value;
        }
        const statusCell = row.querySelector('[data-cell="status"]');
        if (statusCell) statusCell.textContent = device.test_label || "Not Tested";
        const badge = row.querySelector("[data-card-status]");
        if (badge) { badge.dataset.state = device.connection_status; badge.textContent = device.connection_status === "online" ? "TEST PASSED" : device.connection_status === "offline" ? "TEST FAILED" : "NOT TESTED"; }
        row.querySelectorAll("[data-snapshot]").forEach(element => {
            const field = element.dataset.snapshot;
            const value = device[field];
            element.textContent = value ? (field === "tested_at" || field === "last_successful_connection" ? new Date(value).toLocaleString() : String(value)) : "Not available";
            if (element.tagName === "TIME") { if (value) element.dateTime = value; else element.removeAttribute("datetime"); }
        });
        for (const [metric, value] of [["cpu", device.last_connection_test_succeeded ? device.cpu_usage : null], ["ram", device.ram_usage_percent]]) {
            const meter = row.querySelector('[data-meter="' + metric + '"]');
            if (meter) { meter.hidden = value === null || value === undefined; meter.value = value ?? 0; }
        }
        const select = row.querySelector("[data-interface-select]");
        if (select) { const option = document.createElement("option"); option.value = device.incoming_monitoring_interface; option.textContent = device.incoming_monitoring_interface || "Select an interface"; select.replaceChildren(option); }
        document.getElementById("deviceInspector" + device.id)?.querySelectorAll("[data-detail]").forEach(element => {
            const field = element.dataset.detail;
            const value = field === "ssl_label" ? (device.use_ssl ? "Enabled" : "Disabled") : device[field];
            element.textContent = value === null || value === undefined || value === "" ? "Not available" :
                (["tested_at", "last_successful_connection", "raw_provisioning_authorized_at"].includes(field) ? new Date(value).toLocaleString() : String(value));
        });
        refreshSummary(); filterRows();
    }
    function refreshSummary() {
        document.querySelectorAll("[data-summary]").forEach(element => element.textContent = rows.filter(item => element.dataset.summary === "raw" ? item.dataset.rawStatus === "Enabled" : item.dataset.connectionStatus === element.dataset.summary).length);
        const total = document.getElementById("deviceTotal"); if (total) total.textContent = rows.length;
    }

    document.querySelectorAll("[data-test-connection]").forEach((testForm) => {
        testForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            const button = testForm.querySelector("button");
            const row = testForm.closest("[data-device-row]");
            button.disabled = true;
            button.textContent = "Testing…";
            feedback.hidden = false;
            feedback.textContent = "Testing the saved device…";
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 30000);
            try {
                const response = await fetch(testForm.action, {
                    method: "POST", credentials: "same-origin", signal: controller.signal,
                    headers: {"X-CSRFToken": testForm.querySelector("[name=csrfmiddlewaretoken]").value,
                              "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
                });
                if (!response.headers.get("Content-Type")?.includes("application/json")) throw new Error("request");
                const result = await response.json();
                feedback.textContent = result.error || result.message || "Connection test could not be completed.";
                if (result.device) {
                    updateDeviceRow(row, result.device);
                }
            } catch (error) {
                feedback.textContent = error.name === "AbortError"
                    ? "The request timed out. Refresh the inventory to check whether the server saved a result."
                    : "The test request could not be completed. Check your session and try again.";
            } finally {
                clearTimeout(timer);
                button.disabled = false;
                button.textContent = "Test Connection";
            }
        });
    });

    document.querySelectorAll("[data-load-interfaces]").forEach((button) => {
        button.addEventListener("click", async () => {
            const form = button.closest("[data-interface-form]");
            const feedback = form.querySelector("[data-interface-feedback]");
            const select = form.querySelector("[data-interface-select]");
            button.disabled = true;
            feedback.textContent = "Reading interface names…";
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 15000);
            try {
                const response = await fetch(button.dataset.loadInterfaces, {
                    method: "POST", credentials: "same-origin", signal: controller.signal,
                    headers: {"X-CSRFToken": form.querySelector("[name=csrfmiddlewaretoken]").value, "Accept": "application/json"}
                });
                const result = await response.json();
                if (!response.ok || !result.ok || !Array.isArray(result.interfaces)) throw new Error("request");
                const selected = select.value;
                select.replaceChildren();
                for (const name of result.interfaces) {
                    const option = document.createElement("option");
                    option.value = name;
                    option.textContent = name;
                    select.append(option);
                }
                if (result.interfaces.includes(selected)) select.value = selected;
                feedback.textContent = result.interfaces.length ? "Select the incoming interface, then Save interface." : "No enabled interfaces were returned.";
            } catch (_) {
                feedback.textContent = "Interface names could not be loaded. Check the device connection and your session.";
            } finally {
                clearTimeout(timer);
                button.disabled = false;
            }
        });
    });
    const actions = [...document.querySelectorAll(".device-actions")];
    document.addEventListener("click", (event) => {
        actions.forEach((action) => { if (!action.contains(event.target)) action.open = false; });
    });
    document.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") return;
        actions.forEach((action) => {
            if (action.open) { action.open = false; action.querySelector("summary").focus(); }
        });
    });
    // Restore the form if a browser returns via its back/forward cache.
    window.addEventListener("pageshow", () => {
        const save = document.getElementById("saveDeviceButton");
        if (save) { save.disabled = false; save.textContent = "Save"; }
        form?.querySelector('[name="password"]') && (form.querySelector('[name="password"]').value = "");
    });

    document.querySelectorAll("[data-device-management-dialog]").forEach(managementDialog => {
        managementDialog.removeAttribute("open"); managementDialog.showModal();
        const managementForm = managementDialog.querySelector("form");
        managementDialog.querySelectorAll("[data-close-management]").forEach(button => button.addEventListener("click", () => managementDialog.close()));
        managementDialog.addEventListener("close", () => {
            const password = managementForm.querySelector('[name="edit-password"]'); if (password) password.value = "";
        });
        managementForm.addEventListener("submit", async event => {
            event.preventDefault();
            const submit = managementForm.querySelector('button[type="submit"]');
            if (submit.disabled) return;
            const label = submit.textContent; submit.disabled = true; submit.textContent = "Saving…";
            const alert = managementForm.querySelector("[data-management-errors]"); alert.replaceChildren();
            const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 15000);
            try {
                const response = await fetch(managementForm.action, {method: "POST", body: new FormData(managementForm), credentials: "same-origin", signal: controller.signal, headers: {"Accept": "application/json"}});
                if (response.redirected || !response.headers.get("Content-Type")?.includes("application/json")) throw new Error("session");
                const result = await response.json();
                if (!response.ok || !result.ok) {
                    alert.textContent = result.error || "Changes were not saved.";
                    if (result.assigned_ip_count !== undefined) {
                        const count = managementDialog.querySelector("[data-assigned-count]"); if (count) count.textContent = result.assigned_ip_count;
                    }
                    for (const [field, errors] of Object.entries(result.errors || {})) {
                        errors.forEach(item => { const line = document.createElement("p"); const input = managementForm.querySelector('[name="edit-' + field + '"]'); const label = input?.closest("label")?.querySelector("span")?.textContent; line.textContent = (label ? label + ": " : "") + item.message; alert.append(line); });
                    }
                    return;
                }
                if (result.device) {
                    updateDeviceRow(rows.find(row => row.dataset.deviceId === String(result.device.id)), result.device);
                }
                if (result.deleted_id) {
                    document.getElementById("deviceInspector" + result.deleted_id)?.remove();
                    const index = rows.findIndex(row => row.dataset.deviceId === String(result.deleted_id));
                    if (index >= 0) { rows[index].remove(); rows.splice(index, 1); }
                    document.querySelectorAll("[data-detail]").forEach(element => element.textContent = "Not available");
                    if (!rows.length) { const row = document.getElementById("deviceRows").insertRow(0); const cell = row.insertCell(); cell.colSpan = 6; cell.className = "inventory-empty"; cell.textContent = "No devices have been added"; }
                    refreshSummary(); filterRows();
                    window.history.replaceState(null, "", managementForm.dataset.inventoryUrl || "/devices/");
                }
                feedback.hidden = false; feedback.textContent = result.message;
                managementDialog.close();
            } catch (error) {
                alert.textContent = error.name === "AbortError" ? "Request timed out. Refresh the inventory to check the saved result before retrying." : "Changes could not be saved. Check your session and try again.";
            } finally {
                const password = managementForm.querySelector('[name="edit-password"]'); if (password) password.value = "";
                clearTimeout(timer); submit.disabled = false; submit.textContent = label;
            }
        });
    });
})();
