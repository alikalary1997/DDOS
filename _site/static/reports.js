(() => {
    "use strict";
    // Local configuration and layout only. No requests, storage, downloads or scheduling.
    const form = document.getElementById("reportConfigForm");
    const type = document.getElementById("reportType");
    const format = document.getElementById("reportFormat");
    const range = document.getElementById("reportTimeRange");
    const start = document.getElementById("reportStartDate");
    const end = document.getElementById("reportEndDate");
    const preview = document.getElementById("previewReport");
    const dateMessage = document.getElementById("reportDateMessage");
    const reportTitles = {
        ddos: "DDoS Attack Report", public_ip: "Public IP Traffic Report",
        device: "Device Performance Report", network: "Network Traffic Report", alerts: "Alerts Report"
    };
    const rangeLabels = { hour: "Last Hour", day: "24 Hours", week: "7 Days", month: "30 Days" };
    const formats = { pdf: "PDF", csv: "CSV", excel: "Excel" };
    function updateConfiguration() {
        const custom = range.value === "custom";
        start.disabled = !custom;
        end.disabled = !custom;
        dateMessage.textContent = custom && start.value && end.value && start.value > end.value
            ? "Choose an end date on or after the start date."
            : custom && (!start.value || !end.value) ? "Select both dates for a Custom period." : "";
        preview.disabled = !type.value || !format.value || !range.value || Boolean(dateMessage.textContent);
        document.getElementById("generateReport").disabled = true;
        if (document.getElementById("previewReportTitle").textContent !== "No data available") {
            document.getElementById("reportPreviewStatus").textContent = "Configuration changed. Preview Report to update the layout selections; report data remains unavailable.";
        }
    }
    form.addEventListener("submit", (event) => event.preventDefault());
    [type, format, range, start, end].forEach((field) => field.addEventListener("change", updateConfiguration));
    preview.addEventListener("click", () => {
        if (preview.disabled) return;
        document.getElementById("previewReportTitle").textContent = reportTitles[type.value];
        document.getElementById("previewReportPeriod").textContent = range.value === "custom"
            ? `${start.value} to ${end.value} (selected dates only)`
            : `${rangeLabels[range.value]} (selected range only)`;
        document.getElementById("previewReportFormat").textContent = `${formats[format.value]} (no file generated)`;
        document.getElementById("reportPreviewStatus").textContent = "Selected configuration only. No report has been generated; statistics, graphs and events remain unavailable.";
        document.getElementById("reportPreviewPanel").focus();
    });
    const search = document.getElementById("reportHistorySearch");
    const historyType = document.getElementById("reportHistoryType");
    const status = document.getElementById("reportHistoryStatus");
    function updateHistory() {
        document.getElementById("reportHistoryEmpty").textContent = search.value.trim() || historyType.value || status.value
            ? "No report history is available to search or filter. The reporting backend is not implemented."
            : "No data available. Report generation and history are not implemented yet.";
    }
    search.addEventListener("input", updateHistory);
    [historyType, status].forEach((field) => field.addEventListener("change", updateHistory));
    document.getElementById("clearReportFilters").addEventListener("click", () => {
        [search, historyType, status].forEach((field) => field.value = "");
        updateHistory();
    });
    updateConfiguration();
})();
