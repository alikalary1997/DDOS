(() => {
    "use strict";
    // Only local UI previews. No detection, persistence, API calls, polling or mitigation.
    document.querySelectorAll(".attack-graphs .traffic-graph").forEach((graph) => {
        const range = graph.querySelector(".graph-range");
        range.addEventListener("change", () => {
            graph.querySelector(".plot-range-copy").textContent = `${range.value} view \u00b7 no samples available`;
        });
    });
    const units = document.getElementById("bandwidthUnits");
    units.addEventListener("change", () => {
        document.getElementById("bandwidthAxisLabel").textContent = `Bandwidth (${units.value})`;
    });
    const attackSearch = document.getElementById("attackSearch");
    const attackType = document.getElementById("attackTypeFilter");
    const severity = document.getElementById("attackSeverityFilter");
    function updateAttackEmptyState() {
        document.getElementById("attackEmptyMessage").textContent = attackSearch.value.trim() || attackType.value || severity.value
            ? "No attack events are available to search or filter. Detection backend implementation is pending."
            : "No data available. Live attack monitoring is not configured.";
    }
    attackSearch.addEventListener("input", updateAttackEmptyState);
    [attackType, severity].forEach((filter) => filter.addEventListener("change", updateAttackEmptyState));
    const historySearch = document.getElementById("historySearch");
    const startDate = document.getElementById("historyStartDate");
    const endDate = document.getElementById("historyEndDate");
    function updateHistoryEmptyState() {
        document.getElementById("historyDateMessage").textContent = startDate.value && endDate.value && startDate.value > endDate.value
            ? "Choose an end date on or after the start date." : "";
        document.getElementById("historyEmptyMessage").textContent = historySearch.value.trim() || startDate.value || endDate.value
            ? "No attack history is available to search or filter. The history backend is not connected."
            : "No data available. The attack history backend is not connected.";
    }
    historySearch.addEventListener("input", updateHistoryEmptyState);
    [startDate, endDate].forEach((field) => field.addEventListener("change", updateHistoryEmptyState));
    document.getElementById("clearHistoryFilters").addEventListener("click", () => {
        [historySearch, startDate, endDate].forEach((field) => field.value = "");
        updateHistoryEmptyState();
    });
    const form = document.getElementById("thresholdPreviewForm");
    const policyStatus = document.getElementById("thresholdPreviewStatus");
    form.addEventListener("submit", (event) => event.preventDefault());
    form.addEventListener("input", () => {
        const hasValues = Array.from(form.querySelectorAll("input")).some((field) => field.value !== "");
        policyStatus.textContent = hasValues
            ? "Unsaved preview values only. No detection thresholds have been applied."
            : "No data available. Detection policy is not configured.";
    });
    document.getElementById("resetThresholdPreview").addEventListener("click", () => {
        form.reset();
        policyStatus.textContent = "No data available. Detection policy is not configured.";
    });
})();
