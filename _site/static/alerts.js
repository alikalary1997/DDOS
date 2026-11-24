(() => {
    "use strict";
    // Local filter previews only: no requests, polling, persistence or notifications.
    const search = document.getElementById("alertSearch");
    const severity = document.getElementById("alertSeverityFilter");
    const status = document.getElementById("alertStatusFilter");
    const startDate = document.getElementById("alertStartDate");
    const endDate = document.getElementById("alertEndDate");
    const emptyMessage = document.getElementById("alertEmptyMessage");
    const dateMessage = document.getElementById("alertDateMessage");
    function updateFilterPreview() {
        dateMessage.textContent = startDate.value && endDate.value && startDate.value > endDate.value
            ? "Choose an end date on or after the start date." : "";
        const filtering = search.value.trim() || severity.value || status.value || startDate.value || endDate.value;
        emptyMessage.textContent = filtering
            ? "No alert data is available to search or filter. A real alert source is not connected."
            : "No data available. Connect a real alert source to populate this feed.";
    }
    search.addEventListener("input", updateFilterPreview);
    [severity, status, startDate, endDate].forEach((field) => field.addEventListener("change", updateFilterPreview));
    document.getElementById("clearAlertFilters").addEventListener("click", () => {
        [search, severity, status, startDate, endDate].forEach((field) => field.value = "");
        updateFilterPreview();
    });
})();
