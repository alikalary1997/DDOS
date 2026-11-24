(() => {
    "use strict";
    // UI preferences only. No requests, polling, telemetry synthesis or monitoring mutations.
    document.querySelectorAll(".traffic-graph").forEach((graph) => {
        const range = graph.querySelector(".graph-range");
        const rangeCopy = graph.querySelector(".plot-range-copy");
        range.addEventListener("change", () => {
            rangeCopy.textContent = `${range.value} view \u00b7 no samples available`;
        });
    });
    const units = document.getElementById("bandwidthUnits");
    units.addEventListener("change", () => {
        document.getElementById("bandwidthAxisLabel").textContent = `Bandwidth (${units.value})`;
    });
    const search = document.getElementById("interfaceSearch");
    const device = document.getElementById("interfaceDeviceFilter");
    const status = document.getElementById("interfaceStatusFilter");
    const emptyMessage = document.getElementById("interfaceEmptyMessage");
    function updateInterfaceEmptyState() {
        emptyMessage.textContent = search.value.trim() || device.value || status.value
            ? "No interface inventory is available to search or filter. Telemetry backend implementation is pending."
            : "No data available. Interface inventory and telemetry are not configured.";
    }
    search.addEventListener("input", updateInterfaceEmptyState);
    device.addEventListener("change", updateInterfaceEmptyState);
    status.addEventListener("change", updateInterfaceEmptyState);
})();
