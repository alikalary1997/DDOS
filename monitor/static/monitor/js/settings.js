(() => {
    "use strict";
    // Local design interactions only. Other fields remain previews; the shared theme controller handles browser preferences.
    const form = document.getElementById("settingsPreviewForm");
    const status = document.getElementById("settingsPreviewStatus");
    form.addEventListener("submit", (event) => event.preventDefault());
    function markPreview(event) {
        if (event.target?.id === "themePreview") return;
        status.textContent = "Unsaved design preview only. Existing configuration and monitoring remain unchanged.";
    }
    form.addEventListener("input", markPreview);
    form.addEventListener("change", markPreview);
    document.getElementById("resetSettingsPreview").addEventListener("click", () => {
        form.reset();
        window.NetShieldTheme?.syncControls();
        status.textContent = "Other settings remain previews. Theme is saved separately in this browser.";
    });
    const dialog = document.getElementById("userPreviewDialog");
    const userForm = document.getElementById("userPreviewForm");
    let opener = null;
    document.querySelectorAll("[data-user-preview]").forEach((button) => {
        button.disabled = false;
        button.addEventListener("click", () => {
            opener = button;
            userForm.reset();
            const editing = button.dataset.userPreview === "edit";
            document.getElementById("userPreviewTitle").textContent = editing ? "Edit User" : "Add User";
            document.getElementById("userPreviewDescription").textContent = editing
                ? "Edit layout preview. No existing user is selected or loaded."
                : "Add layout preview. No user accounts are created.";
            dialog.showModal();
        });
    });
    userForm.addEventListener("submit", (event) => event.preventDefault());
    dialog.querySelectorAll("[data-close-user]").forEach((button) => button.addEventListener("click", () => dialog.close()));
    dialog.addEventListener("close", () => {
        userForm.reset();
        opener?.focus();
    });
    dialog.addEventListener("click", (event) => {
        if (event.target !== dialog) return;
        const bounds = dialog.getBoundingClientRect();
        if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) dialog.close();
    });
})();
