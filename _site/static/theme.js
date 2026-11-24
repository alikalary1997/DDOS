(() => {
    "use strict";
    const key = "netshield.theme";
    const choices = new Set(["dark", "light", "system"]);
    const root = document.documentElement;
    const media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
    let preference = "dark";
    function normalize(value) { return choices.has(value) ? value : "dark"; }
    try { preference = normalize(window.localStorage.getItem(key)); } catch (_) { /* Storage can be restricted. */ }
    function effectiveTheme() {
        return preference === "system" ? (media?.matches ? "dark" : "light") : preference;
    }
    function syncControls() {
        const effective = effectiveTheme();
        const selector = document.getElementById("themePreview");
        if (selector) selector.value = preference;
        document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
            const target = effective === "dark" ? "light" : "dark";
            const label = `Switch to ${target === "light" ? "Light" : "Dark"} Mode`;
            button.setAttribute("aria-label", label);
            button.title = `${label} (current preference: ${preference})`;
            button.querySelector("[data-theme-icon]").textContent = effective === "dark" ? "\u2600" : "\u263e";
        });
    }
    function apply() {
        const theme = effectiveTheme();
        root.dataset.theme = theme;
        root.dataset.themePreference = preference;
        const meta = document.querySelector('meta[name="theme-color"]');
        if (meta) meta.content = theme === "light" ? "#f3f5f9" : "#07111f";
        syncControls();
    }
    function setPreference(value) {
        preference = normalize(value);
        try { window.localStorage.setItem(key, preference); } catch (_) { /* Apply in memory if saving is unavailable. */ }
        apply();
    }
    window.NetShieldTheme = { getPreference: () => preference, setPreference, syncControls };
    // This script is synchronous in <head>, before every stylesheet and first paint.
    apply();
    function bindControls() {
        document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
            button.addEventListener("click", () => setPreference(effectiveTheme() === "dark" ? "light" : "dark"));
        });
        const selector = document.getElementById("themePreview");
        if (selector) selector.addEventListener("change", () => setPreference(selector.value));
        syncControls();
    }
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bindControls, { once: true });
    else bindControls();
    const onSystemChange = () => { if (preference === "system") apply(); };
    if (media?.addEventListener) media.addEventListener("change", onSystemChange);
    else if (media?.addListener) media.addListener(onSystemChange);
    window.addEventListener("storage", (event) => {
        if (event.key !== key && event.key !== null) return;
        preference = normalize(event.newValue);
        apply();
    });
})();
