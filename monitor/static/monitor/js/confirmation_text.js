(() => {
    "use strict";
    const dialog = document.getElementById("deleteDeviceDialog");
    if (!dialog) return;
    // Decode numeric entities in text nodes only. Never parse HTML or alter form values.
    const walker = document.createTreeWalker(dialog, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
        node.nodeValue = node.nodeValue.replace(/&(?:amp;)*#(x[0-9a-f]+|[0-9]+);/gi, (entity, number) => {
            const value = number[0].toLowerCase() === "x"
                ? Number.parseInt(number.slice(1), 16) : Number.parseInt(number, 10);
            if (!Number.isInteger(value) || value < 32 || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return entity;
            return String.fromCodePoint(value);
        });
    }
})();
