import asyncio

from playwright.async_api import async_playwright


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel='chrome')
        page = await browser.new_page(viewport={'width': 1400, 'height': 900})
        await page.goto('file:///D:/DDOS/_site/index.html')
        await page.wait_for_timeout(1500)

        box = await page.evaluate("""() => {
            const g = [...document.querySelectorAll('.tmap-node')].find(n => /limit-2/i.test(n.textContent));
            const r = g.querySelector('.tmap-box').getBoundingClientRect();
            return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
        }""")
        await page.mouse.click(box['x'], box['y'])
        await page.wait_for_timeout(600)

        state = await page.evaluate("""() => ({
            selected: document.querySelectorAll('.tmap-node.is-selected').length,
            dimmed: document.querySelectorAll('.tmap-node.is-dim').length,
            active: document.querySelectorAll('.tmap-link.is-active').length,
        })""")
        print('after 1 click:', state)

        # Click it again: it should clear.
        await page.mouse.click(box['x'], box['y'])
        await page.wait_for_timeout(600)
        print('after 2 clicks:', await page.evaluate("""() => ({
            selected: document.querySelectorAll('.tmap-node.is-selected').length,
            dimmed: document.querySelectorAll('.tmap-node.is-dim').length,
        })"""))
        await browser.close()


asyncio.run(main())
