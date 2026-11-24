import asyncio

from playwright.async_api import async_playwright


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel='chrome')
        page = await browser.new_page(viewport={'width': 1400, 'height': 900})
        errors = []
        page.on('console', lambda m: errors.append(m.text) if m.type == 'error' else None)
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.on('requestfailed', lambda r: errors.append('FAILED ' + r.url.split('/')[-1]))
        page.on('response', lambda r: errors.append('HTTP %d %s' % (r.status, r.url.split('/')[-1]))
                if r.url.endswith('.js') else None)

        await page.goto('file:///D:/DDOS/_site/index.html')
        await page.wait_for_timeout(1200)
        print('script tag present:', await page.evaluate(
            "[...document.scripts].map(s => s.src.split('/').pop()).filter(Boolean)"))
        print('nodes:', await page.evaluate("document.querySelectorAll('.tmap-node').length"))

        print('script evaluations:', await page.evaluate('window.__evals'))
        print('found:', await page.evaluate("""() => ({
            svg: !!document.querySelector('[data-topo-svg]'),
            map: !!document.querySelector('[data-topo-map]'),
            nodeEls: document.querySelectorAll('[data-topo-svg] [data-node]').length,
        })"""))
        print('box count:', await page.locator('.tmap-box').count())
        b = await page.evaluate("""() => {
            const g = [...document.querySelectorAll('.tmap-node')].find(n => /limit-2/i.test(n.textContent));
            const r = g.querySelector('.tmap-box').getBoundingClientRect();
            return {x: r.x + r.width/2, y: r.y + r.height/2, w: r.width, h: r.height};
        }""")
        print('box rect:', b)
        print('element at point:', await page.evaluate(
            f"() => {{ const e = document.elementFromPoint({b['x']}, {b['y']}); return e ? e.getAttribute('class') || e.tagName : null; }}"))
        await page.evaluate("""() => {
            const g = [...document.querySelectorAll('.tmap-node')].find(n => /limit-2/i.test(n.textContent));
            window.__clicks = 0;
            g.addEventListener('click', () => { window.__clicks++; });
        }""")
        await page.mouse.click(b['x'], b['y'])
        await page.wait_for_timeout(500)
        print('clicks seen on <g>:', await page.evaluate('window.__clicks'))
        print('nested data-node inside one card:', await page.evaluate("""() => {
            const g = [...document.querySelectorAll('.tmap-node')].find(n => /limit-2/i.test(n.textContent));
            return g.querySelectorAll('[data-node]').length;
        }"""))
        print('event listeners probe (is the card inside another clickable?):',
              await page.evaluate("""() => {
            const g = [...document.querySelectorAll('.tmap-node')].find(n => /limit-2/i.test(n.textContent));
            const path = [];
            let el = g;
            while (el && el !== document.body) { path.push(el.tagName + '.' + (el.getAttribute('class')||'') + '[' + (el.getAttribute('data-node')||'') + ']'); el = el.parentElement; }
            return path;
        }"""))
        print('detection_ui binds nodes?:', await page.evaluate(
            "!!window.__detectionNodes"))
        print('selected after click:', await page.evaluate(
            "document.querySelectorAll('.tmap-node.is-selected').length"))
        # Two handlers = start() ran twice. Check by binding a second probe.
        print('dimmed:', await page.evaluate("document.querySelectorAll('.tmap-node.is-dim').length"))
        print('title after click:', await page.evaluate(
            "document.querySelector('[data-inspect-title]').textContent"))

        result = await page.evaluate("""() => {
            const act = document.querySelectorAll('.tmap-link.is-active');
            const s = act[0] ? getComputedStyle(act[0]) : null;
            return {
                selected: [...document.querySelectorAll('.tmap-node.is-selected')]
                    .map(n => n.querySelector('.tmap-name').textContent),
                dimmed: document.querySelectorAll('.tmap-node.is-dim').length,
                activeLinks: act.length,
                stroke: s ? s.stroke : null,
                width: s ? s.strokeWidth : null,
                filter: s ? s.filter : null,
            };
        }""")
        print('errors:', errors)
        print('result:', result)
        await page.screenshot(path='_shot.png')
        await browser.close()


asyncio.run(main())
