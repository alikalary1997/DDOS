import asyncio

from playwright.async_api import async_playwright

BASE = 'http://127.0.0.1:8000'
SESSION = open('_session.txt', encoding='utf-8').read().strip()


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel='chrome')
        context = await browser.new_context(viewport={'width': 1400, 'height': 900})
        await context.add_cookies([{
            'name': 'sessionid', 'value': SESSION, 'domain': '127.0.0.1', 'path': '/',
        }])
        page = await context.new_page()
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.on('console', lambda m: errors.append('console:' + m.text) if m.type == 'error' else None)
        page.on('response', lambda r: errors.append('404 ' + r.url.split('/')[-1]) if r.status == 404 else None)

        await page.goto(f'{BASE}/devices/topology/map/')
        await page.wait_for_timeout(1500)
        print('url:', page.url)
        print('errors:', errors)
        print('nodes:', await page.evaluate("document.querySelectorAll('.tmap-node').length"))
        print('script tags:', await page.evaluate("[...document.scripts].map(s => s.src.split('/').pop()).filter(Boolean)"))
        # Is the topology script's IIFE actually finished (start() bound)?
        print('topo-nodes-data present:', await page.evaluate(
            "!!document.getElementById('topo-nodes-data')"))
        print('nodes json len:', await page.evaluate(
            "(document.getElementById('topo-nodes-data')||{}).textContent?.length || 0"))
        print('handler bound check:',
              await page.evaluate("""() => {
                  const g = document.querySelector('.tmap-node');
                  if (!g) return 'no nodes';
                  return 'has-click=' + (g.onclick !== null);
              }"""))

        box = await page.evaluate("""() => {
            const g = [...document.querySelectorAll('.tmap-node')].find(n => /Kalar/i.test(n.textContent));
            if (!g) return null;
            const r = g.querySelector('.tmap-box').getBoundingClientRect();
            return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
        }""")
        if box:
            # Count click events actually dispatched to the card.
            await page.evaluate("""() => {
                const g = [...document.querySelectorAll('.tmap-node')].find(n => /Kalar/i.test(n.textContent));
                window.__hits = 0;
                g.addEventListener('click', () => { window.__hits++; });
            }""")
            await page.mouse.click(box['x'], box['y'])
            print('clicks seen:', await page.evaluate('window.__hits'))
            print('title:', await page.evaluate("document.querySelector('[data-inspect-title]').textContent"))
            print('detail hidden:', await page.evaluate("document.querySelector('[data-inspect-detail]').hidden"))
            await page.wait_for_timeout(700)
            print('after click:', await page.evaluate("""() => {
                const a = document.querySelector('.tmap-link.is-active');
                const s = a ? getComputedStyle(a) : null;
                return {
                    selected: [...document.querySelectorAll('.tmap-node.is-selected')]
                        .map(n => n.querySelector('.tmap-name').textContent),
                    dimmed: document.querySelectorAll('.tmap-node.is-dim').length,
                    active: document.querySelectorAll('.tmap-link.is-active').length,
                    stroke: s ? s.stroke : null,
                    width: s ? s.strokeWidth : null,
                };
            }"""))
            await page.screenshot(path='_shot.png')
        await browser.close()


asyncio.run(main())
