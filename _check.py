import os
import re
import shutil

import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netshield.settings')
django.setup()

from django.conf import settings  # noqa: E402
from django.contrib.auth import get_user_model  # noqa: E402
from django.test import Client  # noqa: E402

settings.ALLOWED_HOSTS = list(settings.ALLOWED_HOSTS) + ['127.0.0.1', 'testserver']

user = get_user_model().objects.filter(is_superuser=True).first()
client = Client(SERVER_NAME='127.0.0.1')
client.force_login(user)
html = client.get('/devices/topology/map/').content.decode()

os.makedirs('_site/static', exist_ok=True)
# Copy every asset the page references, or a missing one 404s and the script never runs.
for folder in ('css', 'js'):
    for name in os.listdir(os.path.join('monitor/static/monitor', folder)):
        shutil.copy(os.path.join('monitor/static/monitor', folder, name), os.path.join('_site/static', name))
for folder in ('css', 'js'):
    extra = os.path.join('sensors/static/sensors', folder)
    if os.path.isdir(extra):
        for name in os.listdir(extra):
            shutil.copy(os.path.join(extra, name), os.path.join('_site/static', name))

html = re.sub(r'/static/monitor/css/([\w-]+)\.css[^"\']*', r'static/\1.css', html)
html = re.sub(r'/static/monitor/js/([\w-]+)\.js[^"\']*', r'static/\1.js', html)

PROBE = '''
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var g = [].slice.call(document.querySelectorAll('.tmap-node'))
              .find(function (n) { return /limit-2/i.test(n.textContent); });
    var box = g.querySelector('.tmap-box');
    box.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    setTimeout(function () {
      var act = document.querySelectorAll('.tmap-link.is-active');
      var s = act[0] ? getComputedStyle(act[0]) : null;
      var d = document.createElement('div');
      d.style.cssText = 'position:fixed;top:0;left:0;z-index:99999;background:#000;color:#fff;font:14px monospace;padding:8px';
      d.textContent = 'selected=' + document.querySelectorAll('.tmap-node.is-selected').length
        + ' dim=' + document.querySelectorAll('.tmap-node.is-dim').length
        + ' activeLinks=' + act.length
        + (s ? ' stroke=' + s.stroke + ' w=' + s.strokeWidth : '');
      document.body.appendChild(d);
    }, 800);
  }, 1500);
});
</script>
'''

html = html.replace('</body>', PROBE + '</body>')
open('_site/index.html', 'w', encoding='utf-8').write(html)
print('wrote _site/index.html')
