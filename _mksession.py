import os

import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netshield.settings')
django.setup()

from django.contrib.auth import get_user_model  # noqa: E402
from django.test import Client  # noqa: E402

# Reuse the superuser already present so the browser can carry its session cookie.
user = get_user_model().objects.filter(is_superuser=True).first()
client = Client(SERVER_NAME='127.0.0.1')
client.force_login(user)
value = client.cookies['sessionid'].value
open('_session.txt', 'w', encoding='utf-8').write(value)
print('session for', user.get_username(), '->', value[:12] + '...')
