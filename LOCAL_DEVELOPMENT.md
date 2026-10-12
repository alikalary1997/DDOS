# Local NetShield access

The simplest safe setup is a real Django login with a persistent session. Local
mode keeps that session for 30 days, so signing in once is enough across browser
and server restarts. It never logs in automatically, creates a default account,
stores your Django password in a script, or gives anonymous users permissions.

## One-time administrator creation

Inspection found no active administrator account. In your own PowerShell terminal:

    Set-Location D:\DDOS
    .\venv\Scripts\python.exe manage.py createsuperuser

Choose your username and password privately at Django's interactive prompts.
Do not paste them into chat or put them on the command line. This creates a
Django application account; it is separate from MikroTik API credentials.
If you already created an administrator since inspection, use that account
instead of creating another one.

## Daily use

Start (or restart) the server with the explicit local launcher:

    .\start-netshield-local.ps1

Open http://127.0.0.1:8000/devices/ and sign in once. Continue using the same
browser and URL. Normal browser cookies preserve login for up to 30 days;
clearing cookies, private browsing, session expiry, account deactivation or a
password change can require another login. The cookie is host-only and HttpOnly.
You can sign out through Django's existing administrator interface if required.

The local launcher reuses the existing persistent device encryption key and
checks encryption before starting, as the normal launcher does. It never
regenerates a key. Your device records and encrypted passwords are unchanged.

## Isolation from network deployments

Local mode explicitly selects netshield.settings_local; netshield.settings
remains unchanged. It binds to 127.0.0.1 and rejects a non-loopback bind when
-LocalDevelopment is passed to the underlying launcher. Request middleware also
rejects non-loopback peers, nonlocal Host headers and forwarded/proxy headers.
The local-only request guard fails closed with DEBUG=False. No IP-based user
creation, account selection or permission escalation is implemented.

The normal .\start-netshield.ps1 command keeps the normal settings and current
session policy. Public/network deployments must use their usual settings and
normal authentication; this local profile is not a deployment configuration.
A separate netshield_local_sessionid cookie prevents the browser from sending
the local session as the normal deployment's session cookie.

Database-backed sessions survive Django restarts. SESSION_SAVE_EVERY_REQUEST
stays False, so Dashboard's 2-second monitoring reads do not write sessions on
every refresh. Adding devices still requires an active staff/superuser account,
POST, CSRF and valid server-side credential encryption.

References: [Django sessions](https://docs.djangoproject.com/en/6.1/topics/http/sessions/).
