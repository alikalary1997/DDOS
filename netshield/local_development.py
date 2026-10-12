"""Reject network/proxy access to the explicit local-development profile."""
import ipaddress
from urllib.parse import urlsplit

from django.conf import settings
from django.http import HttpResponseForbidden


class LocalDevelopmentOnlyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        allowed = settings.DEBUG and getattr(settings, "LOCAL_DEVELOPMENT_ACCESS", False)
        try:
            peer = ipaddress.ip_address(request.META.get("REMOTE_ADDR", ""))
            host = urlsplit("//" + request.get_host()).hostname
            allowed = allowed and peer.is_loopback and host is not None and host.lower().rstrip(".") in {"localhost", "127.0.0.1", "::1"}
        except (ValueError, TypeError):
            allowed = False
        # This profile must not be exposed through a network reverse proxy.
        if any(name == "HTTP_FORWARDED" or name == "HTTP_X_REAL_IP" or name.startswith("HTTP_X_FORWARDED_") for name in request.META):
            allowed = False
        if not allowed:
            return HttpResponseForbidden("Local development access is available only directly from this PC.")
        return self.get_response(request)
