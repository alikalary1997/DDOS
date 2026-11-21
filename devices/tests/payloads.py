"""Shared readers for the device page's embedded JSON payloads.

The device page renders its table client-side from `ref-devices` (and its sidebar / pickers from
`ref-sidebar`, `ref-group-options`, `ref-topology-options`), so tests read those payloads rather
than looking for server-rendered table markup.
"""
import json


def _payload(html, script_id):
    marker = f'<script id="{script_id}" type="application/json">'
    if marker not in html:
        return []
    return json.loads(html.split(marker, 1)[1].split('</script>', 1)[0])


def device_rows(response_or_html):
    """The device rows the page will render."""
    html = response_or_html.content.decode() if hasattr(response_or_html, 'content') else response_or_html
    return _payload(html, 'ref-devices')


def page_config(response_or_html):
    """canAdd / canDelete / groupCreateUrl, which gate the page's management actions."""
    html = response_or_html.content.decode() if hasattr(response_or_html, 'content') else response_or_html
    return _payload(html, 'ref-config') or {}
