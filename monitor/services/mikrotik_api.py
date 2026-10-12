import os

import routeros_api


# MikroTik connection settings
HOST = "172.26.241.16"
PORT = 4949
USERNAME = os.environ.get("MIKROTIK_USERNAME", "1")
PASSWORD = os.environ.get("MIKROTIK_PASSWORD", "1")


def get_firewall_rules():
    """
    Read MikroTik RAW firewall monitoring counters.
    Read-only: does not change firewall rules.
    """
    connection = None

    try:
        connection = routeros_api.RouterOsApiPool(
            HOST,
            username=USERNAME,
            password=PASSWORD,
            port=PORT,
            plaintext_login=True,
        )

        api = connection.get_api()
        raw = api.get_resource("/ip/firewall/raw")
        rules = raw.get()

        result = []

        for rule in rules:
            comment = rule.get("comment", "")

            if comment.startswith("MONITOR-"):
                packets = int(rule.get("packets", 0))
                byte_count = int(rule.get("bytes", 0))

                result.append({
                    "name": comment,
                    "packets": packets,
                    "bytes": byte_count,
                    "gb": byte_count / (1024 ** 3),
                })

        return result

    finally:
        if connection is not None:
            connection.disconnect()