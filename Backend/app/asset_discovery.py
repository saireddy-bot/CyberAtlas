import socket


def discover_asset(ip_address: str):

    result = {
        "ip_address": ip_address,
        "reachable": False,
        "hostname": None,
        "status": "unknown"
    }

    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        result["hostname"] = hostname
    except socket.herror:
        result["hostname"] = None

    try:
        socket.gethostbyname(ip_address)
        result["reachable"] = True
        result["status"] = "reachable"
    except socket.error:
        result["reachable"] = False
        result["status"] = "unreachable"

    return result