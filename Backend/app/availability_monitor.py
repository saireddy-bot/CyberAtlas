import socket
from typing import Dict


# ============================================================
# HOST REACHABILITY
# ============================================================

def check_host_reachability(
    ip_address: str
) -> Dict:

    if not ip_address:
        return {
            "check": "host_reachability",
            "status": "offline",
            "reachable": False,
            "ip_address": None,
            "message": "No IP address provided."
        }

    # Common ports used to determine whether a host
    # is accepting network connections.
    common_ports = [
        80,
        443,
        22,
        8000,
        8002,
        8080
    ]

    reachable_port = None

    for port in common_ports:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(1)

        try:

            result = sock.connect_ex(
                (ip_address, port)
            )

            if result == 0:
                reachable_port = port
                break

        except socket.error:
            pass

        finally:
            sock.close()

    if reachable_port is not None:

        return {
            "check": "host_reachability",
            "status": "online",
            "reachable": True,
            "ip_address": ip_address,
            "detected_port": reachable_port,
            "message": (
                f"Host is reachable on TCP port "
                f"{reachable_port}."
            )
        }

    return {
        "check": "host_reachability",
        "status": "offline",
        "reachable": False,
        "ip_address": ip_address,
        "detected_port": None,
        "message": (
            "No tested TCP service responded. "
            "Host may be offline or blocking connections."
        )
    }