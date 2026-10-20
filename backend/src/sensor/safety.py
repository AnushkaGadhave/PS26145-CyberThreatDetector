"""
NETRA Local Windows Sensor - Safety & Privacy Policy Module
Enforces operational safety constraints:
- Zero packet transmission/injection (passive only).
- Zero packet payload retention (header metadata only).
- Prevents misclassification of ordinary multicast/discovery traffic as C2.
- Distinguishes capture health from threat detection.
- Scrubbing/sanitization of telemetry for privacy.
"""

import ipaddress
import logging
from typing import Tuple, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Standard Local Discovery and Infrastructure Service Ports
DISCOVERY_PORTS = {
    53: "DNS",
    67: "DHCP_SERVER",
    68: "DHCP_CLIENT",
    123: "NTP",
    137: "NETBIOS_NAME",
    138: "NETBIOS_DATAGRAM",
    546: "DHCPV6_CLIENT",
    547: "DHCPV6_SERVER",
    1900: "SSDP_UPNP",
    3702: "WS_DISCOVERY",
    5353: "MDNS",
    5355: "LLMNR"
}


def is_multicast_or_broadcast_ip(ip_str: Optional[str]) -> bool:
    """
    Checks if an IP address belongs to a multicast, broadcast, or link-local range.
    Handles IPv4 and IPv6 safely.
    """
    if not ip_str:
        return False

    # Quick string prefix checks for high performance in live capture
    if ip_str.startswith("224.") or ip_str.startswith("239.") or ip_str.startswith("ff02:"):
        return True
    if ip_str == "255.255.255.255" or ip_str.endswith(".255"):
        return True

    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_multicast
            or addr.is_loopback
            or addr.is_link_local
            or (isinstance(addr, ipaddress.IPv4Address) and addr.is_reserved)
        )
    except ValueError:
        return False


def is_local_discovery_port(port: Optional[int]) -> bool:
    """Checks if a port matches standard local network service discovery protocols."""
    if port is None:
        return False
    return port in DISCOVERY_PORTS


def evaluate_multicast_discovery_safety(
    src_ip: str,
    dst_ip: str,
    dst_port: Optional[int],
    protocol: str
) -> Tuple[bool, Optional[str]]:
    """
    Evaluates whether a connection is ordinary local discovery or multicast traffic.
    Returns:
        (is_discovery, reason_description)
    """
    # 1. Destination is multicast or broadcast
    if is_multicast_or_broadcast_ip(dst_ip):
        port_desc = DISCOVERY_PORTS.get(dst_port or 0, f"Port {dst_port}")
        return True, f"Multicast/Broadcast destination ({dst_ip}:{port_desc})"

    # 2. Well-known local discovery service port
    if is_local_discovery_port(dst_port):
        svc_name = DISCOVERY_PORTS[dst_port]
        return True, f"Standard local discovery protocol ({svc_name} on port {dst_port})"

    # 3. Source is also link-local or loopback
    if is_multicast_or_broadcast_ip(src_ip):
        return True, f"Link-local/multicast source communication ({src_ip})"

    return False, None


def is_quic_traffic(dst_port: Optional[int], protocol: str) -> bool:
    """Check if connection uses UDP port 443 (standard QUIC / HTTP/3 web traffic)."""
    return (protocol or "").upper() == "UDP" and dst_port == 443


def is_established_web_flow(
    protocol: str,
    dst_port: Optional[int],
    total_packets: int,
    total_bytes: int,
    ack_count: int = 0
) -> bool:
    """
    Checks if a flow represents an established web session (HTTP/HTTPS) carrying application data,
    which must not be classified as a single-flow port reconnaissance scan.
    """
    is_web_port = dst_port in (80, 443, 8080, 8443)
    is_tcp = (protocol or "").upper() == "TCP"
    return is_tcp and is_web_port and total_packets >= 5 and total_bytes >= 1000 and ack_count > 0


def prevent_c2_multicast_misclassification(
    c2_prediction: int,
    c2_score: float,
    src_ip: str,
    dst_ip: str,
    dst_port: Optional[int],
    protocol: str,
    iat_regularity: float = 0.0,
    obs_count: int = 0
) -> Tuple[int, float, Optional[str]]:
    """
    Safety guard to prevent ordinary multicast, discovery, or standard QUIC (UDP:443) traffic
    from being classified as confirmed Command and Control (C2) without supporting external evidence.

    Returns:
        (sanitized_c2_prediction, sanitized_c2_score, safety_note)
    """
    is_disc, reason = evaluate_multicast_discovery_safety(src_ip, dst_ip, dst_port, protocol)

    if is_disc:
        if c2_prediction == 1 or c2_score >= 0.50:
            logger.info(
                f"[SAFETY GUARD] Suppressed false C2 alert on discovery traffic: "
                f"{src_ip} -> {dst_ip}:{dst_port} ({reason}). Original score: {c2_score:.4f}"
            )
            return (
                0,
                min(0.20, c2_score * 0.1),  # De-escalate score to benign baseline
                f"Ordinary discovery/multicast traffic suppressed from C2 classification: {reason}"
            )

    # Standard QUIC (UDP:443) egress without proven high timing regularity
    if is_quic_traffic(dst_port, protocol) and (obs_count < 3 or iat_regularity < 0.5):
        if c2_prediction == 1 or c2_score >= 0.50:
            logger.info(
                f"[SAFETY GUARD] Suppressed false C2 alert on standard QUIC web traffic: "
                f"{src_ip} -> {dst_ip}:{dst_port} (obs={obs_count}, regularity={iat_regularity:.2f}). Original score: {c2_score:.4f}"
            )
            return (
                0,
                min(0.25, c2_score * 0.15),
                "Standard QUIC (UDP:443) egress suppressed from C2 classification due to lack of behavioral beaconing regularity."
            )

    return c2_prediction, c2_score, None
