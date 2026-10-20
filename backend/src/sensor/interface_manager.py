"""
NETRA Local Windows Sensor - Interface Discovery & Selection Module
Provides robust network interface discovery, detailed inspection, and explicit selection
for Windows Npcap/Scapy packet capture.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

import scapy.all as scapy
import psutil

logger = logging.getLogger(__name__)


class InterfaceNotFoundError(ValueError):
    """Raised when a requested network interface is not found or unavailable."""
    pass


@dataclass
class NetworkInterfaceDetails:
    """Detailed metadata for a host network interface."""
    name: str
    description: str
    guid: Optional[str] = None
    device_name: Optional[str] = None
    scapy_name: Optional[str] = None
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    mac_address: Optional[str] = None
    is_active: bool = False
    is_wireless: bool = False
    is_loopback: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert interface details to serializable dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "guid": self.guid,
            "device_name": self.device_name,
            "scapy_name": self.scapy_name,
            "ips": self.ipv4_addresses + self.ipv6_addresses,
            "ipv4": self.ipv4_addresses,
            "ipv6": self.ipv6_addresses,
            "mac": self.mac_address,
            "is_active": self.is_active,
            "is_wireless": self.is_wireless,
            "is_loopback": self.is_loopback
        }


class InterfaceManager:
    """
    Manages discovery, resolution, and validation of Windows network adapters.
    """

    @classmethod
    def list_interfaces(cls, active_only: bool = False) -> List[NetworkInterfaceDetails]:
        """
        Discovers and deduplicates network interfaces on Windows.
        Filters out NDIS sub-driver bindings (e.g. QoS Packet Scheduler, WFP filters)
        to present a clean list of physical and virtual adapters.
        """
        discovered: Dict[str, NetworkInterfaceDetails] = {}

        # 1. Query psutil for interface IP addresses and MACs
        psutil_addrs = {}
        try:
            for iface_name, addrs in psutil.net_if_addrs().items():
                v4 = [a.address for a in addrs if a.family.name == "AF_INET"]
                v6 = [a.address for a in addrs if a.family.name == "AF_INET6"]
                mac = next((a.address for a in addrs if getattr(a.family, "name", "") in ("AF_LINK", "AF_PACKET") or a.family == -1), None)
                psutil_addrs[iface_name] = {"v4": v4, "v6": v6, "mac": mac}
        except Exception as e:
            logger.debug(f"psutil net_if_addrs error: {e}")

        # 2. Query Windows interfaces via Scapy Windows architecture
        try:
            from scapy.arch.windows import get_windows_if_list
            win_ifaces = get_windows_if_list()
        except Exception as e:
            logger.warning(f"Failed to query get_windows_if_list(): {e}")
            win_ifaces = []

        # Filter out sub-driver filter bindings (e.g., "-QoS Packet Scheduler", "-Npcap Packet Driver")
        for item in win_ifaces:
            name = item.get("name", "")
            desc = item.get("description", "")
            guid = item.get("guid")

            if not name:
                continue

            # Skip auxiliary sub-filter items
            if "-" in name and any(filter_tag in name for filter_tag in [
                "Filter", "Packet Scheduler", "Driver", "LightWeight", "Virtual WiFi"
            ]):
                continue

            ips = item.get("ips", [])
            v4 = [ip for ip in ips if ":" not in ip]
            v6 = [ip for ip in ips if ":" in ip]

            # Merge with psutil addresses if available
            if name in psutil_addrs:
                p_info = psutil_addrs[name]
                for ip in p_info["v4"]:
                    if ip not in v4:
                        v4.append(ip)
                for ip in p_info["v6"]:
                    if ip not in v6:
                        v6.append(ip)
                mac = p_info.get("mac")
            else:
                mac = item.get("mac")

            # Check if active (has a routable private or public IP)
            is_active = any(
                ip.startswith("192.168.") or ip.startswith("10.") or (ip.startswith("172.") and not ip.startswith("169.254"))
                for ip in v4
            )
            is_wireless = "Wi-Fi" in name or "Wireless" in desc or "802.11" in desc
            is_loopback = "Loopback" in name or "127.0.0.1" in v4

            device_name = f"\\Device\\NPF_{guid}" if guid else None

            # Check Scapy device name
            scapy_name = name
            try:
                scapy_dev = scapy.conf.ifaces.dev_from_name(name)
                if scapy_dev:
                    scapy_name = getattr(scapy_dev, "name", name)
                    if not device_name:
                        device_name = getattr(scapy_dev, "network_name", None)
            except Exception:
                pass

            details = NetworkInterfaceDetails(
                name=name,
                description=desc,
                guid=guid,
                device_name=device_name,
                scapy_name=scapy_name,
                ipv4_addresses=v4,
                ipv6_addresses=v6,
                mac_address=mac,
                is_active=is_active,
                is_wireless=is_wireless,
                is_loopback=is_loopback
            )

            discovered[name] = details

        # 3. Also include Scapy conf.ifaces items not already caught
        try:
            for iface_key, iface_obj in scapy.conf.ifaces.items():
                name = getattr(iface_obj, "name", str(iface_key))
                desc = getattr(iface_obj, "description", name)
                if name not in discovered and not any(name in d for d in discovered):
                    ips = []
                    v4_val = getattr(iface_obj, "ip", None)
                    if v4_val and str(v4_val) != "0.0.0.0":
                        ips.append(str(v4_val))
                    is_active = any(ip.startswith("192.168.") or ip.startswith("10.") for ip in ips)
                    details = NetworkInterfaceDetails(
                        name=name,
                        description=desc,
                        guid=getattr(iface_obj, "guid", None),
                        device_name=getattr(iface_obj, "network_name", name),
                        scapy_name=name,
                        ipv4_addresses=ips,
                        ipv6_addresses=[],
                        mac_address=getattr(iface_obj, "mac", None),
                        is_active=is_active,
                        is_wireless="Wi-Fi" in name or "Wireless" in desc,
                        is_loopback="Loopback" in name or "127.0.0.1" in ips
                    )
                    discovered[name] = details
        except Exception as e:
            logger.debug(f"Error checking scapy.conf.ifaces: {e}")

        all_interfaces = list(discovered.values())

        # Sort: active first, then wireless, then alphabetical
        all_interfaces.sort(key=lambda i: (not i.is_active, not i.is_wireless, i.name))

        if active_only:
            return [i for i in all_interfaces if i.is_active]

        return all_interfaces

    @classmethod
    def get_interface(cls, name_or_guid: str) -> Optional[NetworkInterfaceDetails]:
        """
        Finds an interface matching friendly name, description, GUID, or device name.
        Case-insensitive.
        """
        if not name_or_guid:
            return None

        query = name_or_guid.strip().lower()
        interfaces = cls.list_interfaces(active_only=False)

        # 1. Exact match on name
        for iface in interfaces:
            if iface.name.lower() == query:
                return iface

        # 2. Exact match on GUID
        for iface in interfaces:
            if iface.guid and iface.guid.lower().strip("{}") == query.strip("{}"):
                return iface

        # 3. Match device_name
        for iface in interfaces:
            if iface.device_name and iface.device_name.lower() == query:
                return iface

        # 4. Partial substring in description or name
        for iface in interfaces:
            if query in iface.name.lower() or query in iface.description.lower():
                return iface

        return None

    @classmethod
    def validate_interface(cls, requested_name: str) -> NetworkInterfaceDetails:
        """
        Validates that a requested interface exists and can be resolved.
        Raises InterfaceNotFoundError with clear diagnostic details if not found.
        """
        iface = cls.get_interface(requested_name)
        if iface is None:
            available = [i.name for i in cls.list_interfaces(active_only=False)]
            active = [i.name for i in cls.list_interfaces(active_only=True)]
            raise InterfaceNotFoundError(
                f"Network interface '{requested_name}' was not found on this Windows host.\n"
                f"Active adapters with IP: {active}\n"
                f"All available adapters: {available}"
            )
        return iface

    @classmethod
    def resolve_interface(cls, requested_name: Optional[str] = None, auto_fallback: bool = True) -> str:
        """
        Resolves the interface identifier to use for Scapy sniffing.

        Args:
            requested_name: User-requested interface name (e.g. 'Wi-Fi 2', 'Wi-Fi 3').
            auto_fallback: If True, falls back to active adapter when requested interface is None.
                           If False, raises InterfaceNotFoundError if requested_name is not found.

        Returns:
            Interface name recognized by Scapy sniffing.
        """
        if requested_name:
            iface = cls.get_interface(requested_name)
            if iface:
                logger.info(f"Explicitly selected network interface: '{iface.name}' ({iface.description})")
                return iface.name

            if not auto_fallback:
                available = [i.name for i in cls.list_interfaces(active_only=False)]
                raise InterfaceNotFoundError(
                    f"Requested interface '{requested_name}' was not found on this host.\n"
                    f"Available interfaces: {available}"
                )

            logger.warning(
                f"Requested interface '{requested_name}' not found. Falling back to active adapter..."
            )

        # Auto-selection: prefer active Wi-Fi, then any active adapter with IP
        active_ifaces = cls.list_interfaces(active_only=True)

        # 1. Active Wi-Fi
        for i in active_ifaces:
            if i.is_wireless and not i.is_loopback:
                logger.info(f"Auto-selected active wireless interface: '{i.name}' ({i.ipv4_addresses})")
                return i.name

        # 2. Any active interface with IPv4
        for i in active_ifaces:
            if not i.is_loopback:
                logger.info(f"Auto-selected active interface: '{i.name}' ({i.ipv4_addresses})")
                return i.name

        # 3. Fallback to Wi-Fi 2 or first discovered
        all_ifaces = cls.list_interfaces(active_only=False)
        for i in all_ifaces:
            if i.name in ("Wi-Fi 2", "Wi-Fi 3", "Wi-Fi"):
                logger.info(f"Defaulting to Wi-Fi adapter: '{i.name}'")
                return i.name

        if all_ifaces:
            return all_ifaces[0].name

        return "Wi-Fi 2"
