# ============================================================
# CYBERFACEGUARD - NETWORK AUDIT ENGINE
# ============================================================
# Local / Read-Only Windows Network Assessment
# ============================================================

import csv
import ipaddress
import json
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


class NetworkAudit:

    KNOWN_PORTS = {
        "53": "DNS",
        "80": "HTTP",
        "135": "Windows RPC",
        "139": "NetBIOS",
        "443": "HTTPS",
        "445": "SMB",
        "3389": "Remote Desktop",
        "5353": "mDNS",
        "5900": "VNC",
    }

    SENSITIVE_PORTS = {
        "21": "FTP",
        "23": "Telnet",
        "135": "Windows RPC",
        "139": "NetBIOS",
        "445": "SMB",
        "3389": "Remote Desktop",
        "5900": "VNC",
    }

    WILDCARD_ADDRESSES = ("0.0.0.0", "::", "*")
    LOOPBACK_ADDRESSES = ("127.0.0.1", "::1")

    # Language-independent TCP state names -> classic netstat names
    STATE_MAP = {
        "listen": "LISTENING",
        "established": "ESTABLISHED",
        "timewait": "TIME_WAIT",
        "closewait": "CLOSE_WAIT",
        "finwait1": "FIN_WAIT_1",
        "finwait2": "FIN_WAIT_2",
        "synsent": "SYN_SENT",
        "synreceived": "SYN_RECEIVED",
        "lastack": "LAST_ACK",
        "closing": "CLOSING",
        "closed": "CLOSED",
        "deletetcb": "DELETE_TCB",
        "bound": "BOUND",
    }

    def __init__(self):
        pass

    # ========================================================
    # HIDDEN PROCESS HELPERS (no console window)
    # ========================================================

    @staticmethod
    def _hidden_flags():
        startupinfo = None
        creationflags = 0

        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW

        return startupinfo, creationflags

    def run_hidden(self, command, timeout=15, encoding="oem"):
        """Run a command with no visible window. Returns stdout or ''."""
        startupinfo, creationflags = self._hidden_flags()

        if sys.platform != "win32":
            encoding = "utf-8"

        try:
            result = subprocess.run(
                command,
                shell=False,
                capture_output=True,
                text=True,
                encoding=encoding,
                errors="replace",
                stdin=subprocess.DEVNULL,
                startupinfo=startupinfo,
                creationflags=creationflags,
                timeout=timeout,
                check=False,
            )
            return result.stdout or ""

        except (OSError, subprocess.SubprocessError, LookupError):
            return ""

    def run_powershell(self, command, timeout=30):
        """Run a PowerShell script hidden (plain -Command, UTF-8 output)."""
        script = (
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
            "$ProgressPreference = 'SilentlyContinue'\n"
            + command
        )

        output = self.run_hidden(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command", script,
            ],
            timeout=timeout,
            encoding="utf-8",
        )

        return output.strip()

    # ========================================================
    # IP HELPERS
    # ========================================================

    def is_valid_ipv4(self, value):
        if not value:
            return False

        try:
            ipaddress.IPv4Address(str(value).strip())
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _split_host_port(value):
        """Split '1.2.3.4:80' / '[::1]:80' into (host, port)."""
        value = str(value or "").strip()

        if value.startswith("[") and "]" in value:
            closing = value.rfind("]")
            return value[1:closing], value[closing + 2:]

        if value.count(":") == 1:
            host, port = value.rsplit(":", 1)
            return host, port

        # Bare IPv6 or bare host
        return value, ""

    def is_private_ip(self, ip):
        if not ip:
            return False

        value, _ = self._split_host_port(ip)
        value = value.split("%", 1)[0]  # strip IPv6 zone id (fe80::1%12)

        try:
            parsed = ipaddress.ip_address(value)
            return (
                parsed.is_private
                or parsed.is_loopback
                or parsed.is_link_local
            )
        except ValueError:
            return False

    @staticmethod
    def _format_endpoint(address, port):
        address = str(address)
        if ":" in address:
            return f"[{address}]:{port}"
        return f"{address}:{port}"

    # ========================================================
    # NETWORK INFORMATION (single PowerShell call)
    # ========================================================

    def get_network_info(self):
        result = {
            "hostname": socket.gethostname(),
            "local_ip": "Unknown",
            "gateway": "Unknown",
            "dns": [],
            "adapters": [],
        }

        output = self.run_powershell(
            r"""
            try {
                $route = Get-NetRoute -AddressFamily IPv4 `
                        -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                    Where-Object { $_.NextHop -ne '0.0.0.0' } |
                    Sort-Object { $_.RouteMetric + $_.InterfaceMetric } |
                    Select-Object -First 1

                $gateway = $null
                $ip = $null

                if ($route) {
                    $gateway = [string]$route.NextHop

                    $obj = Get-NetIPAddress -AddressFamily IPv4 `
                            -InterfaceIndex $route.InterfaceIndex `
                            -ErrorAction SilentlyContinue |
                        Where-Object { $_.IPAddress -notlike '169.254.*' } |
                        Select-Object -First 1

                    if ($obj) { $ip = [string]$obj.IPAddress }
                }

                if (-not $ip) {
                    $obj = Get-NetIPAddress -AddressFamily IPv4 `
                            -ErrorAction SilentlyContinue |
                        Where-Object {
                            $_.IPAddress -ne '127.0.0.1' -and
                            $_.IPAddress -notlike '169.254.*'
                        } |
                        Select-Object -First 1

                    if ($obj) { $ip = [string]$obj.IPAddress }
                }

                $dns = @(
                    Get-DnsClientServerAddress -AddressFamily IPv4 `
                        -ErrorAction SilentlyContinue |
                    ForEach-Object { $_.ServerAddresses } |
                    Where-Object { $_ } |
                    Select-Object -Unique
                )

                $adapters = @(
                    Get-NetAdapter -ErrorAction SilentlyContinue |
                    Where-Object { $_.Status -eq 'Up' } |
                    ForEach-Object {
                        [ordered]@{
                            Name        = [string]$_.Name
                            Description = [string]$_.InterfaceDescription
                            LinkSpeed   = [string]$_.LinkSpeed
                            Mac         = [string]$_.MacAddress
                        }
                    }
                )

                [ordered]@{
                    Gateway  = $gateway
                    LocalIP  = $ip
                    DNS      = $dns
                    Adapters = $adapters
                } | ConvertTo-Json -Compress -Depth 4
            }
            catch {
                Write-Output "ERROR: $($_.Exception.Message)"
            }
            """
        )

        if output and not output.startswith("ERROR:"):
            try:
                data = json.loads(output)

                gateway = data.get("Gateway")
                if self.is_valid_ipv4(gateway):
                    result["gateway"] = str(gateway).strip()

                local_ip = data.get("LocalIP")
                if self.is_valid_ipv4(local_ip):
                    result["local_ip"] = str(local_ip).strip()

                dns_list = data.get("DNS") or []
                if isinstance(dns_list, str):
                    dns_list = [dns_list]

                result["dns"] = list(dict.fromkeys(
                    str(d).strip() for d in dns_list
                    if self.is_valid_ipv4(d)
                ))

                adapters = data.get("Adapters") or []
                if isinstance(adapters, dict):
                    adapters = [adapters]

                # One readable line per adapter (shown in a 1-column table)
                result["adapters"] = [
                    f"{a.get('Name', 'Unknown')} - "
                    f"{a.get('Description', 'Unknown')} | "
                    f"{a.get('LinkSpeed', 'Unknown')} | "
                    f"{a.get('Mac', 'Unknown')}"
                    for a in adapters
                ]

            except (json.JSONDecodeError, TypeError, AttributeError):
                pass

        # Fallbacks for the local IP
        if result["local_ip"] == "Unknown":
            result["local_ip"] = self._fallback_local_ip()

        return result

    def _fallback_local_ip(self):
        # Route lookup only; UDP connect sends no packet.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("10.255.255.255", 1))
                ip = sock.getsockname()[0]
                if self.is_valid_ipv4(ip) and not ip.startswith(("127.", "169.254.")):
                    return ip
        except OSError:
            pass

        try:
            for entry in socket.getaddrinfo(
                socket.gethostname(), None, socket.AF_INET
            ):
                ip = entry[4][0]
                if (
                    self.is_valid_ipv4(ip)
                    and not ip.startswith(("127.", "169.254."))
                ):
                    return ip
        except OSError:
            pass

        return "Unknown"

    # ========================================================
    # INTERNET CONNECTIVITY
    # ========================================================

    def check_internet(self):
        # Real TCP reachability (not only DNS), with a short timeout.
        for host, name in (
            ("1.1.1.1", "Cloudflare"),
            ("8.8.8.8", "Google DNS"),
            ("9.9.9.9", "Quad9"),
        ):
            try:
                with socket.create_connection((host, 443), timeout=3):
                    return {
                        "online": True,
                        "status": "ONLINE",
                        "target": f"{name} ({host})",
                    }
            except OSError:
                continue

        return {
            "online": False,
            "status": "OFFLINE",
            "target": "None",
        }

    # ========================================================
    # TCP TABLE (language independent)
    # ========================================================

    def get_tcp_table(self):
        """Return every TCP endpoint as normalized dictionaries."""
        rows = self._tcp_table_powershell()

        if rows is None:
            rows = self._tcp_table_netstat()

        return rows

    def _tcp_table_powershell(self):
        output = self.run_powershell(
            r"""
            try {
                $names = @{}
                Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
                    $names[[int]$_.Id] = $_.ProcessName
                }

                $rows = @(
                    Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
                        $procId = [int]$_.OwningProcess
                        $name = 'Unknown'
                        if ($names.ContainsKey($procId)) { $name = $names[$procId] }

                        [ordered]@{
                            LocalAddress  = [string]$_.LocalAddress
                            LocalPort     = [int]$_.LocalPort
                            RemoteAddress = [string]$_.RemoteAddress
                            RemotePort    = [int]$_.RemotePort
                            State         = [string]$_.State
                            PID           = $procId
                            Process       = $name
                        }
                    }
                )

                ConvertTo-Json -InputObject $rows -Compress -Depth 4
            }
            catch {
                Write-Output "ERROR: $($_.Exception.Message)"
            }
            """,
            timeout=45,
        )

        if not output or output.startswith("ERROR:"):
            return None

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return None

        if isinstance(data, dict):
            data = [data]

        rows = []

        for item in data:
            state_raw = str(item.get("State", "")).strip()
            state = self.STATE_MAP.get(state_raw.lower(), state_raw.upper())

            rows.append({
                "local_address": str(item.get("LocalAddress", "")),
                "local_port": str(item.get("LocalPort", "")),
                "remote_address": str(item.get("RemoteAddress", "")),
                "remote_port": str(item.get("RemotePort", "")),
                "state": state,
                "pid": str(item.get("PID", "")),
                "process": str(item.get("Process", "Unknown")) or "Unknown",
            })

        return rows

    def _tcp_table_netstat(self):
        """Fallback if PowerShell is unavailable.

        netstat state names are localized, so listening sockets are
        recognised by their wildcard remote address instead.
        """
        process_map = self._process_map()
        rows = []

        output = self.run_hidden(["netstat", "-ano"], timeout=20)

        for line in output.splitlines():
            parts = re.split(r"\s+", line.strip())

            if len(parts) < 4 or parts[0].upper() != "TCP":
                continue

            local, remote = parts[1], parts[2]
            pid = parts[-1]
            state = parts[3].upper() if len(parts) >= 5 else ""

            if remote in ("0.0.0.0:0", "[::]:0", "*:*"):
                state = "LISTENING"

            local_host, local_port = self._split_host_port(local)
            remote_host, remote_port = self._split_host_port(remote)

            rows.append({
                "local_address": local_host,
                "local_port": local_port,
                "remote_address": remote_host,
                "remote_port": remote_port,
                "state": state,
                "pid": pid,
                "process": process_map.get(pid, "Unknown"),
            })

        return rows

    def _process_map(self):
        process_map = {}

        output = self.run_hidden(["tasklist", "/FO", "CSV", "/NH"], timeout=20)

        for line in output.splitlines():
            try:
                fields = next(csv.reader([line]))
            except (csv.Error, StopIteration):
                continue

            if len(fields) >= 2 and fields[1].isdigit():
                process_map[fields[1]] = fields[0]

        return process_map

    # ========================================================
    # ACTIVE TCP CONNECTIONS
    # ========================================================

    def get_active_connections(self, table=None):
        if table is None:
            table = self.get_tcp_table()

        connections = []

        for row in table:
            if row["state"] == "LISTENING":
                continue  # shown in the Listening Ports tab

            connections.append({
                "protocol": "TCP",
                "local": self._format_endpoint(row["local_address"], row["local_port"]),
                "remote": self._format_endpoint(row["remote_address"], row["remote_port"]),
                "remote_address": row["remote_address"],
                "remote_port": row["remote_port"],
                "state": row["state"],
                "pid": row["pid"],
                "process": row["process"],
            })

        return connections

    # ========================================================
    # LISTENING TCP PORTS
    # ========================================================

    def get_listening_ports(self, table=None):
        if table is None:
            table = self.get_tcp_table()

        ports = []
        seen = set()

        for row in table:
            if row["state"] != "LISTENING":
                continue

            key = (row["local_address"], row["local_port"], row["pid"])
            if key in seen:
                continue
            seen.add(key)

            ports.append({
                "address": row["local_address"],
                "port": row["local_port"],
                "pid": row["pid"],
                "process": row["process"],
            })

        ports.sort(key=lambda p: int(p["port"]) if str(p["port"]).isdigit() else 0)

        return ports

    # ========================================================
    # CONNECTION ANALYSIS
    # ========================================================

    def analyze_connections(self, connections):
        analyzed = []

        for connection in connections:
            item = dict(connection)

            remote = str(item.get("remote", ""))
            state = str(item.get("state", "")).upper()

            remote_host = item.get("remote_address")
            remote_port = str(item.get("remote_port", ""))

            if not remote_host:
                remote_host, remote_port = self._split_host_port(remote)

            analysis = "NORMAL"
            reason = "Active TCP connection."

            is_private = self.is_private_ip(remote_host)

            if state == "TIME_WAIT":
                analysis = "INFO"
                reason = "Connection recently closed."

            elif state == "CLOSE_WAIT":
                analysis = "INFO"
                reason = "Remote side closed; check if it persists."

            elif is_private:
                analysis = "LOCAL"
                reason = "Private or loopback network destination."

            elif (
                remote_port in self.SENSITIVE_PORTS
                and state in ("ESTABLISHED", "SYN_SENT")
            ):
                analysis = "WARNING"
                reason = (
                    f"Connection to a public host on "
                    f"{self.SENSITIVE_PORTS[remote_port]} (port {remote_port}); "
                    "verify this is expected."
                )

            item["analysis"] = analysis
            item["reason"] = reason
            analyzed.append(item)

        return analyzed

    # ========================================================
    # LISTENING PORT ANALYSIS
    # ========================================================

    def analyze_listening_ports(self, ports):
        analyzed = []

        for port_info in ports:
            item = dict(port_info)

            port = str(item.get("port", "")).strip()
            process = str(
                item.get("process", item.get("process_name", "Unknown"))
            ).strip()

            address = str(item.get("address", "")).strip()
            normalized = address.strip("[]").lower().split("%", 1)[0]

            analysis = "INFO"
            reason = "Listening service detected; verify if expected."
            if normalized in self.LOOPBACK_ADDRESSES:
                analysis = "LOCAL"
                reason = "Bound to loopback; normally accessible only locally."

            elif port in self.SENSITIVE_PORTS:
                where = (
                    "all interfaces"
                    if normalized in self.WILDCARD_ADDRESSES
                    else address
                )

                # A listening socket alone does not prove network exposure.
                analysis = "INFO"
                reason = (
                    f"{self.SENSITIVE_PORTS[port]} is listening on {where}. "
                    "Network exposure has not been verified; inspect the "
                    "effective Windows Firewall rules and network profile."
                )

            elif process.lower() == "unknown":
                analysis = "WARNING"
                reason = "Process could not be identified; verify the PID."

            elif normalized in self.WILDCARD_ADDRESSES:
                service = self.KNOWN_PORTS.get(port, "Unclassified service")
                reason = (
                    f"{service} listens on all interfaces; "
                    "confirm that this is expected."
                )

            elif port in self.KNOWN_PORTS:
                reason = f"Recognized service: {self.KNOWN_PORTS[port]}."

            item["analysis"] = analysis
            item["reason"] = reason
            analyzed.append(item)

        return analyzed

    # ========================================================
    # NETWORK STATUS
    # ========================================================

    def get_network_status(self, network, internet):
        adapters = network.get("adapters", [])
        local_ip = network.get("local_ip", "Unknown")
        gateway = network.get("gateway", "Unknown")

        if not adapters:
            return {
                "status": "OFFLINE",
                "level": "HIGH",
                "message": "No active network adapter detected.",
            }

        if local_ip == "Unknown" or gateway == "Unknown":
            return {
                "status": "LIMITED",
                "level": "MEDIUM",
                "message": "Network identity is incomplete.",
            }

        if not internet.get("online", False):
            return {
                "status": "LOCAL ONLY",
                "level": "MEDIUM",
                "message": "Local network available; internet unavailable.",
            }

        return {
            "status": "ONLINE",
            "level": "LOW",
            "message": "Network connection is operational.",
        }

    # ========================================================
    # RISK SCORE
    # ========================================================

    def calculate_risk_score(self, connections, listening_ports):
        items = list(connections) + list(listening_ports)

        warnings = sum(item.get("analysis") == "WARNING" for item in items)
        info = sum(item.get("analysis") == "INFO" for item in items)
        local = sum(item.get("analysis") == "LOCAL" for item in items)

        score = max(
            0,
            min(100, 100 - warnings * 10 - min(info, 5) - min(local, 3))
        )

        if score >= 80:
            level = "LOW"
        elif score >= 60:
            level = "MEDIUM"
        else:
            level = "HIGH"

        return {
            "score": score,
            "level": level,
            "warnings": int(warnings),
            "info": int(info),
            "local": int(local),
        }

    # ========================================================
    # FULL AUDIT
    # ========================================================

    def run_full_audit(self):
        started = datetime.now()

        def safe(func, default):
            try:
                return func()
            except Exception:
                return default

        # The three slow tasks run in parallel.
        with ThreadPoolExecutor(max_workers=3) as pool:
            network_future = pool.submit(
                safe, self.get_network_info,
                {
                    "hostname": socket.gethostname(),
                    "local_ip": "Unknown",
                    "gateway": "Unknown",
                    "dns": [],
                    "adapters": [],
                },
            )
            internet_future = pool.submit(
                safe, self.check_internet,
                {"online": False, "status": "OFFLINE", "target": "None"},
            )
            table_future = pool.submit(safe, self.get_tcp_table, [])

            network = network_future.result()
            internet = internet_future.result()
            table = table_future.result()

        connections = self.analyze_connections(
            self.get_active_connections(table)
        )

        listening_ports = self.analyze_listening_ports(
            self.get_listening_ports(table)
        )

        risk = self.calculate_risk_score(connections, listening_ports)

        network_status = self.get_network_status(network, internet)

        summary = {
            "adapters": len(network.get("adapters", [])),
            "active_connections": len(connections),
            "listening_ports": len(listening_ports),
            "dns_servers": len(network.get("dns", [])),
            "warnings": risk["warnings"],
            "info": risk["info"],
            "local": risk["local"],
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "internet_online": internet["online"],
        }

        return {
            "timestamp": started.isoformat(),
            "network": network,
            "internet": internet,
            "network_status": network_status,
            "connections": connections,
            "listening_ports": listening_ports,
            "risk": risk,
            "summary": summary,
        }


if __name__ == "__main__":
    import pprint

    pprint.pp(NetworkAudit().run_full_audit())