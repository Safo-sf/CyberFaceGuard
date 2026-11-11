import json
import platform
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor


# Ports that are commonly risky when reachable from the network.
RISKY_PORTS = {
    21: "FTP",
    23: "Telnet",
    135: "RPC Endpoint Mapper",
    139: "NetBIOS",
    445: "SMB",
    1433: "SQL Server",
    3306: "MySQL",
    3389: "Remote Desktop (RDP)",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
}

LOOPBACK = ("127.0.0.1", "::1")


class SecurityAudit:

    PS_TIMEOUT = 60

    # =========================================================
    # POWERSHELL (hidden window, safe quoting, UTF-8 output)
    # =========================================================

    def run_powershell(self, command):
        """Run a PowerShell script without showing any window.

        Plain -Command (no -EncodedCommand / -ExecutionPolicy Bypass /
        -WindowStyle Hidden) so antivirus heuristics are not triggered.
        Returns stdout (stripped), or a string starting with 'ERROR:'.
        """
        startupinfo = None
        creationflags = 0

        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW

        # Force UTF-8 output so accents / unicode paths are not garbled.
        script = (
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
            "$ProgressPreference = 'SilentlyContinue'\n"
            + command
        )

        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command", script,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdin=subprocess.DEVNULL,
                startupinfo=startupinfo,
                creationflags=creationflags,
                timeout=self.PS_TIMEOUT,
            )

            output = (result.stdout or "").strip()

            if not output and result.returncode != 0:
                error = (result.stderr or "").strip() or f"exit code {result.returncode}"
                return f"ERROR: {error}"

            return output

        except subprocess.TimeoutExpired:
            return "ERROR: PowerShell command timed out."

        except Exception as e:
            return f"ERROR: {e}"

    @staticmethod
    def _unavailable(output):
        return not output or output.startswith("ERROR:")

    @staticmethod
    def _as_list(data):
        if data is None:
            return []
        if isinstance(data, dict):
            return [data]
        return list(data)

    # =========================================================
    # SYSTEM
    # =========================================================

    def check_system(self):
        try:
            system = platform.system()
            release = platform.release()
            machine = platform.machine()

            return {
                "status": "INFO",
                "message": f"{system} {release} ({machine})",
                "os": system,
                "release": release,
                "version": platform.version(),
                "architecture": machine,
                "hostname": platform.node(),
            }

        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    # =========================================================
    # MICROSOFT DEFENDER
    # =========================================================

    def check_defender(self):
        command = r"""
        $av = @()
        try {
            $av = @(
                Get-CimInstance -Namespace root/SecurityCenter2 `
                    -ClassName AntiVirusProduct -ErrorAction Stop |
                ForEach-Object { $_.displayName }
            )
        } catch { }

        try {
            $d = Get-MpComputerStatus -ErrorAction Stop

            [ordered]@{
                AntivirusEnabled          = [bool]$d.AntivirusEnabled
                AntispywareEnabled        = [bool]$d.AntispywareEnabled
                RealTimeProtectionEnabled = [bool]$d.RealTimeProtectionEnabled
                BehaviorMonitorEnabled    = [bool]$d.BehaviorMonitorEnabled
                IoavProtectionEnabled     = [bool]$d.IoavProtectionEnabled
                NISEnabled                = [bool]$d.NISEnabled
                QuickScanAge              = $d.QuickScanAge
                FullScanAge               = $d.FullScanAge
                ThirdPartyAV              = $av
            } | ConvertTo-Json -Compress -Depth 4
        }
        catch {
            [ordered]@{
                Error        = $_.Exception.Message
                ThirdPartyAV = $av
            } | ConvertTo-Json -Compress -Depth 4
        }
        """

        output = self.run_powershell(command)

        if self._unavailable(output):
            return {
                "status": "INFO",
                "message": "Microsoft Defender status unavailable.",
                "details": {}
            }

        try:
            data = json.loads(output)

            av_products = self._as_list(data.get("ThirdPartyAV"))
            others = [a for a in av_products if "defender" not in str(a).lower()]

            if "Error" in data:
                if others:
                    return {
                        "status": "INFO",
                        "message": "Third-party antivirus detected: " + ", ".join(others),
                        "details": {"antivirus_products": av_products}
                    }
                return {
                    "status": "INFO",
                    "message": "Microsoft Defender status unavailable.",
                    "details": {"error": data.get("Error")}
                }

            protections = [
                data.get("AntivirusEnabled", False),
                data.get("AntispywareEnabled", False),
                data.get("RealTimeProtectionEnabled", False),
                data.get("BehaviorMonitorEnabled", False),
                data.get("IoavProtectionEnabled", False),
                data.get("NISEnabled", False),
            ]

            if all(protections):
                status = "PASS"
                message = "Microsoft Defender is enabled with real-time protection."

            elif any(protections):
                status = "WARNING"
                message = "Microsoft Defender is enabled, but some protections are disabled."

            elif others:
                status = "INFO"
                message = "Third-party antivirus detected: " + ", ".join(others)

            else:
                status = "ERROR"
                message = "Microsoft Defender protections appear to be disabled."

            return {
                "status": status,
                "message": message,
                "details": {
                    "antivirus": data.get("AntivirusEnabled"),
                    "antispyware": data.get("AntispywareEnabled"),
                    "realtime": data.get("RealTimeProtectionEnabled"),
                    "behavior_monitor": data.get("BehaviorMonitorEnabled"),
                    "ioav": data.get("IoavProtectionEnabled"),
                    "network_inspection": data.get("NISEnabled"),
                    "quick_scan_age": data.get("QuickScanAge"),
                    "full_scan_age": data.get("FullScanAge"),
                    "antivirus_products": av_products,
                }
            }

        except Exception as e:
            return {
                "status": "INFO",
                "message": f"Unable to parse Defender status: {e}",
                "details": {}
            }

    # =========================================================
    # WINDOWS FIREWALL
    # =========================================================

    def check_firewall(self):
        command = r"""
        try {
            $profiles = @(
                Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
                    [ordered]@{
                        Name                  = [string]$_.Name
                        Enabled               = ([string]$_.Enabled -eq 'True')
                        DefaultInboundAction  = [string]$_.DefaultInboundAction
                        DefaultOutboundAction = [string]$_.DefaultOutboundAction
                    }
                }
            )
            ConvertTo-Json -InputObject $profiles -Compress -Depth 4
        }
        catch {
            Write-Output "ERROR: $($_.Exception.Message)"
        }
        """

        output = self.run_powershell(command)

        if self._unavailable(output):
            return {
                "status": "INFO",
                "message": "Windows Firewall status unavailable.",
                "profiles": []
            }

        try:
            data = self._as_list(json.loads(output))

            profiles = [
                {
                    "name": item.get("Name", "Unknown"),
                    "enabled": bool(item.get("Enabled")),
                    "inbound": str(item.get("DefaultInboundAction", "")),
                    "outbound": str(item.get("DefaultOutboundAction", "")),
                }
                for item in data
            ]

            if not profiles:
                return {
                    "status": "INFO",
                    "message": "No Windows Firewall profiles detected.",
                    "profiles": []
                }

            disabled = [p for p in profiles if not p["enabled"]]

            if not disabled:
                status = "PASS"
                message = "All Windows Firewall profiles are enabled."
            else:
                status = "WARNING"
                message = "Firewall profile(s) disabled: " + ", ".join(
                    p["name"] for p in disabled
                )

            return {"status": status, "message": message, "profiles": profiles}

        except Exception as e:
            return {
                "status": "INFO",
                "message": f"Unable to parse firewall status: {e}",
                "profiles": []
            }

    # =========================================================
    # WINDOWS UPDATE
    # =========================================================

    def check_windows_update(self):
        command = r"""
        try {
            $service = Get-Service -Name wuauserv -ErrorAction Stop

            $kb = $null
            $date = $null
            $days = $null

            try {
                $latest = Get-HotFix -ErrorAction Stop |
                    Where-Object { $_.InstalledOn } |
                    Sort-Object InstalledOn -Descending |
                    Select-Object -First 1

                if ($latest) {
                    $kb = [string]$latest.HotFixID
                    $date = $latest.InstalledOn.ToString('yyyy-MM-dd')
                    $days = [int]((Get-Date) - $latest.InstalledOn).TotalDays
                }
            } catch { }

            [ordered]@{
                Service   = [string]$service.Status
                StartType = [string]$service.StartType
                KB        = $kb
                Date      = $date
                DaysAgo   = $days
            } | ConvertTo-Json -Compress
        }
        catch {
            Write-Output "ERROR: $($_.Exception.Message)"
        }
        """

        output = self.run_powershell(command)

        if self._unavailable(output):
            return {
                "status": "INFO",
                "message": "Windows Update status unavailable.",
                "service": "Unknown",
                "latest_update": None
            }

        try:
            data = json.loads(output)

            service = str(data.get("Service", "Unknown"))
            start_type = str(data.get("StartType", "Unknown"))
            kb = data.get("KB")
            days = data.get("DaysAgo")

            latest = None
            if kb:
                latest = {
                    "kb": kb,
                    "installed_on": data.get("Date"),
                    "days_ago": days,
                }

            # wuauserv is trigger-start: "Stopped" is normal.
            if start_type.lower() == "disabled":
                status = "WARNING"
                message = "Windows Update service is disabled."

            elif isinstance(days, int) and days > 90:
                status = "WARNING"
                message = (
                    f"Last installed update ({kb}) is {days} days old. "
                    "Check for updates."
                )

            elif kb:
                status = "PASS"
                message = (
                    f"Windows Update is available. Latest installed update: "
                    f"{kb} ({data.get('Date')})."
                )

            else:
                status = "PASS"
                message = "Windows Update service is available."

            return {
                "status": status,
                "message": message,
                "service": service,
                "start_type": start_type,
                "latest_update": latest
            }

        except Exception as e:
            return {
                "status": "INFO",
                "message": f"Unable to parse Windows Update status: {e}",
                "service": "Unknown",
                "latest_update": None
            }

    # =========================================================
    # LISTENING PORTS
    # =========================================================

    @staticmethod
    def _analyze_port(address, port):
        """Return (analysis, reason) for one listening endpoint."""
        address = str(address)

        try:
            port_number = int(port)
        except (TypeError, ValueError):
            port_number = None

        if address in LOOPBACK:
            return "LOCAL", "Only reachable from this computer."

        if port_number in RISKY_PORTS:
            service = RISKY_PORTS[port_number]
            return (
                "WARNING",
                f"{service} is listening on a network interface. "
                "Disable it if not needed or restrict it with the firewall."
            )

        return "INFO", "Listening on a network interface. Verify the process is expected."

    def check_listening_ports(self):
        command = r"""
        try {
            $connections = @(
                Get-NetTCPConnection -State Listen -ErrorAction Stop |
                Sort-Object LocalPort
            )

            $results = foreach ($connection in $connections) {
                $processId = $connection.OwningProcess
                $processName = "Unknown"
                $processPath = "Unavailable"

                try {
                    $process = Get-Process -Id $processId -ErrorAction Stop
                    $processName = $process.ProcessName

                    try {
                        if ($process.Path) { $processPath = $process.Path }
                    }
                    catch { }
                }
                catch { }

                [PSCustomObject]@{
                    LocalAddress  = [string]$connection.LocalAddress
                    LocalPort     = $connection.LocalPort
                    OwningProcess = $processId
                    ProcessName   = $processName
                    ProcessPath   = $processPath
                }
            }

            ConvertTo-Json -InputObject @($results) -Compress
        }
        catch {
            Write-Output "ERROR: $($_.Exception.Message)"
        }
        """

        output = self.run_powershell(command)

        if self._unavailable(output):
            return {
                "status": "INFO",
                "message": "Listening ports unavailable.",
                "ports": []
            }

        try:
            data = self._as_list(json.loads(output))

            ports = []

            for item in data:
                address = item.get("LocalAddress", "")
                port = item.get("LocalPort", "")
                name = item.get("ProcessName", "Unknown")
                analysis, reason = self._analyze_port(address, port)

                ports.append({
                    "address": address,
                    "port": port,
                    "pid": item.get("OwningProcess", ""),
                    "process": name,
                    "process_name": name,
                    "process_path": item.get("ProcessPath", "Unavailable"),
                    "analysis": analysis,
                    "reason": reason,
                })

            warnings = sum(1 for p in ports if p["analysis"] == "WARNING")

            return {
                "status": "INFO",
                "message": (
                    f"{len(ports)} listening TCP endpoint(s) detected"
                    + (f", {warnings} worth reviewing." if warnings else ".")
                ),
                "ports": ports
            }

        except Exception as e:
            return {
                "status": "INFO",
                "message": f"Unable to parse listening ports: {e}",
                "ports": []
            }

    # =========================================================
    # BITLOCKER
    # =========================================================

    def check_bitlocker(self):
        command = r"""
        try {
            $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop

            if ($null -eq $volume) {
                Write-Output "NO_VOLUME"
            }
            else {
                [ordered]@{
                    MountPoint           = [string]$volume.MountPoint
                    VolumeStatus         = [string]$volume.VolumeStatus
                    ProtectionStatus     = [string]$volume.ProtectionStatus
                    EncryptionPercentage = $volume.EncryptionPercentage
                    EncryptionMethod     = [string]$volume.EncryptionMethod
                } | ConvertTo-Json -Compress
            }
        }
        catch {
            Write-Output "ERROR: $($_.Exception.Message)"
        }
        """

        output = self.run_powershell(command)

        # Usually: needs Administrator rights, or BitLocker not available.
        if self._unavailable(output) or output == "NO_VOLUME":
            return {
                "status": "INFO",
                "message": (
                    "BitLocker information unavailable "
                    "(run as Administrator) or BitLocker is not available."
                ),
                "details": {}
            }

        try:
            data = json.loads(output)

            volume_status = str(data.get("VolumeStatus", "")).lower()
            protection = str(data.get("ProtectionStatus", "")).lower()

            if volume_status == "fullyencrypted" and protection == "on":
                status = "PASS"
                message = "BitLocker is enabled and protection is active."

            elif volume_status == "fullyencrypted":
                status = "WARNING"
                message = (
                    "BitLocker encryption is present, "
                    "but protection is currently off."
                )

            elif "inprogress" in volume_status or "encrypting" in volume_status:
                status = "WARNING"
                message = "BitLocker encryption is currently in progress."

            elif "decrypt" in volume_status:
                status = "WARNING"
                message = "BitLocker is not enabled on the system volume."

            else:
                status = "INFO"
                message = "BitLocker status could not be classified."

            return {
                "status": status,
                "message": message,
                "details": {
                    "mount_point": data.get("MountPoint"),
                    "volume_status": data.get("VolumeStatus"),
                    "protection_status": data.get("ProtectionStatus"),
                    "encryption_percentage": data.get("EncryptionPercentage"),
                    "encryption_method": data.get("EncryptionMethod"),
                }
            }

        except Exception as e:
            return {
                "status": "INFO",
                "message": f"Unable to parse BitLocker status: {e}",
                "details": {}
            }

    # =========================================================
    # SECURE BOOT
    # =========================================================

    def check_secure_boot(self):
        command = r"""
        try {
            $result = $null

            try {
                $result = Confirm-SecureBootUEFI -ErrorAction Stop
            }
            catch {
                $key = Get-ItemProperty `
                    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" `
                    -Name UEFISecureBootEnabled `
                    -ErrorAction Stop

                $result = [bool]$key.UEFISecureBootEnabled
            }

            [ordered]@{ SecureBoot = [bool]$result } | ConvertTo-Json -Compress
        }
        catch {
            Write-Output "ERROR: $($_.Exception.Message)"
        }
        """

        output = self.run_powershell(command)

        if self._unavailable(output):
            return {
                "status": "INFO",
                "message": (
                    "Secure Boot status unavailable "
                    "(legacy BIOS, permissions or firmware configuration)."
                ),
                "enabled": None
            }

        try:
            data = json.loads(output)
            enabled = bool(data.get("SecureBoot"))

            if enabled:
                return {
                    "status": "PASS",
                    "message": "Secure Boot is enabled.",
                    "enabled": True
                }

            return {
                "status": "WARNING",
                "message": "Secure Boot is disabled.",
                "enabled": False
            }

        except Exception as e:
            return {
                "status": "INFO",
                "message": f"Unable to parse Secure Boot status: {e}",
                "enabled": None
            }

    # =========================================================
    # ACCOUNT SECURITY
    # =========================================================

    def check_account_security(self):
        command = r"""
        try {
            $users = @(
                Get-LocalUser -ErrorAction Stop |
                ForEach-Object {
                    [ordered]@{
                        Name        = [string]$_.Name
                        Enabled     = [bool]$_.Enabled
                        Description = [string]$_.Description
                    }
                }
            )

            $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

            [ordered]@{
                Users        = $users
                GuestEnabled = if ($null -ne $guest) { [bool]$guest.Enabled } else { $false }
            } | ConvertTo-Json -Compress -Depth 4
        }
        catch {
            Write-Output "ERROR: $($_.Exception.Message)"
        }
        """

        output = self.run_powershell(command)

        if self._unavailable(output):
            return {
                "status": "INFO",
                "message": "Local account security unavailable.",
                "users": [],
                "guest_enabled": None
            }

        try:
            data = json.loads(output)

            users = [
                {
                    "name": user.get("Name", ""),
                    "enabled": bool(user.get("Enabled", False)),
                    "description": user.get("Description", "") or "",
                }
                for user in self._as_list(data.get("Users"))
            ]

            enabled_count = sum(1 for user in users if user["enabled"])
            guest_enabled = bool(data.get("GuestEnabled", False))

            if guest_enabled:
                status = "WARNING"
                message = (
                    f"{len(users)} local account(s), {enabled_count} enabled. "
                    "Guest account is enabled."
                )
            else:
                status = "PASS"
                message = (
                    f"{len(users)} local account(s), {enabled_count} enabled. "
                    "Guest account is disabled."
                )

            return {
                "status": status,
                "message": message,
                "users": users,
                "guest_enabled": guest_enabled
            }

        except Exception as e:
            return {
                "status": "INFO",
                "message": f"Unable to parse account security: {e}",
                "users": [],
                "guest_enabled": None
            }

    # =========================================================
    # STARTUP APPLICATIONS
    # =========================================================

    def check_startup_apps(self):
        command = r"""
        try {
            $apps = @(
                Get-CimInstance Win32_StartupCommand -ErrorAction Stop |
                ForEach-Object {
                    [ordered]@{
                        Name     = [string]$_.Name
                        Command  = [string]$_.Command
                        Location = [string]$_.Location
                    }
                }
            )
            ConvertTo-Json -InputObject $apps -Compress -Depth 4
        }
        catch {
            Write-Output "ERROR: $($_.Exception.Message)"
        }
        """

        output = self.run_powershell(command)

        if self._unavailable(output):
            return {
                "status": "INFO",
                "message": "Startup applications unavailable.",
                "apps": []
            }

        try:
            apps = [
                {
                    "name": item.get("Name", ""),
                    "command": item.get("Command", ""),
                    "location": item.get("Location", ""),
                }
                for item in self._as_list(json.loads(output))
            ]

            return {
                "status": "INFO",
                "message": f"{len(apps)} startup application(s) detected.",
                "apps": apps
            }

        except Exception as e:
            return {
                "status": "INFO",
                "message": f"Unable to parse startup applications: {e}",
                "apps": []
            }

    # =========================================================
    # LOCAL USERS
    # =========================================================

    def check_local_users(self):
        command = r"""
        try {
            $users = @(
                Get-LocalUser -ErrorAction Stop |
                ForEach-Object {
                    [ordered]@{
                        Name        = [string]$_.Name
                        Enabled     = [bool]$_.Enabled
                        Description = [string]$_.Description
                    }
                }
            )
            ConvertTo-Json -InputObject $users -Compress -Depth 4
        }
        catch {
            Write-Output "ERROR: $($_.Exception.Message)"
        }
        """

        output = self.run_powershell(command)

        if self._unavailable(output):
            return {
                "status": "INFO",
                "message": "Local users unavailable.",
                "users": []
            }

        try:
            users = [
                {
                    "name": item.get("Name", ""),
                    "enabled": bool(item.get("Enabled", False)),
                    "description": item.get("Description", "") or "",
                }
                for item in self._as_list(json.loads(output))
            ]

            enabled_count = sum(1 for user in users if user["enabled"])

            return {
                "status": "INFO",
                "message": f"{len(users)} local account(s), {enabled_count} enabled.",
                "users": users
            }

        except Exception as e:
            return {
                "status": "INFO",
                "message": f"Unable to parse local users: {e}",
                "users": []
            }

    # =========================================================
    # FULL AUDIT (checks run in parallel to save time)
    # =========================================================

    def run_audit(self):

        checks = {
            "system": self.check_system,
            "defender": self.check_defender,
            "firewall": self.check_firewall,
            "windows_update": self.check_windows_update,
            "listening_ports": self.check_listening_ports,
            "bitlocker": self.check_bitlocker,
            "secure_boot": self.check_secure_boot,
            "account_security": self.check_account_security,
            "startup_apps": self.check_startup_apps,
            "local_users": self.check_local_users,
        }

        def safe_call(func):
            try:
                return func()
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {name: pool.submit(safe_call, func) for name, func in checks.items()}
            return {name: future.result() for name, future in futures.items()}