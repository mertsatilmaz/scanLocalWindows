#!/usr/bin/env python3
"""
Windows Host Security/Configuration Checker (Example with PDF Output)
----------------------------------------------------------------------
This script gathers basic security/health indicators on a Windows system:
  - OS build and installed hotfixes
  - Firewall status
  - AV/Defender status
  - UAC level
  - Local user accounts and groups
  - Running services and startup items
  - Network ports listening
  - Event log samples
  - (Optional) SFC /scannow

It then writes the results to a PDF and flags potentially suspicious items.

Run from an elevated (Administrator) command prompt for best results.
"""

import subprocess
import sys
import platform
import re
import tempfile
import os

# For PDF generation
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
except ImportError:
    print("Please install reportlab before running this script:")
    print("   pip install reportlab")
    sys.exit(1)

def run_command(cmd, shell=False):
    """
    Helper function to run a command and return (output, error_message).
    If the command fails, the error_message will contain the exception.
    """
    try:
        result = subprocess.check_output(cmd, shell=shell, universal_newlines=True)
        return (result, "")
    except subprocess.CalledProcessError as e:
        # Command returned non-zero exit code
        return ("", f"Command '{cmd}' failed with exit code {e.returncode}")
    except Exception as e:
        return ("", f"Error running command '{cmd}': {e}")

def check_os_version():
    """
    Check OS version with the 'platform' module and 'ver' command.
    Returns (text_output, suspicious_msgs).
    """
    suspicious_msgs = []
    lines = []
    lines.append("=== OS Version ===")

    # platform info
    try:
        os_info = platform.platform()
        lines.append(f"Platform: {os_info}")
    except Exception as e:
        lines.append(f"Error checking OS version: {e}")

    # 'ver' command
    cmd_output, cmd_err = run_command("ver", shell=True)
    if cmd_err:
        lines.append(cmd_err)
    else:
        lines.append(f"'ver' output: {cmd_output.strip()}")

    # [Naive Suspicion Check]: If Windows version is older than 10, consider suspicious (example)
    if "Windows-7" in os_info or "Windows-8" in os_info:
        suspicious_msgs.append("OS might be outdated (below Windows 10).")

    return "\n".join(lines), suspicious_msgs

def check_hotfixes():
    """
    List installed hotfixes (patches) via PowerShell's Get-HotFix.
    Returns (text_output, suspicious_msgs).
    """
    suspicious_msgs = []
    lines = ["=== Installed Hotfixes (Patches) ==="]
    ps_command = "Get-HotFix | Select HotFixID, InstalledOn, Description"
    output, err = run_command(["powershell", "-Command", ps_command])
    if err:
        lines.append(err)
    else:
        lines.append(output.strip())

        # [Naive Suspicion Check] If no hotfixes found, suspicious
        # We'll just check if the output only has the header but no data lines
        if "HotFixID" in output and "Description" in output:
            # Some minimal data is present
            # We won't do a deeper parse here, but you could parse for missing updates
            pass
        else:
            suspicious_msgs.append("No hotfix data found (possibly missing updates).")

    return "\n".join(lines), suspicious_msgs

def check_firewall_status():
    """
    Check Windows Firewall status for each profile via netsh.
    Returns (text_output, suspicious_msgs).
    """
    suspicious_msgs = []
    lines = ["=== Firewall Status ==="]
    cmd = "netsh advfirewall show allprofiles"
    output, err = run_command(cmd, shell=True)
    if err:
        lines.append(err)
    else:
        lines.append(output.strip())
        # [Naive Suspicion Check] If 'State OFF' found for domain/public/private
        # highlight as suspicious
        # We'll do a simple search
        off_pattern = re.compile(r"State\s+OFF", re.IGNORECASE)
        if off_pattern.search(output):
            suspicious_msgs.append("Firewall is OFF on at least one profile.")

    return "\n".join(lines), suspicious_msgs

def check_defender_status():
    """
    Check Microsoft Defender status via PowerShell's Get-MpComputerStatus.
    Returns (text_output, suspicious_msgs).
    """
    suspicious_msgs = []
    lines = ["=== Microsoft Defender / AV Status ==="]
    ps_command = "Get-MpComputerStatus | Select AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled"
    output, err = run_command(["powershell", "-Command", ps_command])
    if err:
        lines.append(err)
    else:
        lines.append(output.strip())
        # [Naive Suspicion Check] if 'AntivirusEnabled' or 'RealTimeProtectionEnabled' is 'False'
        if "False" in output:
            suspicious_msgs.append("Defender AV or RealTimeProtection is DISABLED.")

    return "\n".join(lines), suspicious_msgs

def check_uac_level():
    """
    Check UAC level via registry.
    Returns (text_output, suspicious_msgs).
    """
    suspicious_msgs = []
    lines = ["=== UAC Level ==="]
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            value, regtype = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
            lines.append(f"ConsentPromptBehaviorAdmin = {value}")
            if value == 0:
                lines.append("UAC Prompt: Disabled")
                suspicious_msgs.append("UAC is disabled (dangerous).")
            elif value == 1 or value == 5:
                lines.append("UAC Prompt: Enabled / Secure Desktop")
            else:
                lines.append("UAC Prompt: Unknown configuration")
    except FileNotFoundError:
        lines.append("Could not find UAC registry key.")
    except Exception as e:
        lines.append(f"Error checking UAC level: {e}")

    return "\n".join(lines), suspicious_msgs

def check_local_accounts():
    """
    List local user accounts using 'net user'.
    Returns (text_output, suspicious_msgs).
    """
    suspicious_msgs = []
    lines = ["=== Local User Accounts ==="]
    output, err = run_command("net user", shell=True)
    if err:
        lines.append(err)
    else:
        lines.append(output.strip())
        # [Naive Suspicion Check] If 'Guest' or default accounts are enabled
        # or a suspicious name like 'backdoor'
        if "Guest" in output:
            suspicious_msgs.append("Guest account found. Make sure it's disabled.")
        if "backdoor" in output.lower():
            suspicious_msgs.append("User 'backdoor' found (HIGHLY suspicious).")

    return "\n".join(lines), suspicious_msgs

def check_local_groups():
    """
    List local groups using 'net localgroup'.
    Returns (text_output, suspicious_msgs).
    """
    suspicious_msgs = []
    lines = ["=== Local Groups ==="]
    output, err = run_command("net localgroup", shell=True)
    if err:
        lines.append(err)
    else:
        lines.append(output.strip())
        # [Naive Suspicion Check] if 'Administrators' group has too many members, etc. 
        # This is beyond the scope, but we can highlight the presence of any group named 'hackers'.
        if "hackers" in output.lower():
            suspicious_msgs.append("'hackers' group found (HIGHLY suspicious).")

    return "\n".join(lines), suspicious_msgs

def check_services():
    """
    List all services and their current states via PowerShell.
    Returns (text_output, suspicious_msgs).
    """
    suspicious_msgs = []
    lines = ["=== Services ==="]
    ps_command = "Get-Service | Select Name,Status,StartType"
    output, err = run_command(["powershell", "-Command", ps_command])
    if err:
        lines.append(err)
    else:
        lines.append(output.strip())
        # [Naive Suspicion Check] if there's a known suspicious service name
        if "VNC" in output.upper() or "BACKDOOR" in output.upper():
            suspicious_msgs.append("Possible suspicious service related to 'VNC' or 'backdoor' found.")

    return "\n".join(lines), suspicious_msgs

def check_startup_items():
    """
    Check startup items in typical registry locations plus shell:startup folder.
    Returns (text_output, suspicious_msgs).
    """
    suspicious_msgs = []
    lines = ["=== Startup Items (Registry) ==="]
    ps_command = r"""
      Get-CimInstance -Class Win32_StartupCommand | 
      Select Name, Location, Command, User 
    """
    output, err = run_command(["powershell", "-Command", ps_command])
    if err:
        lines.append(err)
    else:
        lines.append(output.strip())
        # [Naive Suspicion Check] Look for "crypto miner", "ransom", "trojan" etc. in command strings
        if re.search(r"(crypto|mining|ransom|trojan)", output, re.IGNORECASE):
            suspicious_msgs.append("Suspicious startup item (possible crypto or ransomware).")

    return "\n".join(lines), suspicious_msgs

def check_open_ports():
    """
    Use netstat to show ports listening with associated PID.
    Returns (text_output, suspicious_msgs).
    """
    suspicious_msgs = []
    lines = ["=== Open Ports / Listening Services ==="]
    output, err = run_command("netstat -ano | findstr LISTENING", shell=True)
    if err:
        lines.append(err)
    else:
        if not output.strip():
            lines.append("No listening ports found or findstr returned no matches.")
        else:
            lines.append(output.strip())
            # [Naive Suspicion Check] if we see high numbered ports or typical malicious ports, etc.
            # For example, port 6666, 4444 often used by malware, etc.
            if re.search(r":6666|:4444", output):
                suspicious_msgs.append("Port 6666 or 4444 is open (commonly used by malware).")

    return "\n".join(lines), suspicious_msgs

def check_recent_event_logs():
    """
    Show the 5 most recent Security Log entries via Get-EventLog (naive).
    Returns (text_output, suspicious_msgs).
    """
    suspicious_msgs = []
    lines = ["=== Recent Security Events ==="]
    ps_command = "Get-EventLog -LogName Security -Newest 5 | Select EventID,TimeGenerated,EntryType,Source"
    output, err = run_command(["powershell", "-Command", ps_command])
    if err:
        lines.append(err)
    else:
        lines.append(output.strip())
        # [Naive Suspicion Check] if we see a bunch of 'FailureAudit' lines
        if "FailureAudit" in output:
            suspicious_msgs.append("Multiple failed logon attempts in Security log.")

    return "\n".join(lines), suspicious_msgs

def run_sfc_check():
    """
    OPTIONAL: File integrity check with System File Checker (SFC).
    This requires Administrator privileges and might take some time.
    """
    suspicious_msgs = []
    lines = ["=== SFC /scannow (OPTIONAL) ==="]

    answer = input("Would you like to run 'sfc /scannow'? (Y/N): ").strip().lower()
    if answer == 'y':
        try:
            # 1) Capture output with a specific code page to avoid garbled characters.
            #    'cp437' is common for Windows console, but you could try 'cp1252' as well.
            cmd_output = subprocess.check_output(
                "sfc /scannow",
                shell=True,
                stderr=subprocess.STDOUT,
                encoding="cp437",     # or "cp1252"
                errors="replace"      # replace unmappable chars with a placeholder
            )

            # 2) Strip out progress-bar box characters and other non-ASCII:
            #    This regex keeps standard printable ASCII plus newlines.
            cmd_output_clean = re.sub(r'[^\x20-\x7E\r\n]+', '', cmd_output)

            lines.append(cmd_output_clean)

            # [Naive Suspicion Check] If "found corrupt files but could not fix" is in the output
            if re.search(r"could\s+not\s+fix", cmd_output_clean, re.IGNORECASE):
                suspicious_msgs.append("SFC found corrupt files that could not be repaired.")

        except subprocess.CalledProcessError as e:
            error_msg = f"SFC /scannow returned a non-zero exit code: {e.returncode}"
            lines.append(error_msg)
            suspicious_msgs.append("SFC scan encountered an error.")
        except Exception as e:
            lines.append(f"Error running SFC: {e}")
            suspicious_msgs.append("SFC scan encountered an error.")
    else:
        lines.append("Skipping SFC check.")

    return "\n".join(lines), suspicious_msgs

def main():
    if not hasattr(sys, 'winver'):
        print("This script is intended for Windows systems only.")
        sys.exit(1)

    # We'll store results from each check plus suspicious flags
    checks = []
    # Each item in checks will be a dict: {
    #   'title': <title string>,
    #   'output': <text output of the command(s)>,
    #   'suspicious': [list of suspicious reasons]
    # }

    print("Starting Windows Host Checks...\n(This may take a moment)\n")

    # Run all checks
    # OS
    out, sus = check_os_version()
    checks.append({"title": "OS Version", "output": out, "suspicious": sus})

    # Hotfixes
    out, sus = check_hotfixes()
    checks.append({"title": "Hotfixes", "output": out, "suspicious": sus})

    # Firewall
    out, sus = check_firewall_status()
    checks.append({"title": "Firewall Status", "output": out, "suspicious": sus})

    # Defender
    out, sus = check_defender_status()
    checks.append({"title": "Defender Status", "output": out, "suspicious": sus})

    # UAC
    out, sus = check_uac_level()
    checks.append({"title": "UAC Level", "output": out, "suspicious": sus})

    # Local Accounts
    out, sus = check_local_accounts()
    checks.append({"title": "Local User Accounts", "output": out, "suspicious": sus})

    # Local Groups
    out, sus = check_local_groups()
    checks.append({"title": "Local Groups", "output": out, "suspicious": sus})

    # Services
    out, sus = check_services()
    checks.append({"title": "Services", "output": out, "suspicious": sus})

    # Startup Items
    out, sus = check_startup_items()
    checks.append({"title": "Startup Items", "output": out, "suspicious": sus})

    # Open Ports
    out, sus = check_open_ports()
    checks.append({"title": "Open Ports", "output": out, "suspicious": sus})

    # Recent Security Events
    out, sus = check_recent_event_logs()
    checks.append({"title": "Recent Security Events", "output": out, "suspicious": sus})

    # SFC (Optional)
    out, sus = run_sfc_check()
    checks.append({"title": "SFC Check", "output": out, "suspicious": sus})

    print("All checks completed. Generating PDF report...")

    # Generate PDF
    generate_pdf_report(checks, output_pdf="host_security_report.pdf")

    print("Report saved as 'host_security_report.pdf'.")

def generate_pdf_report(checks, output_pdf="host_security_report.pdf"):
    """
    Create a PDF summarizing the check outputs, with suspicious items flagged.
    """
    c = canvas.Canvas(output_pdf, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(1 * inch, height - 1 * inch, "Windows Host Security Report")

    y = height - 1.5 * inch

    # Summarize suspicious checks first
    all_suspicious = []
    for item in checks:
        if item["suspicious"]:
            for reason in item["suspicious"]:
                all_suspicious.append((item["title"], reason))

    c.setFont("Helvetica-Bold", 12)
    c.drawString(1 * inch, y, "Suspicious Findings:")
    y -= 0.25 * inch
    c.setFont("Helvetica", 10)

    if not all_suspicious:
        c.drawString(1 * inch, y, "No suspicious items detected based on naive checks.")
        y -= 0.3 * inch
    else:
        for (section, reason) in all_suspicious:
            line = f"[{section}] {reason}"
            c.drawString(1 * inch, y, line)
            y -= 0.25 * inch
            if y < 1 * inch:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 1 * inch

    # Now list full details for each check
    for item in checks:
        c.setFont("Helvetica-Bold", 12)
        c.drawString(1 * inch, y, item["title"])
        y -= 0.25 * inch
        c.setFont("Helvetica", 10)
        # Split the output into lines
        check_lines = item["output"].splitlines()

        for line in check_lines:
            c.drawString(1 * inch, y, line)
            y -= 0.18 * inch
            if y < 1 * inch:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 1 * inch

        # Extra gap
        y -= 0.25 * inch
        if y < 1 * inch:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - 1 * inch

    c.showPage()
    c.save()

if __name__ == "__main__":
    main()
