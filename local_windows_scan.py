import os
import argparse
import requests
import zipfile
import json
import subprocess
import winreg
import logging

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def download_nvd_feed(year=2025, download_dir='.', filename='nvdcve-1.1-2025.json.zip'):
    """
    Download the NVD JSON feed for a given year.
    Default is set to 2025 for demonstration.
    """
    url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip"
    zip_path = os.path.join(download_dir, filename)

    logging.info(f"Downloading NVD feed from {url} ...")
    response = requests.get(url, stream=True)
    response.raise_for_status()

    with open(zip_path, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)

    logging.info(f"Downloaded feed to: {zip_path}")
    return zip_path

def extract_zip(zip_path, extract_to='.'):
    """
    Extract the ZIP file to the specified folder (default current directory).
    """
    logging.info(f"Extracting {zip_path} ...")
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(extract_to)
    logging.info(f"Extracted to: {extract_to}")

def get_installed_software_wmic():
    """
    Use WMIC (deprecated on some systems) to get installed software:
    Return a list of (name, version).
    """
    logging.info("Gathering installed software via WMIC...")
    cmd = ['wmic', 'product', 'get', 'name,version']
    output = subprocess.check_output(cmd, universal_newlines=True, shell=True)
    lines = output.strip().split('\n')
    # Typically the first line is the header.
    software_list = []
    for line in lines[1:]:
        parts = line.strip().split("  ")
        parts = [p.strip() for p in parts if p.strip()]
        if len(parts) >= 2:
            name = parts[0]
            version = parts[1]
            software_list.append((name, version))
    return software_list

def get_installed_software_registry():
    """
    Alternative approach to get installed software from Windows Registry.
    Returns a list of (name, version).
    """
    logging.info("Gathering installed software via Windows Registry...")
    installed_software = []
    uninstall_keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]
    for uninstall_key in uninstall_keys:
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninstall_key)
        except Exception:
            continue

        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(reg_key, i)
                i += 1
                subkey_path = f"{uninstall_key}\\{subkey_name}"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path) as sub_reg_key:
                    try:
                        name, _ = winreg.QueryValueEx(sub_reg_key, "DisplayName")
                        version, _ = winreg.QueryValueEx(sub_reg_key, "DisplayVersion")
                        installed_software.append((name, version))
                    except FileNotFoundError:
                        # Not all keys have name/version
                        pass
            except OSError:
                # No more subkeys
                break
    return installed_software

def parse_nvd_json(json_path):
    """
    Parse the extracted NVD JSON file and return CVE items.
    """
    logging.info(f"Parsing NVD JSON: {json_path}")
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    # Typically 'CVE_Items' holds the list of vulnerabilities
    cve_items = data.get("CVE_Items", [])
    return cve_items

def safe_version_to_float(version_str):
    """
    Attempt to parse a version-like string into a float if possible.
    If the string is non-numeric (e.g., '2023-01-10'), return None.
    
    This is oversimplified, but it prevents crashing on date-like versions.
    """
    if not version_str:
        return None
    
    # Basic check: try splitting on '.' and keep only numeric parts
    parts = version_str.split('.')
    # We'll try just the first two segments
    try:
        major_str = ''.join([ch for ch in parts[0] if ch.isdigit()])
        minor_str = '0'
        if len(parts) > 1:
            minor_str = ''.join([ch for ch in parts[1] if ch.isdigit()])

        if not major_str:  # No numeric data
            return None

        if minor_str:
            return float(f"{major_str}.{minor_str}")
        else:
            return float(major_str)
    except:
        return None

def is_version_in_range(installed_version, cpe_data):
    """
    Check if installed_version is within the naive version range
    specified by cpe_data (e.g., cpe['versionStartIncluding'], cpe['versionEndExcluding'], etc.).
    
    Returns True if no version constraints or if installed_version meets constraints.
    Otherwise False.
    """
    start_incl = cpe_data.get('versionStartIncluding')
    start_excl = cpe_data.get('versionStartExcluding')
    end_incl   = cpe_data.get('versionEndIncluding')
    end_excl   = cpe_data.get('versionEndExcluding')

    installed_v = safe_version_to_float(installed_version)

    # If installed version can't be parsed, we'll skip strict checks and treat as indefinite
    if installed_v is None:
        # If there's any version range set, let's skip. Otherwise, if no constraints, it's okay.
        if any([start_incl, start_excl, end_incl, end_excl]):
            return False
        return True

    # Evaluate constraints only if they're numeric
    if start_incl:
        s_v = safe_version_to_float(start_incl)
        if s_v is not None and installed_v < s_v:
            return False
    if start_excl:
        s_v = safe_version_to_float(start_excl)
        if s_v is not None and installed_v <= s_v:
            return False
    if end_incl:
        s_v = safe_version_to_float(end_incl)
        if s_v is not None and installed_v > s_v:
            return False
    if end_excl:
        s_v = safe_version_to_float(end_excl)
        if s_v is not None and installed_v >= s_v:
            return False

    return True

def match_vulnerabilities(software_list, cve_items):
    """
    A naive matching approach with minimal version checks:
      - For each piece of installed software,
        compare the software name to the CPE strings found in the CVE data.
      - If there's a partial match, then check if version range constraints are satisfied.
      - Return any matched vulnerability, along with severity.
    """
    matched_vulns = []

    for cve in cve_items:
        cve_id = cve["cve"]["CVE_data_meta"]["ID"]

        # Retrieve possible severity from CVSS v3 if available
        severity = None
        cvss_v3 = cve.get("impact", {}).get("baseMetricV3", {})
        cvss_score = cvss_v3.get("cvssV3", {}).get("baseScore")
        if cvss_score is not None:
            # Quick mapping (you could do more robust mapping):
            if cvss_score >= 9.0:
                severity = "Critical"
            elif cvss_score >= 7.0:
                severity = "High"
            elif cvss_score >= 4.0:
                severity = "Medium"
            else:
                severity = "Low"
        else:
            # Fall back to CVSSv2 if needed, or mark as "Unknown"
            severity = "Unknown"
        
        # Checking CPE in "configurations" -> "nodes"
        configurations = cve.get("configurations", {}).get("nodes", [])
        for node in configurations:
            cpe_match = node.get("cpe_match", [])
            for cpe in cpe_match:
                cpe_uri = cpe.get("cpe23Uri", "").lower()
                
                # Check installed software name
                for (sw_name, sw_version) in software_list:
                    if not sw_name:
                        continue
                    if sw_name.lower() in cpe_uri:
                        # Now check version range constraints
                        if is_version_in_range(sw_version, cpe):
                            matched_vulns.append({
                                "cve_id": cve_id,
                                "software": sw_name,
                                "software_version": sw_version,
                                "severity": severity,
                                "cvss_score": cvss_score
                            })
                            # Stop after first match for this CVE/cpe
                            break

    return matched_vulns

def sort_vulnerabilities(matched_vulns):
    """
    Sort vulnerabilities so that critical/high appear first, followed by medium/low/unknown.
    Also sorts by CVSS score descending within each severity group.
    """
    severity_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Unknown": 5}

    def sort_key(v):
        # Smaller number for higher severity, then descending score
        base_score = v["cvss_score"] if v["cvss_score"] else 0.0
        return (severity_order.get(v["severity"], 5), -base_score)

    matched_vulns.sort(key=sort_key)
    return matched_vulns

def get_vulnerability_summary(matched_vulns):
    """
    Return a dictionary summarizing the total vulnerabilities by severity.
    """
    summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0,
        "Total": 0
    }

    for v in matched_vulns:
        summary[v["severity"]] = summary.get(v["severity"], 0) + 1
        summary["Total"] += 1

    return summary

def create_pdf_report(matched_vulns, feed_year, output_pdf='vulnerability_report.pdf'):
    """
    Create a PDF report of matched vulnerabilities using reportlab.
    Includes an executive summary of vulnerability counts by severity.
    Now includes the NVD feed year used for the scan.
    """
    logging.info(f"Creating PDF report: {output_pdf}")
    c = canvas.Canvas(output_pdf, pagesize=letter)
    width, height = letter

    # Executive Summary
    summary = get_vulnerability_summary(matched_vulns)

    c.setFont("Helvetica-Bold", 16)
    c.drawString(1*inch, height - 1*inch, "Vulnerability Report")

    c.setFont("Helvetica", 11)
    y_position = height - 1.8*inch

    # Append the feed year
    c.drawString(1*inch, y_position, f"NVD Feed Year: {feed_year}")
    y_position -= 0.3*inch

    # Draw summary
    c.drawString(1*inch, y_position, f"Total Vulnerabilities Found: {summary['Total']}")
    y_position -= 0.3*inch
    for sev in ["Critical", "High", "Medium", "Low", "Unknown"]:
        c.drawString(1*inch, y_position, f"{sev}: {summary[sev]}")
        y_position -= 0.2*inch

    # Section for listing details
    y_position -= 0.3*inch
    c.setFont("Helvetica-Bold", 12)
    c.drawString(1*inch, y_position, "Matched Vulnerabilities:")
    y_position -= 0.3*inch
    c.setFont("Helvetica", 10)

    for vuln in matched_vulns:
        line = (f"CVE: {vuln['cve_id']} | "
                f"Software: {vuln['software']} {vuln['software_version']} | "
                f"Severity: {vuln['severity']} | "
                f"CVSS Score: {vuln['cvss_score']}")
        c.drawString(1*inch, y_position, line)
        y_position -= 0.25*inch

        # If we run out of page space, create a new page
        if y_position < 1*inch:
            c.showPage()
            c.setFont("Helvetica", 10)
            y_position = height - 1*inch

    c.showPage()
    c.save()
    logging.info("PDF report generation complete.")

def main():
    parser = argparse.ArgumentParser(
        description="Local Windows Vulnerability Scanner with NVD feed"
    )
    parser.add_argument(
        "--year", 
        type=int, 
        default=2025, 
        help="NVD CVE feed year to download (e.g. 2023)"
    )
    parser.add_argument(
        "--output-pdf",
        default="vulnerability_report.pdf",
        help="Output PDF filename"
    )
    parser.add_argument(
        "--use-wmic",
        action="store_true",
        default=False,
        help="Use WMIC to retrieve installed software (instead of registry)"
    )
    parser.add_argument(
        "--download-dir",
        default=".",
        help="Directory to download and extract the NVD feed"
    )
    args = parser.parse_args()

    zip_filename = f"nvdcve-1.1-{args.year}.json.zip"
    json_filename = f"nvdcve-1.1-{args.year}.json"

    # 1. Download the feed
    zip_path = download_nvd_feed(year=args.year, download_dir=args.download_dir, filename=zip_filename)

    # 2. Extract the zip
    extract_zip(zip_path, extract_to=args.download_dir)

    # 3. Get installed software
    if args.use_wmic:
        software_list = get_installed_software_wmic()
    else:
        software_list = get_installed_software_registry()

    logging.info(f"Number of installed software items found: {len(software_list)}")

    # 4. Parse the NVD JSON
    json_path = os.path.join(args.download_dir, json_filename)
    cve_items = parse_nvd_json(json_path)
    logging.info(f"Number of CVE items loaded from NVD feed: {len(cve_items)}")

    # 5. Match vulnerabilities
    matched_vulns = match_vulnerabilities(software_list, cve_items)
    logging.info(f"Number of matched vulnerabilities: {len(matched_vulns)}")

    if not matched_vulns:
        logging.info("No matched vulnerabilities found. Exiting.")
        return

    # 6. Sort vulnerabilities by severity/score
    matched_vulns = sort_vulnerabilities(matched_vulns)

    # 7. Create a PDF of the findings, passing the feed year for the summary
    create_pdf_report(matched_vulns, feed_year=args.year, output_pdf=args.output_pdf)

    logging.info("Scan and report generation complete.")

if __name__ == "__main__":
    main()
