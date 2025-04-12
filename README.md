Below is a sample **README.md** document that you can copy directly into your GitHub repository. It explains how to install, configure, and run the script, as well as provides disclaimers and tips for further development.

---

# Local Windows Vulnerability Scanner

A Python-based script that downloads a specified year of the National Vulnerability Database (NVD) feed, enumerates installed software on a local Windows machine, matches any applicable vulnerabilities, and generates a PDF report summarizing the findings.

## Table of Contents
1. [Features](#features)  
2. [Prerequisites](#prerequisites)  
3. [Installation](#installation)  
4. [Usage](#usage)  
5. [How It Works](#how-it-works)  
6. [Customization](#customization)  
7. [Limitations & Future Improvements](#limitations--future-improvements)  
8. [License](#license)

---

## Features
- **Automatic NVD Feed Download**: Fetches and extracts the specified year’s CVE data (`nvdcve-1.1-<year>.json`).
- **Local Inventory Gathering**: Enumerates installed Windows software through the registry or WMIC.
- **Naive Matching**: Checks software names/versions against CPE URIs in the NVD feed.
- **Basic Version Range Checking**: Handles simple numeric ranges (`versionStartIncluding`, `versionEndExcluding`, etc.).
- **PDF Reporting**:
  - Displays a summary of matched vulnerabilities by severity (Critical, High, Medium, Low, Unknown).
  - Lists each detected vulnerability with CVE ID, software info, severity, and CVSS base score.
  - Annotates the year of the NVD feed for clarity.

---

## Prerequisites
1. **Operating System**: Windows (tested on Windows 10, Windows 11).  
2. **Python**: Version 3.7+ recommended.  
3. **Network Access**: The script needs to download the NVD ZIP file from <https://nvd.nist.gov>.  
4. **Python Packages**:
   - [requests](https://pypi.org/project/requests/)  
   - [reportlab](https://pypi.org/project/reportlab/)  
   - [pywin32](https://pypi.org/project/pywin32/) (optional; typically needed for Registry access on Windows)  

---

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/<YOUR_USERNAME>/<YOUR_REPO_NAME>.git
   cd <YOUR_REPO_NAME>
   ```

2. **Install Required Packages**:
   ```bash
   pip install requests reportlab pywin32
   ```
   > If you have multiple Python versions, you may need `python -m pip install ...`.

3. **(Optional) Create a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/Scripts/activate  # On Windows: venv\Scripts\activate
   pip install requests reportlab pywin32
   ```
   This isolates dependencies to this project if desired.

---

## Usage

After installing dependencies, you can run the script directly:

```bash
python local_windows_scan.py [OPTIONS]
```

### Command-Line Options

| Argument               | Description                                                                                           | Default                        |
|------------------------|-------------------------------------------------------------------------------------------------------|--------------------------------|
| `--year`               | **NVD feed year** to download. Example: `--year 2023`.                                               | 2025                           |
| `--output-pdf`         | Output **PDF filename**. Example: `--output-pdf my_report.pdf`.                                       | `vulnerability_report.pdf`     |
| `--use-wmic`           | If set, the script attempts to use **WMIC** instead of the **Registry** to enumerate installed apps.  | (flag off by default)          |
| `--download-dir`       | **Directory** to download and extract the NVD feed.                                                  | `.` (current directory)        |

**Examples:**

1. **Basic Scan Using Default Registry Enumeration**:
   ```bash
   python local_windows_scan.py --year 2023 --output-pdf my_report.pdf
   ```
   - Downloads the **2023** feed.
   - Generates a PDF named **my_report.pdf**.
   - Enumerates installed software from the Registry.

2. **Use WMIC for Software Enumeration**:
   ```bash
   python local_windows_scan.py --year 2022 --use-wmic
   ```
   - Downloads the **2022** feed.
   - Enumerates installed software using WMIC.
   - Creates the PDF report with the default name (**vulnerability_report.pdf**).

---

## How It Works

1. **NVD Feed Download**  
   The script downloads `nvdcve-1.1-<year>.json.zip` from the NVD site using `requests`.  
2. **Extraction**  
   It extracts the ZIP to retrieve `nvdcve-1.1-<year>.json`.  
3. **Software Inventory**  
   - By default, it reads installed software from the **Windows Registry** under the `Uninstall` keys.  
   - Alternatively, it can query software via **WMIC** if `--use-wmic` is set.  
4. **Vulnerability Matching**  
   - It parses the JSON for CVE items.  
   - For each CVE’s **CPEs**, if the software name partially matches the installed software name, it checks any version constraints.  
5. **Severity & Sorting**  
   - Retrieves CVSS base scores to categorize vulnerabilities as `Critical`, `High`, `Medium`, `Low`, or `Unknown`.  
   - Sorts them in order of severity, then by descending CVSS score.  
6. **PDF Report**  
   - Summarizes the number of matched vulnerabilities by severity and the **NVD feed year** used.  
   - Lists each matched CVE with relevant details.  

---

## Customization

- **Version Parsing**  
  Currently, the script performs **very naive** parsing (e.g., converting version strings to floats). For more accurate version checks, integrate a robust library or custom logic that can handle complex version strings.  
- **Name Matching**  
  The script checks if the installed software name (lowercased) is a **substring** of the CPE URI. You may wish to implement more precise matching logic.  
- **Data Storage**  
  If you need to store results historically or generate advanced queries, you can add a database (e.g., SQLite) and log each scan result there.  
- **Scheduling**  
  To automate scans, run the script via **Windows Task Scheduler** or another scheduling mechanism.  

---

## Limitations & Future Improvements

1. **Naive Version Comparisons**  
   - The script may skip or misinterpret version constraints if they’re not purely numeric.  
   - Real-world scenarios often require advanced version parsing or canonicalization.  

2. **Name-Only Matching**  
   - Software names are matched in a simplistic substring manner.  
   - A robust approach might map installed software to known CPE identifiers or rely on vendor string matching.  

3. **One-Year Feed**  
   - The script uses a single year’s feed. Consider incorporating the [NVD Modified/Recent Feeds](https://nvd.nist.gov/vuln/data-feeds) for more up-to-date or incremental data.  

4. **No OS-Level Checks**  
   - Currently checks only installed programs. You might want to include OS version/hotfix scanning or driver checks.  

5. **No Exploit Data**  
   - The script does not provide information about known exploits or threat intelligence related to each CVE.  

---

## License

This project is provided **as-is**, without warranty or official support. For open-source usage, you can pick a license that suits your needs (e.g., MIT, Apache 2.0, GPL). Include a `LICENSE` file in the repository if you require a specific open-source license.

---

### Disclaimer

This script is primarily a **proof of concept**. It does **not** guarantee complete or accurate results. Always verify findings with additional sources or commercial tools. Use at your own risk.

---

**Enjoy scanning, stay safe, and keep your systems up to date!**
