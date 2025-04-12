#!/usr/bin/env python
"""
A small helper script to install required packages for the Local Windows Vulnerability Scanner:
  - requests
  - reportlab
  - pywin32

Usage:
  python install_dependencies.py
"""

import sys
import subprocess

def install_packages():
    packages = ["requests", "reportlab", "pywin32"]
    try:
        print("Installing required packages...")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + packages)
        print("All required packages installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while installing packages: {e}")
        sys.exit(1)

if __name__ == "__main__":
    install_packages()
