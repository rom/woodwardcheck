#!/usr/bin/env python3
"""
Setup script for WoodwardCheck.

Security Audit Tool for Woodward EasyGen Controllers.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read version from package
version = {}
with open("woodwardcheck/__init__.py") as f:
    for line in f:
        if line.startswith("__version__"):
            exec(line, version)

# Read long description from README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="woodwardcheck",
    version=version.get("__version__", "1.0.0"),
    author="WoodwardCheck Team",
    author_email="security@example.com",
    description="Security Audit Tool for Woodward EasyGen Controllers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/woodwardcheck/woodwardcheck",
    project_urls={
        "Bug Tracker": "https://github.com/woodwardcheck/woodwardcheck/issues",
        "Documentation": "https://github.com/woodwardcheck/woodwardcheck/docs",
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Utilities",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "flake8>=6.0",
            "mypy>=1.0",
            "types-PyYAML",
        ],
        "full": [
            "pymodbus>=3.0",
            "pysnmp>=4.4",
            "requests>=2.28",
            "rich>=13.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "woodwardcheck=woodwardcheck.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=[
        "security",
        "audit",
        "industrial-control-systems",
        "ics",
        "scada",
        "modbus",
        "woodward",
        "easygen",
        "generator-controller",
        "iec62443",
    ],
)
