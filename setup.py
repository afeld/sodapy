#!/usr/bin/env python3

from setuptools import setup

with open("sodapy/version.py") as f:
    exec(f.read())

with open("README.md") as f:
    long_description = f.read()

with open("requirements.txt") as requirements:
    required = requirements.read().splitlines()

kwargs = {
    "name": "sodapy",
    "version": __version__,
    "packages": ["sodapy"],
    "description": "Python library for the Socrata Open Data API",
    "long_description": long_description,
    "long_description_content_type": "text/markdown",
    "author": "Cristina Muñoz",
    "maintainer": "Cristina Muñoz",
    "author_email": "hi@xmunoz.com",
    "maintainer_email": "hi@xmunoz.com",
    "license": "MIT",
    "install_requires": required,
    "url": "https://github.com/xmunoz/sodapy",
    "download_url": "https://github.com/xmunoz/sodapy/archive/main.tar.gz",
    "keywords": "soda socrata opendata api",
    "classifiers": [
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
    ],
}

setup(**kwargs)
