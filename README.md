# gather_0

**gather_0** is a security research tool designed to automate the process of finding subdomains, probing their availability, gathering parameters, filtering out sensitive information, and detecting secrets in JavaScript files. 

## Features
- Discover subdomains using **Subfinder**.
- Probe subdomains for availability using **httprobe**.
- Gather parameters using **gau**.
- Filter out parameters using **uro**.
- Analyze JavaScript files for secrets using **SecretFinder**.

## Requirements

Before running **gather_0**, make sure you have the following dependencies installed on your system:

- **Python 3.7+**
- **Subfinder**
- **httprobe**
- **gau**
- **uro**
- **SecretFinder**

## Installation

### 1. Install Python 3

If you don’t already have Python 3 installed, you can download it from the official Python website:  
[https://www.python.org/downloads/](https://www.python.org/downloads/)

To verify the installation, open a terminal and type:

```bash
python3 --version
