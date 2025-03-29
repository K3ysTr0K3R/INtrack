# INtrack - Internet Crawler & Security Scanner

<p align="center">
  <img src="docs/logo.png" alt="INtrack Logo" width="250"/>
</p>

INtrack is a powerful, multi-threaded security scanner and internet crawler designed for network reconnaissance, vulnerability detection, and security assessment. It can scan for a wide variety of instances, vulnerabilities, IoT devices, exposures, and more.

## Features

- 🔍 **Comprehensive Scanning**: Detect web servers, applications, vulnerable services, and more
- 🌐 **Flexible Target Selection**: Scan single hosts, subnets, random internet IPs, or targets from a file
- 🛠️ **Multiple Scanner Types**:
  - Vulnerability scanners for known CVEs
  - Instance detection (WordPress, Jira, Apache, Nginx, etc.)
  - IoT device detection
  - Backdoor implant detection
  - Network service identification
  - Exposure scanners (robots.txt, security.txt, etc.)
- 🔄 **Multi-threaded**: Fast, concurrent scanning with customizable thread count
- 🔧 **Customizable**: Configure ports, timeouts, and scan types
- 📊 **Progress Visualization**: Real-time scanning progress with alive-progress bar

## Installation

```bash
# Install pipx if not already installed:
python3 -m pip install --user pipx
python3 -m pipx ensurepath

# Install INtrack via pipx directly from GitHub:
pipx install git+https://github.com/K3ysTr0K3R/INtrack.git
```

## Usage

### Basic Usage

```bash
intrack -H 192.168.1.1 -p 80,443
```

### Scan Types

```bash
# Check for WordPress instances
intrack -H 192.168.1.0/24 --instance wordpress

# Scan for specific vulnerability
intrack -H 192.168.1.0/24 --vuln CVE-2017-7921

# Detect IoT devices
intrack -H 192.168.1.0/24 --iot hikvision

# Check for exposed API documentation
intrack -H 192.168.1.0/24 --exposure api-docs

# Search for backdoor implants
intrack -H 192.168.1.0/24 --backdoor antsword

# Run network checks
intrack -H 192.168.1.0/24 --network telnet
```

### Target Selection

```bash
# Scan a single host
intrack -H 192.168.1.1 --instance wordpress

# Scan a subnet
intrack -H 192.168.1.0/24 --instance nginx

# Scan targets from a file
intrack -f targets.txt --instance jira

# Scan random internet hosts
intrack -n 100 --instance apache
```

### Advanced Options

```bash
# Combine multiple scan types
intrack -H 192.168.1.0/24 --instance "wordpress,jira" --exposure "robots-txt,security-txt"

# Save results to a file
intrack -H 192.168.1.0/24 --instance wordpress -o results.txt

# Resolve hostnames for IPs
intrack -H 192.168.1.0/24 --hostname --instance wordpress

# Use more threads for faster scanning
intrack -H 192.168.1.0/24 -t 50 --instance wordpress

# Execute worm scripts (requires listener)
intrack -H 192.168.1.0/24 --worm tomcat -L 192.168.1.100 -P 4444

# Probe for HTTP/HTTPS services
intrack -H 192.168.1.0/24 --probe -o webservers.txt
```

### List All Available Scanners

```bash
intrack --list
```

### Vulnerabilities
- Multiple CVEs (use `--list` to see all)

## Command Line Arguments

| Argument           | Description                                                                                 |
|--------------------|---------------------------------------------------------------------------------------------|
| `-H, --host`       | Specify a single target IP or subnet range                                                  |
| `-f, --file`       | Specify a file containing target IPs                                                         |
| `-n, --n-targets`  | Number of random targets to find                                                            |
| `-p, --port`       | Port(s) to check (default: 80)                                                                |
| `-t, --threads`    | Number of threads to use (default: 25)                                                        |
| `-o, --output`     | Store results into a file                                                                   |
| `--lh, --lhost`    | Add a listening host for reverse shells                                                     |
| `--lp, --lport`    | A listening port for reverse shells                                                         |
| `--hostname`       | Resolve hostnames for IP addresses                                                          |
| `--instance`       | Type of instance to check                                                                   |
| `--backdoor`       | Look for backdoor implants                                                                    |
| `--worm`           | Enable special script execution                                                             |
| `--vuln`           | Enable vulnerability script execution                                                       |
| `--exposure`       | Used to detect exposure files                                                               |
| `--iot`            | Used to detect IoT devices                                                                    |
| `--miscellaneous`  | Used for miscellaneous checks                                                               |
| `--workflows`      | Run workflow scans on targets                                                               |
| `-N, --network`    | Used for network scans                                                                      |
| `--timeout`        | Timeout seconds for web requests (default: 10)                                                |
| `--probe`          | Used for probing hosts for HTTP/HTTPS                                                       |
| `-s, --spider`     | Specify subnet range to scan if a result is found                                             |
| `--list`           | List available scanners and checks                                                          |
| `--bar-style`      | Progress bar style (default 'smooth')                                                       |

## Legal Disclaimer

This tool is intended for legal security assessments, penetration testing, and educational purposes only. Use responsibly and only against systems you own or have explicit permission to test.

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please follow the standard contribution guidelines for submitting issues or pull requests.

---

**Stay tuned for updates as we continue to improve INtrack!**