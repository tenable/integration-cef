# Tenable.io to Syslog (CEF Formatted)

This integration is designed to pull Tenable.io vulnerability data and then
generate Syslog messages in the CEF standard to be pushed to any CEF compatible
SIEM.  The integration will leverage the following fields:

* **Vendor**: Tenable
* **Product**: Tenable.io
* **Version**: Version of the integration script
* **Severity**: The Vulnerability Severity
* **ID**: The Plugin ID of the vulnerability Check
* **Destination IP (_dst_)**: Host IPv4 Address
* **Destination Mac (_dmac_)**: Host Mac Address
* **Destination Port (_dport_)**: Vulnerability Port
* **Protocol (_proto_)**: Vulnerability Check Protocol
* **Received Time (_rt_)**: Vulnerability Last Found
* **Custom Field 1 (_cs1_ & _c1sLabel_)**: Vulnerability Output
* **Custom Field 2 (_cs2_ & _cs2Label_)**: Vulnerability Description
* **Custom Field 3 (_cs3_ & _cs3Label_)**: Vulnerability Solution
* **Custom Field 4 (_cs4_ & _cs4Label_)**: CVSS Base Score

Example Event:

```
CEF:0|Tenable|Tenable.io|1.0.0|8555|Mac OS X < 10.10 Multiple Vulnerabilities (APPLE-SA-2014-10-16-1 OS X Yosemite v10.10)|Very-High|dst=192.168.0.100 dmac=00:de:ad:be:ef:00 dhost=192.168.0.100 dport=0 proto=TCP rt=1574324071000 cs1=The detected OS X version is :\nOS X 10_9_2 cs1Label=VulnerabilityOutput cs2=Apple OS X 10.10 (Yosemite) contains fixes for the following components: \n  - 802.1X\n  - AFP File Server\n  - App Sandbox\n  - Bash\n  - Bluetooth\n  - CFPreferences\n  - CUPS\n  - Certificate Trust Policy\n  - CoreStorage\n  - Dock\n  - IOAcceleratorFamily\n  - IOHIDFamily\n  - IOKit\n  - Kernel\n  - LaunchServices\n  - LoginWindow\n  - MCX Desktop Config Profiles\n  - Mail\n  - NetFS Client Framework\n  - QuickTime\n  - Safari\n  - Secure Transport\n  - Code Signing\n  - Security\n  - apache\n  - fdesetup\n  - iCloud Find My Mac cs2Label=VulnerabilityDescription cs3=Upgrade to OS X 10.10 or higher. cs3Label=VulnerabilitySolution cs4=10.0 cs4Label=CVSSBase core cs5=CVE-2014-4435 CVE-2014-4446 CVE-2014-4434 CVE-2014-4444 CVE-2014-4433 CVE-2014-4432 CVE-2014-4443 CVE-2014-4428 CVE-2014-4417 CVE-2014-4439 CVE-2014-4427 CVE-2014-4438 CVE-2014-4437 CVE-2014-4426 CVE-2014-4425 CVE-2014-4436 CVE-2014-4391 CVE-2014-4431 CVE-2014-4442 CVE-2014-4441 CVE-2014-4430 CVE-2014-4440 cs5Label=CVE cs6=5.9 cs6Label=VPRScore
```

## Requirements

* Tenable.io API Keys associated to an account with Admin privileges (required
  for the Vuln Export APIs).
* Syslog host & port to send the data to.
* A host to run the script on.

## Setup

```
pip install tenable-cef
```


## Options

Configuration is as simple as either specifying the appropriate environment
variables and/or command-line options.

```
Usage: tenable-cef [OPTIONS]

  Tenable.io -> CEF Transformer & Ingester

Options:
  --tio-access-key TEXT         Tenable.io Access Key
  --tio-secret-key TEXT         Tenable.io Secret Key
  -v, --verbose                 Logging Verbosity
  -s, --observed-since INTEGER  The unix timestamp of the age threshold
  -r, --run-every INTEGER       How many hours between recurring imports
  -t, --threads INTEGER         How many concurrent threads to run for the
                                import.
  -d, --destination TEXT        Syslog Destination for CEF Formatted Data
  -p, --port INTEGER            Syslog Port for CEF Formatted Data
  --severity TEXT               Tenable.io vulnerability severity
  --help                        Show this message and exit.
```

The following environment variables can be used:

```
VERBOSITY           Logging Verbosity.
                        0 - WARNING
                        1 - INFO
                        2 - DEBUG
SINCE               The observed-since option.
RUN_EVERY           The run-every option.
THREADS             The number of threads to run the syslog sender.
DEST_ADDRESS        The Syslog host address
DEST_PORT           The Syslog service port.
```

## Example Usage

Run once and transform everything from all time:

```
tenable-cef
```

Run once and only import findings that have been seen since yesterday:

```
tenable-cef -s $(date -v-1d +%s)
```

Run the import every 24 hours

```
tenable-cef -r 24
```

Only import High and Critical vulnerabilities:

```
tenable-cef --severity high --severity critical
```

## Changelog

Visit the [changelog][CHANGELOG.md].