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

Example Event (newlined for easier reading):

```
CEF:0|Tenable|Tenable.io|1.0.0|50686|IP Forwarding Enabled|Medium|
dst=192.168.0.100
dmac=00:DE:AD:BE:EF:00
dhost=192.168.101.193
dport=0
proto=TCP
rt=1574316940000
cs1=None
cs1Label=VulnerabilityOutput
cs2=The remote host has IP forwarding enabled. An attacker can exploit\nthis to route packets through the host and potentially bypass some\nfirewalls / routers / NAC filtering. \n\nUnless the remote host is a router, it is recommended that you disable\nIP forwarding.
cs2Label=VulnerabilityDescription
cs3=On Linux, you can disable IP forwarding by doing :\n\necho 0 > /proc/sys/net/ipv4 ip_forward\n\nOn Windows, set the key 'IPEnableRouter' to 0 under\n\nHKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\n\nOn Mac OS X, you can disable IP forwarding by executing the command :\n\nsysctl -w net.inet.ip.forwarding=0\n\nFor other systems, check with your vendor.
cs3Label=VulnerabilitySolution
cs4=5.8
cs4Label=CVSSBaseScore
cs5=CVE-1999-0511
cs5Label=CVE
cs6=None
cs6Label=VPRScore
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
  -S, --sources TEXT            Tenable.io asset sources
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