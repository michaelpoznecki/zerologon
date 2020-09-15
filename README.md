# Zerologon Exploit Script

This script is used to test and exploit unpatched Domain Controllers for the Zerologon Vulnerability (CVE-2020-1472).
More information on this vulnerability can by found here:

https://www.secura.com/blog/zero-logon

The PoC code for detection was provided by SecuraBV and can be found here:

https://github.com/SecuraBV/CVE-2020-1472

The exploit code has been provided by two sources:

https://github.com/dirkjanm/CVE-2020-1472

https://github.com/cube0x0/CVE-2020-1472

## Requirements

The latest version of impacket from GitHub is needed for this attack, and at the time of writing, the 
impacket library nrpc.py was not updated and is needed to be imported locally. This can be found
in the github repository from cube0x0 shown above.

## Usage

```
usage: zerologon.py [-h] [-x] N [N ...] IP [IP ...]

Tests whether a domain controller is vulnerable to the Zerologon attack.

positional arguments:
  N              Netbios name of the Domain Controller
  IP             IP address of the DOmain Controller

optional arguments:
  -h, --help     show this help message and exit
  -x, --exploit  Exploit the target
```

## Example

```python3 zerologon.py DC\_NAME X.X.X.X```

Scans the target for the vulnerability

```python3 zerologon.py DC\_NAME X.X.X.X -exploit```

Scans the target then sets the account ("DC\_NAME$") password to 0


