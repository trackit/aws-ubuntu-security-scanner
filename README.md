# Ubuntu security scanner

This script will generate an excel spreadsheet with security informations regarding kernel, packages, cve and ssh keys

## Requirements

- Install the python dependencies: `sudo pip install -r requirements.txt`
- sudo account on the machines you want to scan

## How to run the tool on your machine

```
# Print help and usage informations
$> ./aws-ubuntu-security-scanner.py --help

# Generate a report
$> ./aws-ubuntu-security-scanner.py --key my_ssh_key --username ubuntu --output myoutput.xlsx --password mypassword --hosts mylistofhosts

# Generate a report and upload it to S3
$> ./aws-ubuntu-security-scanner.py --key my_ssh_key --username ubuntu --output myoutput.xlsx --password mypassword --hosts mylistofhostsfilename --s3 mybucket
```

The tool is built to use AWS credentials stored in `~/.aws/credentials`.
If you set the profile to `env`, the tool will use environment variables you supplied instead.

## Hosts list format

The tool requires a text file containing a list of hosts. This files contains one host per line (ip address of dns name). Example:
```
10.100.42.84
myhost1.mydomain.com
192.168.5.3
```
