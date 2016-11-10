# Domain-check script
=====================

[![N|Solid](https://www2.vcn.bc.ca/wp-content/uploads/2014/06/VCN-logo.png)](https://www2.vcn.bc.ca/)

## What Domain-check script does:
  - Read domain names from the local file
  - Generate IP range for valid IPs
  - Resilve IP address for domain names from the list
  - Retreive WHOIS information for "invalid" domains
  - Compare between domain names from the list vs valid IP range
  - Export all resalts to local file in CSV format
  - Send an email notification to all "invalid" domain-admins
  
## Motivation
Domain-check is a python based script. The main purpose is to automate process of verification of hosted domain names and detect if there any domains that no longer related to the hosted server.

# Prerequisisties:
1. Python 2.7.9
2. pip tool for installing Python packages, see [pip 9.0.1](https://pypi.python.org/pypi/pip)
3. tld for Python, see [tld 0.7.6](https://pypi.python.org/pypi/tld)

# In order to run it:
1. Unzip Domain-check.zip file
2. Open CLI
3. Go to Domain-check folder rom CLI console: cd /Domain-check
4. Run: python domain-check_v4.0.py

# File list:
>'domains.csv'      - Filename for domain/url list

>'template.csv'     - File name for the template file

>'config.txt'       - Filename for list with SMTP server configurations

>'logging.log'      - Filename for logs (automaticly created after by script)

>'ip_list.csv'      - Filename for ip list (automaticly created after by script)

>'vcn_ip_range.csv' - List with valid ips (automaticly deleted after script finished to run)

>'WHOIS.csv'         - List with WHOIS results (automaticly deleted after script finished to run)


## Authors

* **Egor Kostan** - *Initial work* - [iKostan](https://github.com/ikostan)

