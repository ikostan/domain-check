# Domain-check script
=====================
[![N|Solid](https://www2.vcn.bc.ca/wp-content/uploads/2014/06/VCN-logo.png)](https://www2.vcn.bc.ca/)
# What Domain-check script does:
  - Read domain names from the local file
  - Generate IP range for valid IPs
  - Resolve IP addresses for domain names from the list
  - Retrieve WHOIS information for "invalid" domains
  - Compare between domain names from the list vs valid IP range
  - Extract relevant eMail addresses
  - Extract web-admin name
  - Export all results to local file in CSV format
  - Send an email notification to all "invalid" domain-admins
  
# Motivation
Domain-check is a python based script. The main purpose is to automate the process of verification of hosted domain names and detect if there any domains that no longer related to the hosted server.

# Prerequisites:
1. Python 2.7.9
2. pip tool for installing Python packages, see [pip 9.0.1](https://pypi.python.org/pypi/pip)
3. tld for Python, see [tld 0.7.6](https://pypi.python.org/pypi/tld)
4. numpy
5. validate_email 1.3 (see more info: https://pypi.python.org/pypi/validate_email)

# In order to run it:
1. Unzip Domain-check.zip file
2. Edit 'domains.csv' file (enter domain names that you want to validate, see example inside the file)
3. Edit 'config.txt' file (enter your SMTP server configurations, see example inside the file)
4. Open CLI
5. Go to Domain-check folder from CLI console: cd /Domain-check
6. Run: python domain-check_v4.0.py

# Aditional configurations:
## Logs level:
1. Default logs level is logging.INFO
2. In order to change it to DEBUG: change "logging.INFO" to "logging.DEBUG"
3. Please note logging.warning, logging.error and logging.critical are still not implemented
4. Known issue: logging.DEBUG logs show a lot of errors from CLI console, but this issue does not interrupt script function. 

## Valid IP range:
- NOTE:By default script generates IP range from 207.102.64.1 to 207.102.64.255
- In oprder to change default range configuration:

1. Go to 'create_vcn_ip_csv' function
2. Edit 'startIP' value (default value is: 0.0.0.)
3. 'ip' represents IP range.

## Email template (email.csv):
- Please customaze default text before use it.

## Wait method:
- Sleep time between WHOIS calls is set to 1 second (time.sleep(1)).

## How to disable/enable send email function:
1. During script run-time you will see following question: "Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no): "
2. Enter "2" if you not intrested in sending email.

### NOTE: send email function disabled by default.

## File list:
>'domains.csv'      - Filename for domain/url list

>'template.csv'     - File name for the template file

>'config.txt'       - Filename for list with SMTP server configurations

>'logging.log'      - Filename for logs (automaticly created after by script)

>'ip_list.csv'      - Filename for ip list (automaticly created after by script)

>'vcn_ip_range.csv' - List with valid ips (automaticly deleted after script finished to run)

>'WHOIS.csv'        - List with WHOIS results (automatically deleted after script finished to run)

> 'email.txt'       - Contains email notification template


## Authors

* **Egor Kostan** - *Initial work* - [iKostan](https://github.com/ikostan)

