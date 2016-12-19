# Domain-check script
=====================
[![N|Solid](https://www2.vcn.bc.ca/wp-content/uploads/2014/06/VCN-logo.png)](https://www2.vcn.bc.ca/)
## What Domain-check script does:
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
3. Edit 'config.csv' file (enter your configurations, see example inside the file)
4. Open CLI
5. Go to Domain-check folder from CLI console: cd /Domain-check
6. Run: python domain-check_v4.0.py

  # Aditional configurations:
  ## Logs level:
1. Default logs level is logging.DEBUG
2. In order to change it to INFO: change "logging.DEBUG" to "logging.INFO"
3. Please note logging.warning, logging.error and logging.critical are still not implemented
4. Known issue: n/a. 

  ## Valid IP range:
- NOTE:By default script generates IP range from 0.0.0.1 to 0.0.0.254 (only last 8 bits)
- In oprder to change default range configuration:

1. Open config.csv file
2. Go to 'startIP' column
3. Edit 'startIP' value (default value is: 0.0.0.). Please note: IP range is 255.

  ## Configuration file (config.csv):
Please customaze default configurations before before running the script:
  ###A. General configurations:

- isSilent
- startIP

  ###B. sendEmail related configurations:

- isSend
- SMTP_server
- port
- sender
- userName
- userPassword
- test_sendEmail
- test_emailAddress

  ###C. Wait method related configurations:

- sleep_Ping
- sleep_WHOIS
- sleep_sendEmail

  ###D. Web-admin / website-owner email patterns:

- registrant_email
- registrar_abuse_contact_email
- e_mail
- admin_email
- tech_email
- error_code
- email_
- reseller_email

PLEASE NOTE:
- Script will perform a few validations regarding values from config.csv fle. In case of configurations conflict sendEmail will be disabled

## Email template (email.csv):
- Please customaze default text before use it.
- Script using WHOIS output in order to search for web-owner name.
- Script will use web-owner if client name is not available.

  ## Wait method:
- all sleep/wait values in 'config.csv' file
- Sleep time between WHOIS calls (sleep_WHOIS column in 'config.csv' file) is set to 1 second (time.sleep(sleep_WHOIS)).
- Sleep time for sendEmail function (sleep_sendEmail column in 'config.csv' file) is set to 3 second (time.sleep(sleep_sendEmail)).
- Sleep time between ping calls (sleep_Ping column in 'config.csv' file) is set to 1 second (time.sleep(sleep_Ping)).

  ## How to disable/enable send email function:
  ###A: General configurations.
1. Open config.csv file
2. Go to isSend column and change value: no > do not send email, yes > send email.
3. Go to SMTP_server column and edit default value. Note: SMTP value by default is smtp.gmail.com.
4. Go to port column and change default value. Note: port value by default is 587.

  ###B: Sender configurations.
1. Sender confiigurations (used for email login + sendEmail function): Open config.csv file and edit following values/columns: sender (email address), userName, userPassword. 
2. During script run-time, if you not provided sender configs + isSilent = False, you will see following question: "Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no): "
3. Enter "2" if you not intrested in sending email.

  ### NOTE: In case isSilen is TRUE + isSend is TRUE + you not provided sender configurations >>> script will continue to run BUT email notifications will not be sent.

  ###C: test_sendEmail function.
1. There is test_sendEmail function for debuging and fine-tuning porposes.
2. In order to activate this function open config.csv file.
3. Go to test_sendEmail column and change value to "yes".
4. Go to test_emailAddress and provide your test email account.

PLEASE NOTE: 
- In case you need to debug the script or during script fine-tuning it is recommended to look for output from: ip_list.csv, logging.log (change log level to DEBUG mode).
- When test_sendEmail is active all email notifications will be sent to test_emailAddress.
- sendEmail and test_sendEmail will be disabled if you not provided test_emailAddress when test_sendEmail is active.
- sendEmail and test_sendEmail functions are disabled by default.

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

