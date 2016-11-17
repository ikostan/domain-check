#!/usr/local/bin/python

import sys
import os
import logging
import random
import csv                                      # Allows handle CSV files
import codecs                                   # UTF-8 encoded BOM. in order to get rid of \xef\xbb\xbf in a list read from a file
import socket                                   # Low-level networking interface
import numpy                                    # Data manipulation
import shutil                                   # High-level file operations
import tld                                      # Extracts the top level domain (TLD) from the URL given (pip install tld).
import time                                     # This module provides various time-related functions
import smtplib                                  # Import smtplib for the actual sending function
from email.mime.text import MIMEText            # Import the email modules we'll need
from email.mime.multipart import MIMEMultipart  # Allows to send a MIME message
#from mailer import Mailer
#from mailer import Message


# System variables:
# currentDirectory = os.getcwd()                            # Get current working directory
# 'domains.csv'                                             # Filename for domain/url list
# 'ip_list.csv'                                             # Filename for ip list
# 'logging.log'                                             # Filename for logs
# 'template.csv'                                            # File name for the template file
# 'vcn_ip_range.csv'                                        # Filename for list with VCN IP range
# file_path = os.path.join(os.getcwd(), domainList_file)    # Path to domains.cs
# file_path = os.path.join(os.getcwd(), ipList_file)        # Path to ip_list.csv
# file_path = os.path.join(os.getcwd(), template_file)      # Path to template.csv
# file_path = os.path.join(os.getcwd(), ipList_file)        # Path to vcn_ip.range.csv
# file_path = os.path.join(os.getcwd(), Config_file)        # Path to config.txt


def get_file_path(fileName):
    currentDirectory = os.getcwd() # get current working directory
    file_path = os.path.join(os.getcwd(), fileName)  #Path to CSV file
    print("\nFile name: " + fileName + "\nFile directory: " + file_path + "\n")
    return file_path

domainList_file = get_file_path('domains.csv')    #Domain list file
ipList_file = get_file_path('ip_list.csv')        #IP list file
template_file = get_file_path('template.csv')     #Empty template file
LOG_FILENAME = get_file_path('logging.log')       #Log file
VCN_IP_RANGE = get_file_path('vcn_ip_range.csv')  #List with vcn ips
WHOIS_file = get_file_path('WHOIS.csv')           #List with WHOIS results
Config_file = get_file_path('config.txt')         #Config file: SMTP server + port

# Write log messages to a log file and the console at the same time:
if os.path.exists(LOG_FILENAME):
    print "Log file exists, no need to created a new one"
else:
   open(LOG_FILENAME, 'w')

logger = logging.getLogger(LOG_FILENAME)

logging.basicConfig(filename=LOG_FILENAME, filemode='a', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

logging.debug('This is a debug message')
logging.info('This is an info message')
logging.warning('This is a warning message')
logging.error('This is an error message')
logging.critical('This is a critical error message')


#Create/copy files and display the path:
shutil.copyfile(template_file, ipList_file)  #Copy clean template file to ipList_file
print '\nA new CSV file is created under: ', ipList_file, '\n'
logging.info('A new CSV file is created under: ')
logging.debug('A new CSV file is created under: ', ipList_file)

logging.info('START')
# Create a full list of VCN ips:
def create_vcn_ip_csv(VCN_IP_RANGE):
    VCN_ip_list = {}
    ip = 1                              #Start index from 1
    with codecs.open(VCN_IP_RANGE,'w','utf-8-sig') as csvVCNip: #Open file
        writer = csv.writer(csvVCNip)   #Read file
        startIP = '0.0.0.'
        while ip < 255:
            IPstr = str(ip)             #Convert integer to string
            vcnIP = startIP + IPstr
            writer.writerow([vcnIP])    #Write generated ip address
            VCN_ip_list[ip] = vcnIP
            ip += 1                     #Increase index by 1
    return VCN_ip_list
    csvVCNip.close()                    #Close the file
    
VCN_ip_list = create_vcn_ip_csv(VCN_IP_RANGE) #Call create_vcn_ip_csv function

num = len(VCN_ip_list) #A total number of ips in the list
print '\nA total number of IPs to validate: ', num, '\n'
logging.info('A total number of IPs to validate:')
logging.debug('A total number of IPs to validate: ', num)


# Implement Top Level Domain Name:
from tld import get_tld

def get_domain_name(url):
    logging.info('Start get_domain_name function')
    domain_name = get_tld(url) #Get Top Level Domain Name
    return domain_name
    logging.info('Finish get_domain_name function')


#Clean email string:
def clean_email(email):
    logging.info('Start clean_email function')
    new = ""                                            #A new string
    if "Registrant Email:" in email:
        old = "['Registrant Email:"                     #String to replase - condition 1.1
        email = str.replace(email, old, new)            #Replace method
        if "']" in email:                               #String to replase - condition 1.2
            old = "']"                                  #String to replase
            email = str.replace(email, old, new)        #Replace method
            if " " in email:                            #Strip all whitespace from string
                old = " "                               #String to replase
                email = str.replace(email, old, new)    #Replace method
    elif "['Registrar Abuse Contact Email:" in email:
        old = "['Registrar Abuse Contact Email:"        #String to replase - condition 2.1
        email = str.replace(email, old, new)            #Replace method
        if "']" in email:                               #String to replase - condition 2.2
            old = "']"                                  #String to replase
            email = str.replace(email, old, new)        #Replace method
            if " " in email:                            #Strip all whitespace from string
                old = " "                               #String to replase
                email = str.replace(email, old, new)    #Replace method
    elif "['e-mail:" in email:
        old = "['e-mail:"                               #String to replase - condition 3.1
        email = str.replace(email, old, new)            #replace method
        if "']" in email:                               #string to replase - condition 3.2.1
            old = "']"                                  #string to replase
            email = str.replace(email, old, new)        #replace method
            if " AT " in email:                         #string to replase - condition 3.2.2
                old = " AT "                            #string to replase
                new_1 = "@"
                email = str.replace(email, old, new_1)  #Replace method
                if " " in email:                        #to strip all whitespace from string
                    old = " "
                    email = str.replace(email, old, new)#replace method   
    elif "['Admin Email:" in email:
        old = "['Admin Email:"                          #string to replase - condition 4.1
        email = str.replace(email, old, new)            #replace method
        if "']" in email:                               #string to replase - condition 4.2
            old = "']"                                  #string to replase
            email = str.replace(email, old, new)        #replace method
            if " " in email:                            #to strip all whitespace from string
                old = " "                               #string to replase
                email = str.replace(email, old, new)    #replace method
    elif "['Registrant Email:" in email:
        old = "['Registrant Email:"                     #string to replase - condition 5.1
        email = str.replace(email, old, new)            #replace method
        if "']" in email:                               #string to replase - condition 5.2
            old = "']"                                  #string to replase
            email = str.replace(email, old, new)        #replace method
            if " " in email:                            #to strip all whitespace from string
                old = " "                               #string to replase
                email = str.replace(email, old, new)    #replace method
    elif "['Tech Email:" in email:
        old = "['Tech Email:"                           #string to replase - condition 6.1
        email = str.replace(email, old, new)            #replace method
        if "']" in email:                               #string to replase - condition 6.2
            old = "']"                                  #string to replase
            email = str.replace(email, old, new)        #replace method
            if " " in email:                            #to strip all whitespace from string
                old = " "                               #string to replase
                email = str.replace(email, old, new)    #replace method    
      
    return email                                        #return the result
    logging.info('Finish clean_email function')


# Read from csv file function:
def read_csv(domainList_file):
    logging.info('Start domainList_file function')
    domains = {} #a smart list of domain names - it has an index starts from 1
    i = 0
    with codecs.open(domainList_file, 'rU', 'utf-8-sig') as csvFile: #Open file
        reader = csv.reader(csvFile)                                 #Read file
        print '\nConverting domain names to IP addresses:\n'
        logging.info('Converting domain names to IP addresses:')
        for row in reader:
            if not "Domain_name" in row:                       #Print all except "Domain name" label
                domainName = row[0]                            #Print each row from CSV file - only from domain name column: row[0]
                if "http" in domainName:                       #Call get_domain_name function in case when url contains http/https
                    domainName = get_domain_name(domainName)   #Get Top Level Domain Name
                i += 1                                         #indexing
                domains[i] = domainName
                domainIP = socket.gethostbyname(domains[i])    #Get website IP
                print domainName, ' > ', domainIP
                logging.debug(domainName, ' > ', domainIP)
    return domains
    return ip_list
    csvFile.Close()
    logging.info('Finish domainList_file function')

domains = read_csv(domainList_file) #call read_csv function in order to create smart domains list
n = len(domains)                    #A total number of domain names in the list
print '\nA total number of domain names in the test list: ', n, '\n'
logging.info('A total number of domain names in the test list: ')
logging.debug('A total number of domain names in the test list: ', n)


# WHOIS function:
def get_whois(url):
    logging.info('Start get_whois function')
    command = "whois " + url                                        #run whois command from CLI
    process = os.popen(command)                                     #open a new CLI as a process
    whois_result = str(process.read())                              #get WHOIS result from the CLI and save is as a string "whois_result"
    with codecs.open(WHOIS_file, 'w','utf-8-sig') as file_handler:  #write results to a file
        for row in whois_result:
            file_handler.write(row)              
    return whois_result
    logging.info('Finish get_whois function')


#Read WHOIS_file file in order to create smart whois_rows list:
def read_whois(WHOIS_file):
    logging.info('Start read_whois function')
    i = 0
    whois_rows = {}
    with codecs.open(WHOIS_file,'rU','utf-8-sig') as csvWHOIS1: #Open file
                read_whois = csv.reader(csvWHOIS1) #Read file
                for row in read_whois:
                    whois_rows[i] = row
                    i += 1
    return whois_rows
    csvWHOIS1.Close()
    logging.info('Finish read_whois function')


#Get Email from WHOIS_file function:
def get_email(WHOIS_file):
    logging.info('Start get_email function')
    emails = {}
    with codecs.open(WHOIS_file,'rU','utf-8-sig') as csvWHOIS: #Open file
        read_whois = csv.reader(csvWHOIS) #Read file
        i=0
        emails_id = 0
        for row in read_whois:
            #if '% The data in the WHOIS database of the .il registry is provided' in row:
            test_string = str(row)
            if test_string.find('e-mail:') != -1: #Find 'e-mail:' in row
                emails[emails_id] = test_string
                emails_id += 1
            elif test_string.find('Email:') != -1: #Find 'e-mail:' in row
                emails[emails_id] = test_string
                emails_id += 1
            i += 1
    return emails
    csvWHOIS.Close()
    logging.info('Finish get_email function')


# Send an Email function:
def send_Email(recipient):
    logging.info('Start send_Email function')

    # Send the message via local SMTP server.
    # Read config file:
    logging.info('Read config file')

    read_config = open(Config_file, 'r') #Open file

    SMTP_server = read_config.readline()
    SMTP_server = SMTP_server.strip("\xef\xbb\xbf")
    SMTP_server = SMTP_server.strip("\r\n")

    port = read_config.readline()
    port = port.strip("\r\n")

    sender = read_config.readline()
    sender = sender.strip("\r\n")

    mail = smtplib.SMTP(SMTP_server, port)
    mail.ehlo()
    mail.starttls()

    # Create message container - the correct MIME type is multipart/alternative.
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Link"
    msg['From'] = sender
    msg['To'] = recipient

    # Create the body of the message (a plain-text and an HTML version).
    text = "Hello.\nThis is sample text." #a plain-text
    #an HTML version
    html = """\ 
    <html>
    <head></head>
    <body>
        <p>
            Hello.<br>
            This is sample text.
        </p>
    </body>
    </html>
    """

    # Record the MIME types of both parts - text/plain and text/HTML.
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    # Attach parts into message container.
    # According to RFC 2046, the last part of a multi-part message, in this case
    # the HTML message, is best and preferred.
    msg.attach(part1)
    msg.attach(part2)

    logging.info('Ask for user-name')
    username = raw_input("Please enter your user-name: ") #ask for user-name
    logging.info('Ask for password')

    import getpass
    password = getpass.getpass()        #ask for password
    #print 'You entered:', password     #for debugging only 

    logging.info('Login in to email account')
    mail.login(username, password)

    logging.info('Send Email')
    mail.sendmail(sender, recipient, msg.as_string())
    mail.quit()
    logging.info('Finish send_Email function')


# Write to csv file function:
def write_csv(ipList_file):
    logging.info('Start write_csv function')
    with codecs.open(ipList_file,'a','utf-8-sig') as csvFile2: #Open file
        writer = csv.writer(csvFile2) #Write to file
        i = 1                         #start index from 1
        for row in domains:           #start loop
            domainIP = socket.gethostbyname(domains[i]) #Get IP
            isValid = 0
            with codecs.open(VCN_IP_RANGE,'r','utf-8-sig') as csvFile3:
                reader = csv.reader(csvFile3)
                for row in reader:
                    if row[0] == domainIP: #verify if domain IP is in VCN range
                        print 'Found valid IP: ' + domains[i] + ': '+ row[0] + " matches " + domainIP
                        logging.info('Found valid IP: ')
                        logging.debug('Found valid IP: ' + domains[i] + ': '+ row[0] + " matches " + domainIP)
                        isValid = 1
            csvFile3.close() #close the file

            if isValid == 0:
                # Removing www.
                # This is a bad idea, because www.python.org could 
                # resolve to something different than python.org
                from urlparse import urlsplit  # Python 2
                import re #Regular expression operations
                if domains[i].startswith('www.'): #remove www.
                    domain_url = domains[i][4:]
                elif domains[i].startswith('www2.'): #remove www2.
                    domain_url = domains[i][5:]
                elif domains[i].startswith('www3.'): #remove www3.
                    domain_url = domains[i][5:]                
                elif domains[i].startswith('www4.'): #remove www4.
                    domain_url = domains[i][5:]
                else :
                    domain_url = domains[i]          #do nothing

                print '>>> Found invalid IP: ' + domains[i] + ': '+ domainIP + ' <<<'
                logging.info('Found invalid IP:')
                logging.debug('Found invalid IP: ' + domains[i] + ': '+ domainIP)

                site_whois = get_whois(domain_url) #call get_whois function in order to create WHOIS.csv file with WHOIS data
                
                time.sleep(1) # Wait for x second
                
                emails = get_email(WHOIS_file)     #call get_email function in order to extract email from WHOIS data
                emails_num = len(emails)           #get total number of emails
                if emails_num == 0:
                     emails[0] = 'null'
                     emails[1] = 'null'
                     emails[2] = 'null'
                     emails[3] = 'null'
                     emails[4] = 'null'
                elif emails_num == 1:
                     emails[1] = 'null'
                     emails[2] = 'null'
                     emails[3] = 'null'
                     emails[4] = 'null'
                elif emails_num == 2:
                     emails[2] = 'null'
                     emails[3] = 'null'
                     emails[4] = 'null'
                elif emails_num == 3:
                     emails[3] = 'null'
                     emails[4] = 'null'
                elif emails_num == 4:
                     emails[4] = 'null'

                emails[0] = clean_email(emails[0]) #call clean_email function in order to clean up all the garbage from the string
                emails[1] = clean_email(emails[1]) #call clean_email function in order to clean up all the garbage from the string
                emails[2] = clean_email(emails[2]) #call clean_email function in order to clean up all the garbage from the string
                emails[3] = clean_email(emails[3]) #call clean_email function in order to clean up all the garbage from the string
                emails[4] = clean_email(emails[4]) #call clean_email function in order to clean up all the garbage from the string
                
                #Invalid IP - write domain name, IP address and INVALID comment
                writer.writerow([domains[i], domainIP, 'invalid', emails[0], emails[1], emails[2], emails[3], emails[4], 'true', 'not implemented', 'not implemented'])

                send_Email(emails[1]) #call send email function
                
                #logs
                logging.info('Writing: domains[i], domainIP, invalid, emails[0], emails[1], emails[2], emails[3], emails[4], true, not implemented, not implemented')
                logging.debug(domains[i], domainIP, 'invalid', emails[0], emails[1], emails[2], emails[3], emails[4], 'true', 'not implemented', 'not implemented')
                os.remove(WHOIS_file) #remove WHOIS_file
            else:
                #write domain name and IP address, IP address and VALID comment
                writer.writerow([domains[i], domainIP, 'valid', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'false', 'n/a', 'not implemented'])  
                #logs
                logging.info('Writing:[domains[i], domainIP, valid, n/a, n/a, n/a, n/a, n/a, false, n/a, not implemented')
                logging.debug(domains[i], domainIP, 'valid', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'false', 'n/a', 'n/a')

            i += 1      #increase index by 1
    csvFile2.close()    #close the file
    logging.info('Finish write_csv function')
    
domains = write_csv(ipList_file) #call write_csv function

os.remove(VCN_IP_RANGE) #remove VCN_IP_RANGE
print 'FINISHED'
logging.info('FINISHED')

#THE END
