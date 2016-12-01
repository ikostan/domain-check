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
import datetime                                 # Date/Time

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
# file_path = os.path.join(os.getcwd(), Email_file)        # Path to config.txt


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
Email_file = get_file_path('email.csv')           #Email notification template

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
print "\n=====================================================================================\n"
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
    if "['Registrant Email:" in email:
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
    elif "['Tech Email:" in email:
        old = "['Tech Email:"                           #string to replase - condition 6.1
        email = str.replace(email, old, new)            #replace method
        if "']" in email:                               #string to replase - condition 6.2
            old = "']"                                  #string to replase
            email = str.replace(email, old, new)        #replace method
            if " " in email:                            #to strip all whitespace from string
                old = " "                               #string to replase
                email = str.replace(email, old, new)    #replace method
    elif "['Error code:" in email:                      #Failed receive WHOIS due to error
        old = "['Error code:"                                      #string to replase - condition 7.1
        email = str.replace(email, old, new)            #replace method
        if "']" in email:                               #string to replase - condition 7.2
            old = "']"                                  #string to replase
            email = str.replace(email, old, new)        #replace method
            if " " in email:                            #to strip all whitespace from string
                old = " "                               #string to replase
                email = str.replace(email, old, new)    #replace method      
    elif "['    Email:" in email:                      #Failed receive WHOIS due to error
        old = "['    Email:"                                      #string to replase - condition 8.1
        email = str.replace(email, old, new)            #replace method
        if "']" in email:                               #string to replase - condition 8.2
            old = "']"                                  #string to replase
            email = str.replace(email, old, new)        #replace method
            if " " in email:                            #to strip all whitespace from string
                old = " "                               #string to replase
                email = str.replace(email, old, new)    #replace method
    return email                                        #return the result
    logging.info('Finish clean_email function')


#Clean name string:
def clean_name(name):
    logging.info('Start clean_name function')
    new_name = ""                                               #A new string #1
    new_name2 = " "                                             #A new string #2
    if ("['Admin Name:" in name) or ("['person:" in name) or ("['Owner Name    :" in name):
        if "['Admin Name:" in name:
            old_name = "['Admin Name: "                             #String to replase - condition 1.1
            name = str.replace(name, old_name, new_name)            #Replace method
            if "']" in name:                                        #String to replase - condition 1.2
                old_name = "']"                                     #String to replase
                name = str.replace(name, old_name, new_name)        #Replace method
                name = name.strip()                                 #remove extra spaces
                if "', '" in name:                                  #String to replase - condition 1.2.1
                    old_name = "', '"                                   #String to replase
                    name = str.replace(name, old_name, new_name2)       #Replace method

        elif "['person:" in name:                                   #Failed receive WHOIS due to error
            old_name = "['person: "                                 #string to replase - condition 2.1
            name = str.replace(name, old_name, new_name)            #replace method
            if "']" in name:                                        #string to replase - condition 2.2
                old_name = "']"                                     #string to replase
                name = str.replace(name, old_name, new_name)        #replace method
                name = name.strip()                                 #remove extra spaces
                if "', '" in name:                                  #String to replase - condition 1.2.1
                    old_name = "', '"                                   #String to replase
                    name = str.replace(name, old_name, new_name2)       #Replace method

        elif "['Owner Name    :" in name:                           #Failed receive WHOIS due to error
            old_name = "['Owner Name    :"                          #string to replase - condition 3.1
            name = str.replace(name, old_name, new_name)            #replace method
            if "']" in name:                                        #string to replase - condition 3.2
                old_name = "']"                                     #string to replase
                name = str.replace(name, old_name, new_name)        #replace method
                name = name.strip()                                 #remove extra spaces
                if "', '" in name:                                  #String to replase - condition 1.2.1
                    old_name = "', '"                                   #String to replase
                    name = str.replace(name, old_name, new_name2)       #Replace method
                    
    else:
        name = "NOT FOUND"                                          #Admin Name not found
    
    if name == "Whois Privacy Protection Service by VALUE-DOMAIN":
        name = "PROTECTED"
    elif name == "Registration Private":
        name = "PROTECTED"

    return name                                                     #return the result
    logging.info('Finish clean_name function')

# Read from csv file function:
def read_csv(domainList_file):
    logging.info('Start domainList_file function')
    domains = {} #a smart list of domain names - it has an index starts from 1
    i = 0
    with codecs.open(domainList_file, 'rU', 'utf-8-sig') as csvFile: #Open file
        reader = csv.reader(csvFile)                                 #Read file
        print "\n=====================================================================================\n"
        print '\nConverting domain names to IP addresses...\n'
        logging.info('Converting domain names to IP addresses...')
        for row in reader:
            if not "Domain_name" in row:                       #Print all except "Domain name" label
                domainName = row[0]                            #Print each row from CSV file - only from domain name column: row[0]
                if "http" in domainName:                       #Call get_domain_name function in case when url contains http/https
                    domainName = get_domain_name(domainName)   #Get Top Level Domain Name
                i += 1                                         #indexing
                domains[i] = domainName
                '''
                try:
                    domainIP = socket.gethostbyname(domains[i])    #Get website IP
                except (socket.gaierror):
                    print "\nOops!  Name or service not known..."
                    domainIP = "unknown host"
                    logging.info('Name or service not known...')
                    logging.debug('INVALID HOSTNAME: unknown host', domainName, ' > ', domainIP)

                if domainIP != "unknown host":
                    print domainName, ' > ', domainIP
                    logging.debug(domainName, ' > ', domainIP)
                else:
                    print domainName, ' > ', domainIP, "\n"
                '''                   
    return domains
    #return ip_list
    csvFile.Close()
    logging.info('Finish domainList_file function')

domains = read_csv(domainList_file) #call read_csv function in order to create smart domains list
n = len(domains)                    #A total number of domain names in the list
print "\n=====================================================================================\n"
print '\nA total number of domain names in the test list: ', n, '\n'
print "\n=====================================================================================\n"
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


#Get Admin Name from WHOIS_file function:
def get_cName(WHOIS_file):
    logging.info('Start get_cName function')
    cNames = ""
    with codecs.open(WHOIS_file,'rU','utf-8-sig') as csvWHOIS: #Open file
        read_whois = csv.reader(csvWHOIS) #Read file
        i=0
        for row in read_whois:
            test_string = str(row)
            if test_string.find('Admin Name:') != -1:  #Find 'Admin Name:' in row
                cNames = test_string
            elif test_string.find('Owner Name') != -1: #Find 'Owner Name' in row
                cNames = test_string
            elif test_string.find('person:') != -1:    #Find 'person:' in row
                cNames = test_string

            i += 1
    return cNames
    csvWHOIS.Close()
    logging.info('Finish get_cName function')


#Read and concatinate Email notification:
def get_eTemplate(Email_file, name, domain):
    logging.info('Start get_eTemplate function')
    eTemplate = ""
    with codecs.open(Email_file,'rU','utf-8-sig') as csvTEMPLATE:   #Open file
        read_template = csv.reader(csvTEMPLATE)                     #Read file
        if name == 'NOT FOUND' or name == 'PROTECTED':      
            eTemplate = "Hello " + domain + "," + "\n"
        else:
            eTemplate = "Hello " + name + "," + "\n"
        for row in read_template:
            eTemplate = eTemplate + "\n" + ''.join(row)             #convert list object to string

    return eTemplate
    csvTEMPLATE.Close()
    logging.info('Finish get_eTemplate function')


# Send an Email function:
def send_Email(recipient, name, domain):
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
    msg['Subject'] = "Web-admin notification"
    msg['From'] = sender
    msg['To'] = recipient

    # Create the body of the message (a plain-text and an HTML version).
    text = get_eTemplate(Email_file, name, domain) #a plain-text

    # Record the MIME types of both parts - text/plain and text/html.
    part1 = MIMEText(text, 'plain')

    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    msg.attach(part1)

    logging.info('Ask for username')
    username = raw_input("Please enter your username: ") #ask for username
    logging.info('Ask for password')

    import getpass
    password = getpass.getpass()        #ask for password
    #print 'You entered:', password     #for debuging only 

    logging.info('Login in to email account')
    mail.login(username, password)

    logging.info('Send Email')
    mail.sendmail(sender, recipient, msg.as_string())
    mail.quit()
    logging.info('Finish send_Email function')


sendEmail = raw_input("Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no): ")
print "\n=====================================================================================\n"
logging.info('Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no)')
logging.debug('Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no)', sendEmail)

isSent = False

# Write to csv file function:
def write_csv(ipList_file):
    logging.info('Start write_csv function')
    invalidName = {}
    invalidNum = 1
    with codecs.open(ipList_file,'a','utf-8-sig') as csvFile2: #Open file
        writer = csv.writer(csvFile2) #Write to file
        i = 1                         #start index from 1
        for row in domains:           #start loop
            
            try:
                domainIP = socket.gethostbyname(domains[i]) #Get IP
            except (socket.gaierror):
                print "Oops!  Name or service not known..."
                domainIP = "unknown host"
                logging.info('Name or service not known...')
                logging.debug('INVALID HOSTNAME: unknown host: ', domainIP)

            if domainIP != "unknown host":
                print domains[i], ' > ', domainIP
                logging.debug(domains[i], ' > ', domainIP)
            else:
                print domains[i], ' > ', domainIP

            isValid = 0
            with codecs.open(VCN_IP_RANGE,'r','utf-8-sig') as csvFile3:
                reader = csv.reader(csvFile3)
                for row in reader:
                    if row[0] == domainIP: #verify if domain IP is in VCN range
                        print 'Found valid IP: ' + domains[i] + ': '+ row[0] + " matches " + domainIP, "\n"
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

                print '>>> Found invalid IP: ' + domains[i] + ': '+ domainIP + ' <<<', "\n"
                invalidName[invalidNum] = domains[i]
                invalidNum += 1
                logging.info('Found invalid IP:')
                logging.debug('Found invalid IP: ' + domains[i] + ': '+ domainIP)

                site_whois = get_whois(domain_url) #call get_whois function in order to create WHOIS.csv file with whois data
                
                time.sleep(1) # Wait for x second
                
                emails = get_email(WHOIS_file)     #call get_email function in order to extract email from whois data
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

                emails[0] = clean_email(emails[0]) #call clean_email function in order to clean up all the garbage from the emails string
                emails[1] = clean_email(emails[1]) #call clean_email function in order to clean up all the garbage from the emails string
                emails[2] = clean_email(emails[2]) #call clean_email function in order to clean up all the garbage from the emails string
                emails[3] = clean_email(emails[3]) #call clean_email function in order to clean up all the garbage from the emails string
                emails[4] = clean_email(emails[4]) #call clean_email function in order to clean up all the garbage from the emails string
                
                Admin_Name = get_cName(WHOIS_file)
                Admin_Name = clean_name(Admin_Name) #call clean_name function in order to clean up all the garbage from the Admin_Name string

                #sendEmail = raw_input("Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no): ") 
                #logging.info('Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no)')
                #logging.debug('Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no)', sendEmail)

                if sendEmail == "1":
                    send_Email(emails[1], Admin_Name, domains[i]) #call send_Email function (recipient, name, domain, isSent)  
                    isSent = True
                    logging.info('Email sent')
                    logging.debug('Email sent', isSent)
                else:
                    isSent = False
                    logging.info('Email not sent')
                    logging.debug('Email not sent', isSent)
     
                now = datetime.datetime.now() #Date/Time stamp
                timeNow = now.strftime("%Y-%m-%d %H:%M:%S") # Current date and time using strftime (for example: 2014-09-26 16:34)
                logging.info('date/time')
                logging.debug('Date/Time: ', now.strftime("%Y-%m-%d %H:%M"))

                #Invalid IP - write domain name, ip address and INVALID comment
                if emails[0] == "null":
                    writer.writerow([domains[i], domainIP, 'invalid', emails[0], emails[1], emails[2], emails[3], emails[4], Admin_Name, 'not implemented', 'FAILED: INVALID EMAL', timeNow])
                    #logs
                    logging.info('Writing: domains[i], domainIP, invalid, emails[0], emails[1], emails[2], emails[3], emails[4], client name, address, FAILED: INVALID EMAL, Date/Time')
                    logging.debug(domains[i], domainIP, 'invalid', emails[0], emails[1], emails[2], emails[3], emails[4], Admin_Name, 'address', 'FAILED: INVALID EMAL', timeNow)
                else:
                    writer.writerow([domains[i], domainIP, 'invalid', emails[0], emails[1], emails[2], emails[3], emails[4], Admin_Name, 'not implemented', isSent, timeNow])
                    #logs
                    logging.info('Writing: domains[i], domainIP, invalid, emails[0], emails[1], emails[2], emails[3], emails[4], client name, address, true???, Date/Time')
                    logging.debug(domains[i], domainIP, 'invalid', emails[0], emails[1], emails[2], emails[3], emails[4], Admin_Name, 'address', isSent, timeNow)        
                
                os.remove(WHOIS_file) #remove WHOIS_file
            else:
                #write domain name and ip address, ip address and VALID comment
                writer.writerow([domains[i], domainIP, 'valid', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a','False', timeNow])  
                #logs
                logging.info('Writing:[domains[i], domainIP, valid, n/a, n/a, n/a, n/a, n/a, n/a, n/a, false, date/time')
                logging.debug(domains[i], domainIP, 'valid', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'False', timeNow)

            i += 1      #increase index by 1
    return invalidName
    csvFile2.close()    #close the file
    logging.info('Finish write_csv function')
    
invalidName = write_csv(ipList_file) #call write_csv function

invalidDomains = len(invalidName)
validDomains = n - len(invalidName)

print "\n=====================================================================================\n"

print "Summary:\n"
print '1) A total number of validated IPs: ', num, '\n'
print '2) A total number of domain names in the test list: ', n, '\n'
print '3) A total number of invalid domain names in the test list: ', invalidDomains, '\n'
print '4) A total number of valid domain names in the test list: ', validDomains, '\n'
print '5) Send an eMail notification to all administrators of invalid domains: ', isSent, '\n'

os.remove(VCN_IP_RANGE) #remove VCN_IP_RANGE
print "\n=====================================================================================\n"
print 'FINISHED'
logging.info('FINISHED')

#THE END