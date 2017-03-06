#!/usr/local/bin/python

# Domain-check project URL: https://github.com/ikostan/domain-check

# v_5.2

import sys
import os
import os.path
import logging                                  # Create logs
import random                                   
import csv                                      # Allows handle CSV files
import codecs                                   # UTF-8 encoded BOM. in order to get rid of \xef\xbb\xbf in a list read from a file
import socket                                   # Low-level networking interface
import numpy                                    # Data manipulation
import shutil                                   # High-level file operations
import tld                                      # Extracts the top level domain (TLD) from the URL given (pip install tld).
from tld import get_tld
import time                                     # This module provides various time-related functions
import smtplib                                  # Import smtplib for the actual sending function
from email.mime.text import MIMEText            # Import the email modules we'll need
from email.mime.multipart import MIMEMultipart  # Allows to send a MIME message
import datetime                                 # Date/Time
import math                                     # It provides access to the mathematical functions defined by the C standard.
from validate_email import validate_email       # Validate_email is a package for Python that check if an email is valid
from urlparse import urlsplit                   # Python 2
import re                                       # Regular expression operations


# System variables:

# currentDirectory = os.getcwd()                            # Get current working directory

# 'domains.csv'                                             # Filename for domain/url list
# 'ip_list.csv'                                             # Filename for ip list
# 'logging.log'                                             # Filename for logs
# 'template.csv'                                            # Filename for the template file
# 'vcn_ip_range.csv'                                        # Filename for list with VCN IP range
# 'WHOIS.csv'                                               # Filename for list with vcn ips
# 'config.txt'                                              # Filename for config file: SMTP server, port, UNP and more.....
# 'email.csv'                                               # Filename for Email notification template

# file_path = os.path.join(os.getcwd(), domainList_file)    # Path to domains.cs
# file_path = os.path.join(os.getcwd(), ipList_file)        # Path to ip_list.csv
# file_path = os.path.join(os.getcwd(), template_file)      # Path to template.csv
# file_path = os.path.join(os.getcwd(), LOG_FILENAME)       # Path to logging.log
# file_path = os.path.join(os.getcwd(), VCN_IP_RANGE)       # Path to vcn_ip_range.csv
# file_path = os.path.join(os.getcwd(), WHOIS_file)         # Path to WHOIS.csv
# file_path = os.path.join(os.getcwd(), Config_file)        # Path to config.txt
# file_path = os.path.join(os.getcwd(), Email_file)         # Path to email.csv


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
Config_file = get_file_path('config.csv')         #Config file: SMTP server + port
Email_file = get_file_path('email.csv')           #Email notification template

# Write log messages to a log file and the console at the same time:
if os.path.exists(LOG_FILENAME):
    print "Log file exists, no need to created a new one"
else:
   open(LOG_FILENAME, 'w')

logger = logging.getLogger(LOG_FILENAME)

try:
    logging.basicConfig(filename=LOG_FILENAME, filemode='a', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
except Exception as error:
    logging.debug('Logging config error:'  + str(error))
    logging.info('Logging config error')

logging.debug('This is a debug message')
logging.info('This is an info message')
logging.warning('This is a warning message')
logging.error('This is an error message')
logging.critical('This is a critical error message')


#Create/copy files and display the path:

try:
    shutil.copyfile(template_file, ipList_file)  #Copy clean template file to ipList_file
    print '\nA new CSV file is created under: ', ipList_file, '\n'
    logging.info('A new CSV file is created under: ')
    logging.debug('A new CSV file is created under: ' + str(ipList_file))
except Exception as ferror:
    logging.info('File copy error')
    logging.debug('Logging config error: ' + str(ferror))

logging.info('START')


#Global variables:
sender = ""                 #User email address
userName = ""               #User name from email account
userPassword = ""           #Password from email account

isSilent = ""               #Return boolean (True - silent mode is active, False - silent mode is not active)
isSent = False              #Return boolean (True - email notification has been sent, False - email notification has not been sent)
isEmailAccountValid = False #Return boolean (True - valid email account, False - invalid email account)
sendEmail = False           #In case you would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no. default)
SMTP_server = ""            #SMTP server name
port = ""                   #Mail Server port number
sender = ""                 #Sender email address

startIP = ""                #initial IP range
mailSentNum = 0             #Number of an eMail notifications sent to invalid domaina dministrators

test_sendEmail = False      #Send Email test mode >>> all email notifications will be transfered to >>> test_emailAddress
test_emailAddress = ""      #Email address >>> used in test_sendEmail mode only
sleep_Ping = 0              #Sleep (in sec): pause between pings
sleep_WHOIS = 0             #Sleep (in sec): pause between WHOIS requests
sleep_sendEmail = 0         #Sleep (in sec): pause between sending email
templateExist = False

#resolve_domain_ip = False   #Resolve domain IP (ping)

get_name_servers = False    #Get domain name servers from WHOIS responce
name_server_1 = "no"        #Name server to compare with
name_server_2 = "no"        #Name server to compare with
name_server_3 = "no"        #Name server to compare with
name_server_4 = "no"        #Name server to compare with
name_server_5 = "no"        #Name server to compare with
name_server_6 = "no"        #Name server to compare with

isValid_nameServer = False

#email patterns:
registrant_email = False
registrar_abuse_contact_email = False
e_mail = False
admin_email = False
tech_email = False
error_code = False
email_ = False
reseller_email = False

use_admin_name = False


def verifyMandatoryFiles(domainList_file, template_file, Config_file, Email_file, templateExist): #Verify all mandatory files
    
    if os.path.isfile(domainList_file) == False:
        print('Mandatory file dose not exist: ' + str(domainList_file) + '\n')
        logging.info('Mandatory file dose not exist: domains.csv')
        logging.debug('Mandatory file dose not exist: ' + str(domainList_file))
        sys.exit() #Terminating a Python script
    
    if os.path.isfile(template_file) == False:
        print('Mandatory file dose not exist: ' + str(template_file) + '\n')
        logging.info('Mandatory file dose not exist: template.csv')
        logging.debug('Mandatory file dose not exist: ' + str(template_file))
        sys.exit() #Terminating a Python script

    if os.path.isfile(Config_file) == False:
        print('Mandatory file dose not exist: ' + str(Config_file) + '\n')
        logging.info('Mandatory file dose not exist: config.txt')
        logging.debug('Mandatory file dose not exist: ' + str(Config_file))
        sys.exit() #Terminating a Python script

    if os.path.isfile(Email_file) == False:
        print('Mandatory file dose not exist: ' + str(Email_file) + '\n')
        logging.info('Mandatory file dose not exist: email.csv')
        logging.debug('Mandatory file dose not exist: ' + str(Email_file))
        templateExist = False
    else:
        templateExist = True

    return templateExist


templateExist = verifyMandatoryFiles(domainList_file, template_file, Config_file, Email_file, templateExist)

def setConfigs(Config_file): #Read configurations file

    print "\n=====================================================================================\n"
    logging.info('Reading config.csv file')
    logging.debug('Reading config.csv file. File path: ' + str(Config_file))

    #with codecs.open(Config_file,'r','utf-8-sig') as mySettings: #Open file
    with open(Config_file, 'r') as mySettings: #Open file        
        myReader = csv.reader(mySettings, delimiter=',')   #Read file
        myReader.next()                     #Skip first row

        for row in myReader: #Get silentMode value
            silentMode = row[0]
            if silentMode.upper() == "NO" or silentMode.upper() == "FALSE":
                isSilent = False
            elif silentMode.upper() == "YES" or silentMode.upper() == "TRUE":
                isSilent = True
            else:
                print ('Abort script execution due to invalid configurations. Please check "isSilent" value in config.csv file.')
                logging.info('Abort script execution due to invalid configurations. Please check "isSilent" value in config.csv file.')
                logging.debug('Abort script execution due to invalid configurations. Please check "isSilent" value in config.csv file: ' + str(Config_file))
                sys.exit() #abort script execution due to invalid configurations

        #for row in myReader: #Get sendEmail value
            notificationMode = (row[1])
            if notificationMode.upper() == "NO" or notificationMode.upper() == "FALSE":
                sendEmail = False
            elif notificationMode.upper() == "YES" or notificationMode.upper() == "TRUE":
                sendEmail = True
            else:
                sendEmail = False
                print ('Email notification canceled due to invalid "sendEmail" value.')
                logging.info('Email notification canceled due to invalid "sendEmail" value.')
                logging.debug('Email notification canceled due to invalid "sendEmail" value. Configuration changed: sendEmail = ' + str(sendEmail))

        #for row in myReader: #Get SMTP_server value
            smtpMode = (row[2])
            if smtpMode == "" or smtpMode == None:
                SMTP_server = ""                   
                print ('Found invalid parameter: Please check "SMTP_server" value in config.csv file.')
                logging.info('Found invalid parameter: Please check "SMTP_server" value in config.csv file.')
                logging.debug('Found invalid parameter: Please check "SMTP_server" value in config.csv file: ' + str(Config_file))
            else:
                SMTP_server = smtpMode
                logging.info('SMTP server address found.')
                logging.debug('SMTP server: ' + str(SMTP_server))
                                                
        #for row in myReader: #Get port value
            myPort = (row[3])
            if myPort == "" or myPort == None or math.isnan(float(myPort)) == True:
                port = ""
                print ('Found invalid parameter: Please check "port" value in config.csv file.')
                logging.info('Found invalid parameter: Please check "port" value in config.csv file.')
                logging.debug('Found invalid parameter: Please check "port" value in config.csv file: ' + str(Config_file))
            else:
                port = myPort
                logging.info('SMTP server port number found.')
                logging.debug('SMTP server port: ' + str(port))
            
        #for row in myReader: #Get sender value
            if row[4] != "" and row[4] != None:
                sender = row[4]
            else:
                sender = ""

        #for row in myReader: #Get userName value
            if row[5] != "" and row[5] != None:
                userName = row[5]
            else:
                userName = ""
                print ('Found invalid parameter: Please check "userName" value in config.csv file.')
                logging.info('Found invalid parameter: Please check "userName" value in config.csv file.')
                logging.debug('Found invalid parameter: Please check "userName" value in config.csv file: ' + str(Config_file))

        #for row[6] in myReader: #Get userPassword value
            if row[6] != "" and row[6] != None:
                userPassword = row[6]
            else:
                userPassword = ""
                print ('Found invalid parameter: Please check "userPassword" value in config.csv file.')
                logging.info('Found invalid parameter: Please check "userPassword" value in config.csv file.')
                logging.debug('Found invalid parameter: Please check "userPassword" value in config.csv file: ' + str(Config_file))

        #for row[7] in myReader: #Get startIP value
            if (row[7]) != "" and (row[7]) != None:
                startIP = (row[7])
            else:
                startIP = "0.0.0."
                print ('Found invalid parameter: Please check "startIP" value in config.csv file.')
                logging.info('Found invalid parameter: Please check "startIP" value in config.csv file.')
                logging.info('Found invalid parameter: "startIP" value changed to: 0.0.0.')
                logging.debug('Found invalid parameter: Please check "startIP" value in config.csv file: ' + str(Config_file))               

        #for row[8] in myReader: #Get test_sendEmail value
            if (row[8]).upper() == "FALSE" or (row[8]).upper() == "NO":
                test_sendEmail = False
            elif (row[8]).upper() == "YES" or (row[8]).upper() == "TRUE":
                test_sendEmail = True
            else:
                test_sendEmail = False
                print ('Found invalid parameter: Please check "test_sendEmail" value in config.csv file.')
                logging.info('Found invalid parameter: Please check "test_sendEmail" value in config.csv file.')
                logging.info('Found invalid parameter: "test_sendEmail" value changed to: FALSE')
                logging.debug('Found invalid parameter: Please check "test_sendEmail" value in config.csv file: ' + str(Config_file))

        #for row[9] in myReader: #Get test_emailAddress value
            if (row[9]).upper() == "" or (row[9]).upper() == None:
                test_emailAddress = ""
            elif (row[9]).upper() != "" and (row[9]).upper() != None:
                if validate_email(row[9]) == True:   #Test if email address is valid
                    test_emailAddress = row[9]
                else:
                    test_emailAddress = ""
                    test_sendEmail = False
                    print ('Found invalid parameter: Please check "test_emailAddress" value in config.csv file.')
                    logging.info('Found invalid parameter: Please check "test_emailAddress" value in config.csv file.')
                    logging.info('Found invalid parameter: "test_sendEmail" value changed to: FALSE')
                    logging.debug('Found invalid parameter: Please check "test_emailAddress" value in config.csv file: ' + str(Config_file))

        #for row[10] in myReader: #Get sleep_Ping value
            if (row[10]) == "" or (row[10]) == None or (row[10]).upper() == "NO" or (row[10]).upper() == "FALSE":
                sleep_Ping = 0
            elif math.isnan(float(row[10])) == False:
                sleep_Ping = float((row[10]))
            else:
                sleep_Ping = 0
                print ('Found invalid parameter: Please check "sleep_Ping" value in config.csv file.')
                logging.info('Found invalid parameter: Please check "sleep_Ping" value in config.csv file.')
                logging.info('Found invalid parameter: "sleep_Ping" value changed to: 0')
                logging.debug('Found invalid parameter: Please check "sleep_Ping" value in config.csv file: ' + str(Config_file))

        #for row[11] in myReader: #Get sleep_WHOIS value
            if (row[11]) == "" or (row[11]) == None or (row[11]).upper() == "NO" or (row[1]).upper() == "FALSE":
                sleep_WHOIS = 0
            elif math.isnan(float(row[11])) == False:
                sleep_WHOIS = float((row[11]))
            else:
                sleep_WHOIS = 0
                print ('Found invalid parameter: Please check "sleep_WHOIS" value in config.csv file.')
                logging.info('Found invalid parameter: Please check "sleep_WHOIS" value in config.csv file.')
                logging.info('Found invalid parameter: "sleep_WHOIS" value changed to: 0')
                logging.debug('Found invalid parameter: Please check "sleep_WHOIS" value in config.csv file: ' + str(Config_file))

        #for row[12] in myReader: #Get sleep_sendEmail value
            if (row[12]) == "" or (row[12]) == None or (row[12]).upper() == "NO" or (row[12]).upper() == "FALSE":
                sleep_sendEmail = 0
            elif math.isnan(float(row[12])) == False:
                sleep_sendEmail = float((row[12]))
            else:
                sleep_sendEmail = 0
                print ('Found invalid parameter: Please check "sleep_sendEmail" value in config.csv file.')
                logging.info('Found invalid parameter: Please check "sleep_sendEmail" value in config.csv file.')
                logging.info('Found invalid parameter: "sleep_sendEmail" value changed to: 0')
                logging.debug('Found invalid parameter: Please check "sleep_sendEmail" value in config.csv file: ' + str(Config_file))       

        #for row[13] in myReader: #Get registrant_email value
            if row[13].upper() == "YES":
                registrant_email = True 
            elif row[13].upper() == "NO":
                registrant_email = False 
            else:
                registrant_email = False
                print ('Found invalid parameter: Please check "registrant_email" value in config.csv file.')
                print ('"registrant_email" value changed to: ' + str(registrant_email))
                logging.info('Found invalid parameter: Please check "registrant_email" value in config.csv file.')
                logging.info('Found invalid parameter: "registrant_email" value changed to: False')
                logging.debug('Found invalid parameter: Please check "registrant_email" value in config.csv file: ' + str(Config_file))
                logging.debug('"registrant_email" value changed to: ' + str(registrant_email))

        #for row[14] in myReader: #Get registrar_abuse_contact_email value
            if row[14].upper() == "YES":
                registrar_abuse_contact_email = True 
            elif row[14].upper() == "NO":
                registrar_abuse_contact_email = False 
            else:
                registrar_abuse_contact_email = False
                print ('Found invalid parameter: Please check "registrar_abuse_contact_email" value in config.csv file.')
                print ('"registrar_abuse_contact_email" value changed to: ' + str(registrar_abuse_contact_email))
                logging.info('Found invalid parameter: Please check "registrar_abuse_contact_email" value in config.csv file.')
                logging.info('Found invalid parameter: "registrar_abuse_contact_email" value changed to: False')
                logging.debug('Found invalid parameter: Please check "registrar_abuse_contact_email" value in config.csv file: ' + str(Config_file))
                logging.debug('"registrar_abuse_contact_email" value changed to: ' + str(registrar_abuse_contact_email))

        #for row[15] in myReader: #Get e_mail value
            if row[15].upper() == "YES":
                e_mail = True 
            elif row[15].upper() == "NO":
                e_mail = False 
            else:
                e_mail = False
                print ('Found invalid parameter: Please check "e_mail" value in config.csv file.')
                print ('"e_mail" value changed to: ' + str(e_mail))
                logging.info('Found invalid parameter: Please check "e_mail" value in config.csv file.')
                logging.info('Found invalid parameter: "e_mail" value changed to: False')
                logging.debug('Found invalid parameter: Please check "e_mail" value in config.csv file: ' + str(Config_file))
                logging.debug('"e_mail" value changed to: ' + str(e_mail))

        #for row[16] in myReader: #Get admin_email value
            if row[16].upper() == "YES":
                admin_email = True 
            elif row[16].upper() == "NO":
                admin_email = False 
            else:
                admin_email = False
                print ('Found invalid parameter: Please check "admin_email" value in config.csv file.')
                print ('"admin_email" value changed to: ' + str(admin_email))
                logging.info('Found invalid parameter: Please check "admin_email" value in config.csv file.')
                logging.info('Found invalid parameter: "admin_email" value changed to: False')
                logging.debug('Found invalid parameter: Please check "admin_email" value in config.csv file: ' + str(Config_file))
                logging.debug('"admin_email" value changed to: ' + str(admin_email))

        #for row[17] in myReader: #Get tech_email  value
            if row[17].upper() == "YES":
                tech_email  = True 
            elif row[17].upper() == "NO":
                tech_email  = False 
            else:
                tech_email  = False
                print ('Found invalid parameter: Please check "tech_email " value in config.csv file.')
                print ('"tech_email " value changed to: ' + str(tech_email))
                logging.info('Found invalid parameter: Please check "tech_email " value in config.csv file.')
                logging.info('Found invalid parameter: "tech_email " value changed to: False')
                logging.debug('Found invalid parameter: Please check "tech_email" value in config.csv file: ' + str(Config_file))
                logging.debug('"tech_email" value changed to: ' + str(tech_email))

        #for row[18] in myReader: #Get error_code  value
            if row[18].upper() == "YES":
                error_code  = True 
            elif row[18].upper() == "NO":
                error_code  = False 
            else:
                error_code  = False
                print ('Found invalid parameter: Please check "error_code " value in config.csv file.')
                print ('"error_code " value changed to: ' + str(error_code))
                logging.info('Found invalid parameter: Please check "error_code " value in config.csv file.')
                logging.info('Found invalid parameter: "error_code" value changed to: False')
                logging.debug('Found invalid parameter: Please check "error_code " value in config.csv file: ' + str(Config_file))
                logging.debug('"error_code" value changed to: ' + str(error_code))

        #for row[19] in myReader: #Get email value
            if row[19].upper() == "YES":
                email_ = True 
            elif row[19].upper() == "NO":
                email_  = False 
            else:
                email_ = False
                print ('Found invalid parameter: Please check "email_" value in config.csv file.')
                print ('"email_" value changed to: ' + str(email_))
                logging.info('Found invalid parameter: Please check "email_" value in config.csv file.')
                logging.info('Found invalid parameter: "email_" value changed to: False')
                logging.debug('Found invalid parameter: Please check "email_" value in config.csv file: ' + str(Config_file))
                logging.debug('"email_" value changed to: ' + str(email_))
            
        #for row[20] in myReader: #Get email value
            if row[20].upper() == "YES":
                reseller_email = True 
            elif row[20].upper() == "NO":
                reseller_email = False 
            else:
                reseller_email = False
                print ('Found invalid parameter: Please check "reseller_email" value in config.csv file.')
                print ('"reseller_email" value changed to: ' + str(reseller_email))
                logging.info('Found invalid parameter: Please check "reseller_email" value in config.csv file.')
                logging.info('Found invalid parameter: "reseller_email" value changed to: False')
                logging.debug('Found invalid parameter: Please check "reseller_email" value in config.csv file: ' + str(Config_file))
                logging.debug('"reseller_email" value changed to: ' + str(reseller_email))

        #for row[21] in myReader: #Get use_admin_name value
            if (row[21]).upper() == "" or (row[21]) == None or (row[21]).upper() == "NO" or (row[21]).upper() == "FALSE":
                use_admin_name = False
            elif (row[21]).upper() == "YES" or (row[9]).upper() == "TRUE":
                use_admin_name = True

        #for row[22] in myReader: #Get get_name_servers value
            if row[22].upper() == "YES":
                get_name_servers = True 
            elif row[22].upper() == "NO":
                get_name_servers = False 
            else:
                get_name_servers = False
                print ('Found invalid parameter: Please check "get_name_servers" value in config.csv file.')
                print ('"get_name_servers" value changed to: ' + str(get_name_servers))
                logging.info('Found invalid parameter: Please check "get_name_servers" value in config.csv file.')
                logging.info('Found invalid parameter: "get_name_servers" value changed to: False')
                logging.debug('Found invalid parameter: Please check "get_name_servers" value in config.csv file: ' + str(Config_file))
                logging.debug('"get_name_servers" value changed to: ' + str(get_name_servers))

        #for row[23] in myReader: #Name server to compare with
            if row[23].upper() != "NO":
                name_server_1 = row[23]
            elif row[23].upper() == "NO":
                name_server_1 = "NO"
            else:
                name_server_1 = "NO"
                print ('Found invalid parameter: Please check "name_server_1" value in config.csv file.')
                print ('"name_server_1" value changed to: ' + str(name_server_1))
                logging.info('Found invalid parameter: Please check "name_server_1" value in config.csv file.')
                logging.info('Found invalid parameter: "name_server_1" value changed to: False')
                logging.debug('Found invalid parameter: Please check "name_server_1" value in config.csv file: ' + str(Config_file))
                logging.debug('"name_server_1" value changed to: ' + str(name_server_1))


            #for row[24] in myReader: #Name server to compare with
            if row[24].upper() != "NO":
                name_server_2 = row[24]
            elif row[24].upper() == "NO":
                name_server_2 = "NO"
            else:
                name_server_2 = "NO"
                print ('Found invalid parameter: Please check "name_server_2" value in config.csv file.')
                print ('"name_server_2" value changed to: ' + str(name_server_2))
                logging.info('Found invalid parameter: Please check "name_server_2" value in config.csv file.')
                logging.info('Found invalid parameter: "name_server_2" value changed to: False')
                logging.debug('Found invalid parameter: Please check "name_server_2" value in config.csv file: ' + str(Config_file))
                logging.debug('"name_server_2" value changed to: ' + str(name_server_2))

            #for row[25] in myReader: #Name server to compare with
            if row[25].upper() != "NO":
                name_server_3 = row[25]
            elif row[25].upper() == "NO":
                name_server_3 = "NO"
            else:
                name_server_3 = "NO"
                print ('Found invalid parameter: Please check "name_server_3" value in config.csv file.')
                print ('"name_server_3" value changed to: ' + str(name_server_3))
                logging.info('Found invalid parameter: Please check "name_server_3" value in config.csv file.')
                logging.info('Found invalid parameter: "name_server_3" value changed to: False')
                logging.debug('Found invalid parameter: Please check "name_server_3" value in config.csv file: ' + str(Config_file))
                logging.debug('"name_server_3" value changed to: ' + str(name_server_3))

            #for row[26] in myReader: #Name server to compare with
            if row[26].upper() != "NO":
                name_server_4 = row[26]
            elif row[26].upper() == "NO":
                name_server_4 = "NO"
            else:
                name_server_4 = "NO"
                print ('Found invalid parameter: Please check "name_server_4" value in config.csv file.')
                print ('"name_server_4" value changed to: ' + str(name_server_4))
                logging.info('Found invalid parameter: Please check "name_server_4" value in config.csv file.')
                logging.info('Found invalid parameter: "name_server_4" value changed to: False')
                logging.debug('Found invalid parameter: Please check "name_server_4" value in config.csv file: ' + str(Config_file))
                logging.debug('"name_server_4" value changed to: ' + str(name_server_4))

            #for row[27] in myReader: #Name server to compare with
            if row[27].upper() != "NO":
                name_server_5 = row[27]
            elif row[27].upper() == "NO":
                name_server_5 = "NO"
            else:
                name_server_5 = "NO"
                print ('Found invalid parameter: Please check "name_server_5" value in config.csv file.')
                print ('"name_server_5" value changed to: ' + str(name_server_5))
                logging.info('Found invalid parameter: Please check "name_server_5" value in config.csv file.')
                logging.info('Found invalid parameter: "name_server_5" value changed to: False')
                logging.debug('Found invalid parameter: Please check "name_server_5" value in config.csv file: ' + str(Config_file))
                logging.debug('"name_server_4" value changed to: ' + str(name_server_5))

            #for row[28] in myReader: #Name server to compare with
            if row[28].upper() != "NO":
                name_server_6 = row[28]
            elif row[28].upper() == "NO":
                name_server_6 = "NO"
            else:
                name_server_6 = "NO"
                print ('Found invalid parameter: Please check "name_server_6" value in config.csv file.')
                print ('"name_server_6" value changed to: ' + str(name_server_6))
                logging.info('Found invalid parameter: Please check "name_server_6" value in config.csv file.')
                logging.info('Found invalid parameter: "name_server_6" value changed to: False')
                logging.debug('Found invalid parameter: Please check "name_server_6" value in config.csv file: ' + str(Config_file))
                logging.debug('"name_server_6" value changed to: ' + str(name_server_6))

    if isSilent == True:
        if sendEmail == True:
            if (sender == "" or userName== ""): 
                print ('Abort sentEmail execution due to invalid configurations: user-name/sender')
                sendEmail == False
                logging.info('Abort sentEmail execution due to invalid configurations: user-name/sender')
                logging.debug('Abort sentEmail execution due to invalid configurations: '+ str(Config_file) + ' Please check following configurations: user-name/sender')
                #sys.exit() #abort script execution due to invalid configurations

            elif templateExist == False:
                print ('Abort sentEmail execution due to invalid configurations: email.csv file not found')
                sendEmail = False
                logging.info('Abort sentEmail execution due to invalid configurations: email.csv file not found')
                #sys.exit() #abort script execution due to invalid configurations

            elif SMTP_server == "":
                print ('Abort sentEmail execution due to invalid configurations. Please check "SMTP_server" value in config.csv file.')
                sendEmail = False
                logging.info('Abort sentEmail execution due to invalid configurations. Please check "SMTP_server" value in config.csv file.')
                logging.debug('Abort sentEmail execution due to invalid configurations. Please check "SMTP_server" value in config.csv file: ' + str(Config_file))
                #sys.exit() #abort script execution due to invalid configurations
            elif port == "":
                print ('Abort sentEmail execution due to invalid configurations. Please check "port" value in config.csv file.')
                sendEmail = False
                logging.info('Abort sentEmail execution due to invalid configurations. Please check "port" value in config.csv file.')
                logging.debug('Abort sentEmail execution due to invalid configurations. Please check "port" value in config.csv file: ' + str(Config_file))
                #sys.exit() #abort script execution due to invalid configurations
            elif userName == "":
                print ('Abort sentEmail execution due to invalid configurations. Please check "userName" value in config.csv file.')
                sendEmail = False
                logging.info('Abort sentEmail execution due to invalid configurations. Please check "userName" value in config.csv file.')
                logging.debug('Abort sentEmail execution due to invalid configurations. Please check "userName" value in config.csv file: ' + str(Config_file))
                sys.exit() #abort script execution due to invalid configurations
            elif userPassword == "":
                print ('Abort sentEmail execution due to invalid configurations. Please check "userPassword" value in config.csv file.')
                sendEmail = False
                logging.info('Abort sentEmail execution due to invalid configurations. Please check "userPassword" value in config.csv file.')
                logging.debug('Abort sentEmail execution due to invalid configurations. Please check "userPassword" value in config.csv file: ' + str(Config_file))
                #sys.exit() #abort script execution due to invalid configurations
   
    else:
        if sendEmail == True and templateExist == True and  ((userName== "" or userName== None) or (userPassword == "" or userPassword == None)): #Ask for username/password (in case when UNP values from config.csv are empty or null)
            print "\n=====================================================================================\n"         
            sendEmailInput = raw_input("Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no): ")
            if sendEmailInput == "1":
                sendEmail = True
            else:
                sendEmail = False
            logging.info('Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no)')
            logging.debug('Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no): ' + str(sendEmail))

            if sendEmail == True and templateExist == True:
                uTimes = 0 #counter              
                logging.info('Ask for username')
                userName = raw_input("Please enter your username: ") #ask for username

                while (userName == "" or userName == None):
                    userName = raw_input("Username can not be empty. Please enter your username: ") #ask for username
                    logging.info("Username can not be empty. Please enter your username") 
                    uTimes = uTimes + 1
                    if uTimes > 3:
                        sendEmailInput = raw_input("Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no): ")
                        if sendEmailInput == "1":
                            sendEmail = True
                        else:
                            sendEmail = False
                            logging.info('eMail notification canceled.')
                            logging.debug('eMail notification canceled, sendEmail = ' + str(sendEmail))
                            break

                if sendEmail == True:
                    pTimes = 0 #counter
                    logging.info('Ask for password')
                    import getpass
                    userPassword = getpass.getpass()        #ask for password

                    while (userPassword == "" or userPassword == None):
                        print("Username passwor can not be empty. Please enter user password.") 
                        logging.info("Username passwor can not be empty. Please re-enter user password") 
                        userPassword = getpass.getpass()     #ask for password
                        pTimes = pTimes + 1
                        if pTimes > 3:
                            sendEmailInput = raw_input("Would you like to send an eMail notification to all administrators of invalid domains (1 - yes; 2- no): ")
                            if sendEmailInput == "1":
                                sendEmail = True
                            else:
                                sendEmail = False
                                logging.info('eMail notification canceled.')
                                logging.debug('eMail notification canceled, sendEmail = ' + str(sendEmail))
                                break

    
    return isSilent, sendEmail, SMTP_server, port, sender, userName, userPassword, startIP, test_sendEmail, test_emailAddress, sleep_Ping, sleep_WHOIS, sleep_sendEmail, registrant_email, registrar_abuse_contact_email, e_mail, admin_email, tech_email, error_code, email_, reseller_email, use_admin_name, get_name_servers, name_server_1, name_server_2, name_server_3, name_server_4, name_server_5, name_server_6
    mySettings.close()


getConfigs = setConfigs(Config_file) #Call setConfigs function


#Set global vars:
isSilent, sendEmail, SMTP_server, port, sender, userName, userPassword, startIP, test_sendEmail, test_emailAddress, sleep_Ping, sleep_WHOIS, sleep_sendEmail, registrant_email, registrar_abuse_contact_email, e_mail, admin_email, tech_email, error_code, email_, reseller_email, use_admin_name, get_name_servers, name_server_1, name_server_2, name_server_3, name_server_4, name_server_5, name_server_6 = getConfigs

print ('\nisSilent: ' + str(isSilent))
print ('sendEmail: ' + str(sendEmail))
print ('SMTP server: ' + str(SMTP_server))
print ('port: ' + str(port))
print("Sender: " + str(sender))
print("User Name: " + str(userName))
#print("PSWD: " + userPassword)
print("Start IP: " + str(startIP))

print ('test_sendEmail: ' + str(test_sendEmail))
print ('test_emailAddress: ' + str(test_emailAddress))
print ('sleep_Ping: ' + str(sleep_Ping))
print ('sleep_WHOIS: ' + str(sleep_WHOIS))
print ('sleep_sendEmail: ' + str(sleep_sendEmail))
print ('templateExist: ' + str(templateExist))
print ('use_admin_name: ' + str(use_admin_name))

#email patterns:
print("registrant_email: " + str(registrant_email))
print("registrar_abuse_contact_email: " + str(registrar_abuse_contact_email))
print("e_mail: " + str(e_mail))
print("admin_email: " + str(admin_email))
print("tech_email: " + str(tech_email))
print("error_code: " + str(error_code))
print("email_: " + str(email_))
print("reseller_email: " + str(reseller_email))

print("get_name_servers: " + str(get_name_servers))
#print("resolve_domain_ip: " + str(resolve_domain_ip))

print('name_server_1: ' + str(name_server_1))
print('name_server_2: ' + str(name_server_2))
print('name_server_3: ' + str(name_server_3))
print('name_server_4: ' + str(name_server_4))
print('name_server_5: ' + str(name_server_5))
print('name_server_6: ' + str(name_server_6))

logging.info("Finished setup global variables")

logging.debug('\nisSilent: ' + str(isSilent) + ' ' + 'sendEmail: ' + str(sendEmail) + ' ' +
'SMTP server: ' + str(SMTP_server) + ' ' + 'port: ' + str(port) + ' ' + 'Sender: ' + str(sender) + ' ' +
'User Name: ' + str(userName) + ' ' + 'Start IP: ' + str(startIP) + ' ' + 'test_sendEmail: ' + str(test_sendEmail) + ' ' +
'test_emailAddress: ' + str(test_emailAddress) + ' ' + 'sleep_Ping: ' + str(sleep_Ping) + ' ' + 'sleep_WHOIS: ' + str(sleep_WHOIS) + ' ' +
'sleep_sendEmail: ' + str(sleep_sendEmail) + ' ' + 'e_mail: ' + str(e_mail) + ' ' + 'admin_email: ' + str(admin_email) + ' ' +
'tech_email: ' + str(tech_email) + ' ' + 'error_code: ' + str(error_code) + ' ' + 'email: ' + str(email_) + ' ' + 
'reseller_email: ' + str(reseller_email) + ' ' + 'templateExist: ' + str(templateExist) + ' ' + 'use_admin_name: ' + str(use_admin_name) + ' ' + 
'get_name_servers: ' + str(get_name_servers) + ' ' + 
'name_server_1: ' + str(name_server_1) + ' ' + 'name_server_2: ' + str(name_server_2) + ' ' + 'name_server_3: ' + str(name_server_3) + ' ' + 
'name_server_4: ' + str(name_server_4) + ' ' + 'name_server_5: ' + str(name_server_5) + ' ' + 'name_server_6: ' + str(name_server_6))


#Create a smart names server list:
def create_name_server_list(name_server_1, name_server_2, name_server_3, name_server_4, name_server_5, name_server_6):
    logging.info("Start create_name_server_list function")
    name_server_list = {}

    name_server_list[0] = name_server_1
    name_server_list[1] = name_server_2
    name_server_list[2] = name_server_3
    name_server_list[3] = name_server_4
    name_server_list[4] = name_server_5
    name_server_list[5] = name_server_6

    logging.info("A smart names server list is created")
    logging.debug("A smart names server list is created: " + str(name_server_list))
    return name_server_list

name_server_list = create_name_server_list(name_server_1, name_server_2, name_server_3, name_server_4, name_server_5, name_server_6) #Create list of valid name servers

# Create a full list of VCN ips:
def create_vcn_ip_csv(VCN_IP_RANGE, startIP):
    VCN_ip_list = {}
    ip = 1                              #Start index from 1
    with codecs.open(VCN_IP_RANGE,'w','utf-8-sig') as csvVCNip: #Open file
        writer = csv.writer(csvVCNip)   #Read file
        while ip < 255:
            IPstr = str(ip)             #Convert integer to string
            vcnIP = startIP + IPstr
            writer.writerow([vcnIP])    #Write generated ip address
            VCN_ip_list[ip] = vcnIP
            ip += 1                     #Increase index by 1
    return VCN_ip_list
    csvVCNip.close()                    #Close the file
    
VCN_ip_list = create_vcn_ip_csv(VCN_IP_RANGE, startIP) #Call create_vcn_ip_csv function

num = len(VCN_ip_list) #A total number of ips in the list
print "\n=====================================================================================\n"
print '\nA total number of IPs to validate: ', num, '\n'
logging.info('A total number of IPs to validate')
logging.debug('A total number of IPs to validate: ' + str(num))


# Implement Top Level Domain Name:
#from tld import get_tld

def get_domain_name(url):
    logging.info('Start get_domain_name function')
    domain_name = get_tld(url) #Get Top Level Domain Name
    return domain_name
    logging.info('Finish get_domain_name function')

###################################################################

#Clean email string according to requested pattern:
def clean_email(email, registrant_email, registrar_abuse_contact_email, e_mail, admin_email, tech_email, error_code, email_, reseller_email):
    logging.info('Start clean_email function')
    new = ""                                                #A new string
    if registrant_email == True:                                   
        if "['Registrant Email:" in email:            
            old = "['Registrant Email:"                     #String to replase - condition 1.1
            email = str.replace(email, old, new)            #Replace method
            if "']" in email:                               #String to replase - condition 1.2
                old = "']"                                  #String to replase
                email = str.replace(email, old, new)        #Replace method
                if " " in email:                            #Strip all whitespace from string
                    old = " "                               #String to replase
                    email = str.replace(email, old, new)    #Replace method
    else:
        if "['Registrant Email:" in email:
           email = "not requested"                          #In case "Registrant Email" pattern wasn't requested by user
           logging.debug('"Registrant Email" pattern was not requested by user, registrant_email: ' + str(registrant_email))

    if registrar_abuse_contact_email == True:
        if "['Registrar Abuse Contact Email:" in email: 
            old = "['Registrar Abuse Contact Email:"        #String to replase - condition 2.1
            email = str.replace(email, old, new)            #Replace method
            if "']" in email:                               #String to replase - condition 2.2
                old = "']"                                  #String to replase
                email = str.replace(email, old, new)        #Replace method
                if " " in email:                            #Strip all whitespace from string
                    old = " "                               #String to replase
                    email = str.replace(email, old, new)    #Replace method
    else:
        if "['Registrar Abuse Contact Email:" in email:
           email = "not requested"                          #In case "Registrar Abuse Contact Email" pattern wasn't requested by user
           logging.debug('"Registrar Abuse Contact Email" pattern was not requested by user, registrar_abuse_contact_email: ' + str(registrar_abuse_contact_email))
    
    if e_mail == True:
        #email = email.strip()
        if "['e-mail:" in email:      
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
    else:
        if "['e-mail:" in email:
           email = "not requested"                          #In case "e-mail" pattern wasn't requested by user
           logging.debug('"e-mail" pattern was not requested by user, e_mail: ' + str(e_mail))    
    
    if admin_email == True:
        if "['Admin Email:" in email:       
            old = "['Admin Email:"                          #string to replase - condition 4.1
            email = str.replace(email, old, new)            #replace method
            if "']" in email:                               #string to replase - condition 4.2
                old = "']"                                  #string to replase
                email = str.replace(email, old, new)        #replace method
                if " " in email:                            #to strip all whitespace from string
                    old = " "                               #string to replase
                    email = str.replace(email, old, new)    #replace method
    else:
        if "['Admin Email:" in email:
           email = "not requested"                          #In case "Admin Email" pattern wasn't requested by user
           logging.debug('"Admin Email" pattern was not requested by user, admin_email: ' + str(admin_email))

    if tech_email == True:
        if "['Tech Email:" in email:
            old = "['Tech Email:"                           #string to replase - condition 6.1
            email = str.replace(email, old, new)            #replace method
            if "']" in email:                               #string to replase - condition 6.2
                old = "']"                                  #string to replase
                email = str.replace(email, old, new)        #replace method
                if " " in email:                            #to strip all whitespace from string
                    old = " "                               #string to replase
                    email = str.replace(email, old, new)    #replace method
    else:
        if "['Tech Email:" in email:
           email = "not requested"                          #In case "Tech Email" pattern wasn't requested by user
           logging.debug('"Tech Email" pattern was not requested by user, tech_email: ' + str(tech_email))

    if error_code == True:
        if "['Error code:" in email:                        #r
            old = "['Error code:"                           #string to replase - condition 7.1
            email = str.replace(email, old, new)            #replace method
            if "']" in email:                               #string to replase - condition 7.2
                old = "']"                                  #string to replase
                email = str.replace(email, old, new)        #replace method
                if " " in email:                            #to strip all whitespace from string
                    old = " "                               #string to replase
                    email = str.replace(email, old, new)    #replace method      
    else:
        if "['Error code:" in email:
           email = "not requested"                          #In case "Error code" pattern wasn't requested by user
           logging.debug('"Error code" pattern was not requested by user, error_code: ' + str(error_code))
    
    if email_ == True:
        if "['    Email:" in email:                         # 
            old = "['    Email:"                            #string to replase - condition 8.1
            email = str.replace(email, old, new)            #replace method
            if "']" in email:                               #string to replase - condition 8.2
                old = "']"                                  #string to replase
                email = str.replace(email, old, new)        #replace method
                if " " in email:                            #to strip all whitespace from string
                    old = " "                               #string to replase
                    email = str.replace(email, old, new)    #replace method
    else:
        if "['    Email:" in email:
           email = "not requested"                          #In case "Email" pattern wasn't requested by user
           logging.debug('"Email" pattern was not requested by user, email_ : ' + str(email_))
    
    if reseller_email == True:
        email.strip()
        if "['Reseller Email: ']" in email:                 #  
            old = "['Reseller Email:"                       #string to replase - condition 9.1
            email = str.replace(email, old, new)            #replace method
            if "']" in email:                               #string to replase - condition 9.2
                old = "']"                                  #string to replase
                email = str.replace(email, old, new)        #replace method
                if " " in email:                            #to strip all whitespace from string
                    old = " "                               #string to replase
                    email = str.replace(email, old, new)    #replace method
                    if email == "" or email == " " or email == None:
                        email = 'null'
    else:
        if "['Reseller Email: ']" in email:
           email = "not requested"                          #In case "reseller_email" pattern wasn't requested by user
           logging.debug('"reseller email" pattern was not requested by user, reseller_email : ' + str(reseller_email))

    return email.lower()                                    #return the result
    logging.info('Finish clean_email function')

####################################################################

#Clean name server string:
def clean_name_server(name_server, name_servers):
    logging.info('Start clean_name_server function')
    new = ""                                                        #A new string

    logging.debug('NS: nameServers list ' + str(name_servers))

    if "Name Server:" in name_server:            
        old = "Name Server:"                                        #String to replase - condition 1.1
        name_server = str.replace(name_server, old, new)            #Replace method
        if "']" in name_server:                                     #String to replase - condition 1.2
            old = "']"                                              #String to replase
            name_server = str.replace(name_server, old, new)        #Replace method
        if "['" in name_server:                                     #String to replase - condition 1.2
            old = "['"                                              #String to replase
            name_server = str.replace(name_server, old, new)        #Replace method
            if " " in name_server:                                  #Strip all whitespace from string
                old = " "                                           #String to replase
                name_server = str.replace(name_server, old, new)    #Replace method
        
        for name_server_item in name_servers:                       #Avoid duplicate names
            logging.debug('NS: compare between ' + str(name_server) + ' vs ' + str(name_server_item))
            if name_server == name_server_item:
                logging.debug('NS: found duplicate name server ' + str(name_server) + ' is equal to ' + str(name_server_item) + ' convert it to null.')
                name_server = 'null'

    if "Name servers:" in name_server:            
        old = "Name servers:"                                       #String to replase - condition 2.1
        name_server = str.replace(name_server, old, new)            #Replace method

        if ("felix.vcn.bc.ca" in name_server) or ("sylvester.vcn.bc.ca" in name_server):
            if "felix.vcn.bc.ca" in name_server:
                old = name_server
                name_server = str.replace(name_server, old, "felix.vcn.bc.ca")        #Replace method
            elif "sylvester.vcn.bc.ca" in name_server:
                old = name_server
                name_server = str.replace(name_server, old, "sylvester.vcn.bc.ca")    #Replace method
        else:
            if "']" in name_server:                                 #String to replase - condition 2.2
                old = "']"                                          #String to replase
                name_server = str.replace(name_server, old, new)    #Replace method
            if "['" in name_server:                                 #String to replase - condition 2.2
                old = "['"                                          #String to replase
                name_server = str.replace(name_server, old, new)    #Replace method
            if " " in name_server:                                  #Strip all whitespace from string
                old = " "                                           #String to replase
                name_server = str.replace(name_server, old, new)    #Replace method
        
        for name_server_item in name_servers:                       #Avoid duplicate names
            logging.debug('NS: compare between ' + str(name_server) + ' vs ' + str(name_server_item))
            if name_server == name_server_item:
                logging.debug('NS: found duplicate name server ' + str(name_server) + ' is equal to ' + str(name_server_item) + ' convert it to null.')
                name_server = 'null'

    if "nserver:" in name_server:            
        old = "nserver:"                                            #String to replase - condition 3.1
        name_server = str.replace(name_server, old, new)            #Replace method
        if "']" in name_server:                                     #String to replase - condition 3.2
            old = "']"                                              #String to replase
            name_server = str.replace(name_server, old, new)        #Replace method
        if "['" in name_server:                                     #String to replase - condition 3.2
            old = "['"                                              #String to replase
            name_server = str.replace(name_server, old, new)        #Replace method
            if " " in name_server:                                  #Strip all whitespace from string
                old = " "                                           #String to replase
                name_server = str.replace(name_server, old, new)    #Replace method
        
        for name_server_item in name_servers:                       #Avoid duplicate names
            logging.debug('NS: compare between ' + str(name_server) + ' vs ' + str(name_server_item))
            if name_server == name_server_item:
                logging.debug('NS: found duplicate name server ' + str(name_server) + ' is equal to ' + str(name_server_item) + ' convert it to null.')
                name_server = 'null'


    return name_server.lower()                                      #return the result
    logging.info('Finish clean_name_server function')

####################################################################

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
        name = 'not avaiable'                                         #Admin Name not found
    
    if name == 'Whois Privacy Protection Service by VALUE-DOMAIN':
        name = 'protected'
    elif name == 'Registration Private':
        name = 'protected'

    return name   #return the result
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
logging.debug('A total number of domain names in the test list: ' + str(n))


# WHOIS function:
def get_whois(url):
    logging.info('Start get_whois function')
    time.sleep(sleep_WHOIS) # Wait for x second
    command = "whois " + url                                        #run whois command from CLI
    process = os.popen(command)                                     #open a new CLI as a process
    whois_result = str(process.read())                              #get WHOIS result from the CLI and save is as a string "whois_result"
    with codecs.open(WHOIS_file, 'w','utf-8-sig') as file_handler:  #write results to a file
        for row in whois_result:
            file_handler.write(row)              
    return whois_result
    file_handler.close()
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


####################################################################

#Get get domain name servers from WHOIS_file function:
def get_NameServers(WHOIS_file):
    logging.info('Start get_NameServers function')
    nameServer = {}
    with codecs.open(WHOIS_file,'rU','utf-8-sig') as csvWHOIS: #Open file
        read_whois = csv.reader(csvWHOIS) #Read file
        i=0
        nameServer_id = 0
        for row in read_whois:
            #isDouble = False
            #if '% The data in the WHOIS database of the .il registry is provided' in row:
            test_string = str(row)
            if test_string.find('Name servers:') != -1: #Find 'Name servers:' in row
                
                str1 = str(test_string)
                str2 = str(read_whois.next())
                str3 = str1 + str2
                if nameServer_id == 0:
                    nameServer[nameServer_id] = str3
                    logging.debug('NS: nameServer_id: ' + str(nameServer_id) + ' ,nameServer: ' + str(str3))
                    nameServer_id += 1
                else:
                    isDouble = False
                    for nameServerItem in nameServer:  # Test for duplicate names
                        if nameServerItem == str3:
                            isDouble = True                   
                    if isDouble == False:               # Add new item to the list (only if item is unique)
                        nameServer[nameServer_id] = str3
                        logging.debug('NS: nameServer_id: ' + str(nameServer_id) + ' ,nameServer: ' + str(str3) + ' ,isDouble: ' + str(isDouble))
                        nameServer_id += 1
               
                str1 = str(test_string)
                str4 = str(read_whois.next())
                str5 = str1 + str4
                if nameServer_id == 0:
                    nameServer[nameServer_id] = str5
                    logging.debug('NS: nameServer_id: ' + str(nameServer_id) + ' nameServer: ' + str(str5))
                    nameServer_id += 1
                else:
                    isDouble = False
                    for nameServerItem in nameServer:   # Test for duplicate names
                        if nameServerItem == str5:
                            isDouble = True                   
                    if isDouble == False:               # Add new item to the list (only if item is unique)
                        nameServer[nameServer_id] = str5
                        logging.debug('NS: nameServer_id: ' + str(nameServer_id) + ' ,nameServer: ' + str(str5) + ' ,isDouble: ' + str(isDouble))
                        nameServer_id += 1


            elif test_string.find('nserver:') != -1:    #Find 'nserver:' in row 
                if nameServer_id == 0:
                    nameServer[nameServer_id] = test_string
                    logging.debug('NS: nameServer_id: ' + str(nameServer_id) + ' ,nameServer: ' + str(test_string))
                    nameServer_id += 1
                else:
                    isDouble = False
                    for nameServerItem in nameServer:   # Test for duplicate names
                        if nameServerItem == test_string:
                            isDouble = True                   
                    if isDouble == False:               # Add new item to the list (only if item is unique)
                        nameServer[nameServer_id] = test_string
                        logging.debug('NS: nameServer_id: ' + str(nameServer_id) + ' ,nameServer: ' + str(test_string) + ' ,isDouble: ' + str(isDouble))
                        nameServer_id += 1

            elif test_string.find('Name Server:') != -1: #Find 'Name Server:' in row 
                if nameServer_id == 0:
                    nameServer[nameServer_id] = test_string
                    logging.debug('NS: nameServer_id: ' + str(nameServer_id) + ' ,nameServer: ' + str(test_string))
                    nameServer_id += 1
                else:
                    isDouble = False
                    for nameServerItem in nameServer:   # Test for duplicate names
                        if nameServerItem == test_string:
                            isDouble = True                   
                    if isDouble == False:               # Add new item to the list (only if item is unique)
                        nameServer[nameServer_id] = test_string
                        logging.debug('NS: nameServer_id: ' + str(nameServer_id) + ' ,nameServer: ' + str(test_string) + ' ,isDouble: ' + str(isDouble))
                        nameServer_id += 1

            i += 1
    return nameServer
    csvWHOIS.Close()
    logging.info('Finish get_NameServers function')

####################################################################

#Compare name server vs list of valid names from config.csv:
def is_valid_NameServer(nameServer, isValid_nameServer, name_server_list):
    logging.info('Start is_valid_NameServer function')
    logging.debug('Boolean value: ' + str(isValid_nameServer))
    logging.debug('List of name servers for testing: ' + str(nameServer))
    logging.debug('List of name servers to compare with: ' + str(name_server_list))

    i = 0 #counter
    while i < len(nameServer):
        k = 0
        while k < len(name_server_list):
            if name_server_list[k] != "NO":
                if nameServer[i] != 'null':
                    logging.debug('Compare (<tested> vs <valid>): ' + str(nameServer[i]) + " vs " + str(name_server_list[k]))
                    if nameServer[i] == name_server_list[k]:
                        isValid_nameServer = True
                        logging.debug('A valid name server found: ' + str(nameServer[i]))
                        break
            k = k + 1
        if isValid_nameServer == True:
            break
        else:
            i = i + 1

    logging.info('End is_valid_NameServer function')
    #logging.debug('End is_valid_NameServer function: ' + " " + "nameServer: " + str(nameServer[i]) + " " + "Is valid: " + str(isValid_nameServer))
    return isValid_nameServer

####################################################################

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
def get_eTemplate(Email_file, name, domain, use_admin_name):
    logging.info('Start get_eTemplate function')
    eTemplate = ""
    with codecs.open(Email_file,'rU','utf-8-sig') as csvTEMPLATE:   #Open file
        read_template = csv.reader(csvTEMPLATE)                     #Read file
        if use_admin_name == True:
            if name == 'not avaiable' or name == 'protected':      
                eTemplate = "Hello " + domain.strip() + " administrator," + "\n"
            else:
                eTemplate = "Hello " + name + "," + "\n"
        else:
                eTemplate = "Hello " + domain.strip() + " administrator," + "\n"
        for row in read_template:
            eTemplate = eTemplate + "\n" + ''.join(row)             #convert list object to string

    return eTemplate
    csvTEMPLATE.Close()
    logging.info('Finish get_eTemplate function')


#Filter invalid recipient email addresess
def testIsEmailAccountValid(recipient, isEmailAccountValid):

    if recipient == "null":
        isEmailAccountValid = False
    elif recipient == "n/a":
        isEmailAccountValid = False
    elif recipient == None:
        isEmailAccountValid = False
    elif recipient == "":
        isEmailAccountValid = False
    elif recipient == "not requested":
        isEmailAccountValid = False
    else:       
        # Validate_email is a package for Python that check if an email is valid
        if validate_email(recipient) == True:
            isEmailAccountValid = True
        else:
            isEmailAccountValid = False
    
    return isEmailAccountValid


# Send an Email function:
def send_Email(recipient, name, domain, isEmailAccountValid, SMTP_server, port, sender, userName, userPassword, test_sendEmail, test_emailAddress):

    logging.info('Start send_Email function')
    time.sleep(sleep_sendEmail) # Wait for x second

    # Send the message via SMTP server.
    mail = smtplib.SMTP(SMTP_server, port)
    mail.ehlo()
    mail.starttls()

    logging.info('Email Config')
    logging.debug("Email Config: " + str(SMTP_server) + " " + str(port) + " " + str(sender) + " " + str(SMTP_server))

    # Create message container - the correct MIME type is multipart/alternative.
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Web-admin notification"
    msg['From'] = sender
    msg['To'] = recipient

    # Create the body of the message (a plain-text and an HTML version).
    text = get_eTemplate(Email_file, name, domain, use_admin_name) #a plain-text

    # Record the MIME types of both parts - text/plain and text/html.
    part1 = MIMEText(text, 'plain')
    logging.info('Email text')
    logging.debug("Email text: " + str(text))

    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    msg.attach(part1)

    print('Login in to email account')
    logging.info('Login in to email account')
    logging.debug('isEmailAccountValid ' + str(isEmailAccountValid))

    try:
        mail.login(userName, userPassword) #Email login
    except Exception as error:
        print('Email Login Failed:')
        print(error)
        logging.info('Email Login Failed')
        logging.debug('Email Login Failed: ' + str(error))
        logging.debug("userName: " + str(userName) + "userPassword ")
        #logging.debug("userName: " + str(userName) + "userPassword " + str(userPassword))
        isEmailAccountValid = False
    
    if isEmailAccountValid == True:
        print('Sending Email' + '\n')
        logging.info('Send Email')
        logging.debug("Send Email: " + str(sender) + " " + str(recipient) + " " + msg.as_string())

        if test_sendEmail == False:
            logging.info("test_sendEmail: False")
            logging.debug("test_sendEmail: " + str(test_sendEmail))
            logging.debug("recipient: " + str(recipient))
            try:
                mail.sendmail(sender, recipient, msg.as_string())
                mail.quit()
            except Exception as sendError:
                print(sendError.message)
                logging.info('Send eMail notification:  Failed')
                logging.debug('Send eMail notification: ' + str(sendError.message))
                isEmailAccountValid = False
        else:
            logging.info("test_sendEmail: True")
            logging.debug("test_sendEmail: " + str(test_sendEmail))
            recipient = test_emailAddress
            logging.debug("recipient: " + str(recipient))
            try:
                mail.sendmail(sender, recipient, msg.as_string())
                mail.quit()
            except Exception as sendError:
                print(sendError)
                logging.info('Send eMail notification:  Failed')
                logging.debug('Send eMail notification: ' + str(sendError))
                isEmailAccountValid = False

    else:
        logging.info('Send Email function failed. Invalid Email account.')
        logging.debug('isEmailAccountValid: ' + str(isEmailAccountValid))

    logging.info('Finish send_Email function')


# Get website data and write it into csv file function:
def write_csv(ipList_file, mailSentNum, isEmailAccountValid, isSent, test_sendEmail, test_emailAddress, registrant_email, registrar_abuse_contact_email, e_mail, admin_email, tech_email, error_code, email_, reseller_email, get_name_servers, isValid_nameServer, name_server_list):
    logging.info('Start write_csv function')
    invalidName = {}
    invalidNum = 1
    with codecs.open(ipList_file,'a','utf-8-sig') as csvFile2:      #Open file
        writer = csv.writer(csvFile2, delimiter=',')                #Write to file
        i = 1                                                       #start index from 1
        for row in domains:                                         #start loop            
            test_domain = domains[i].strip()                        #Clean extra spaces            
            time.sleep(sleep_Ping) # Wait for x second

            try:                              
                domainIP = socket.gethostbyname(test_domain)        #Get website IP
            except (socket.gaierror) as strError:
                #print (str(strError))
                print "Oops!  Name or service not known..."
                domainIP = "unknown host"
                logging.info('Name or service not known...')
                logging.debug('INVALID HOSTNAME: ' + str(test_domain) + ' Error message: ' + str(strError))

            
            if domainIP != "unknown host":
                print domains[i], ' > ', domainIP
                logging.debug(str(domains[i]) + ' > ' + str(domainIP))
            else:
                print domains[i], ' > ', domainIP

            isValid = 0
            with codecs.open(VCN_IP_RANGE,'r','utf-8-sig') as csvFile3:
                reader = csv.reader(csvFile3)
                for row in reader:
                    if row[0] == domainIP: #verify if domain IP is in VCN range
                        print ('Found valid IP: ' + domains[i] + ': '+ row[0] + " matches " + domainIP)
                        logging.info('Found valid IP: ')
                        logging.debug('Found valid IP: ' + str(domains[i]) + ' : ' + str(row[0]) + ' matches ' + str(domainIP))
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

                print ('>>> Found invalid IP: ' + domains[i] + ': '+ domainIP + ' <<<')
                invalidName[invalidNum] = domains[i]
                invalidNum += 1
                logging.info('Found invalid IP')
                logging.debug('Found invalid IP: ' + str(domains[i]) + ' : '+ str(domainIP))

                site_whois = get_whois(domain_url) #call get_whois function in order to create WHOIS.csv file with whois data
                
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

                emails[0] = clean_email(emails[0], registrant_email, registrar_abuse_contact_email, e_mail, admin_email, tech_email, error_code, email_, reseller_email) #call clean_email function in order to clean up all the garbage from the emails string
                emails[1] = clean_email(emails[1], registrant_email, registrar_abuse_contact_email, e_mail, admin_email, tech_email, error_code, email_, reseller_email) #call clean_email function in order to clean up all the garbage from the emails string
                emails[2] = clean_email(emails[2], registrant_email, registrar_abuse_contact_email, e_mail, admin_email, tech_email, error_code, email_, reseller_email) #call clean_email function in order to clean up all the garbage from the emails string
                emails[3] = clean_email(emails[3], registrant_email, registrar_abuse_contact_email, e_mail, admin_email, tech_email, error_code, email_, reseller_email) #call clean_email function in order to clean up all the garbage from the emails string
                emails[4] = clean_email(emails[4], registrant_email, registrar_abuse_contact_email, e_mail, admin_email, tech_email, error_code, email_, reseller_email) #call clean_email function in order to clean up all the garbage from the emails string
                
                if get_name_servers == True:

                    nameServer = get_NameServers(WHOIS_file)
                    nameServer_num = len(nameServer)           #get total number of name servers
                    if nameServer_num == 0:
                        nameServer[0] = 'null'
                        nameServer[1] = 'null'
                        nameServer[2] = 'null'
                        nameServer[3] = 'null'
                        nameServer[4] = 'null'
                    elif nameServer_num == 1:
                        nameServer[1] = 'null'
                        nameServer[2] = 'null'
                        nameServer[3] = 'null'
                        nameServer[4] = 'null'
                    elif nameServer_num == 2:
                        nameServer[2] = 'null'
                        nameServer[3] = 'null'
                        nameServer[4] = 'null'
                    elif nameServer_num == 3:
                        nameServer[3] = 'null'
                        nameServer[4] = 'null'
                    elif nameServer_num == 4:
                        nameServer[4] = 'null'

                    nameServer[0] = clean_name_server(nameServer[0], nameServer) #call clean_name_server function in order to clean up all the garbage from the nameServer string
                    nameServer[1] = clean_name_server(nameServer[1], nameServer) #call clean_name_server function in order to clean up all the garbage from the nameServer string
                    nameServer[2] = clean_name_server(nameServer[2], nameServer) #call clean_name_server function in order to clean up all the garbage from the nameServer string
                    nameServer[3] = clean_name_server(nameServer[3], nameServer) #call clean_name_server function in order to clean up all the garbage from the nameServer string
                    nameServer[4] = clean_name_server(nameServer[4], nameServer) #call clean_name_server function in order to clean up all the garbage from the nameServer string

                    isValid_nameServer = False
                    isValid_nameServer = is_valid_NameServer(nameServer, isValid_nameServer, name_server_list)

                else:
                    n_counter = 0
                    isValid_nameServer = "Not tested"
                    nameServer = {}
                    while n_counter < 5:
                        nameServer[n_counter] = "Not requested"
                        n_counter = n_counter + 1 

                Admin_Name = get_cName(WHOIS_file)
                Admin_Name = clean_name(Admin_Name) #call clean_name function in order to clean up all the garbage from the Admin_Name string

                logging.info('Send email notification desicion: START')
                print("sendEmail: " + str(sendEmail))
                print("test_sendEmail: " + str(test_sendEmail))

                recipient_email = ""
                reason = ""
                
                os.remove(WHOIS_file) #remove WHOIS_file

                if sendEmail == True:
                    items = 0 #counter
                    for item in emails:
                        #logging.info('#1') 
                        isEmailAccountValid = testIsEmailAccountValid(emails[items], isEmailAccountValid)  #Verify recipient email

                        print('Email: ' + emails[items] + ' ' + 'isEmailAccountValid: ' + str(isEmailAccountValid))
                        logging.debug('Email: ' + ' ' + emails[items] + 'isEmailAccountValid: ' + str(isEmailAccountValid))                   

                        if isEmailAccountValid == True:

                            if test_sendEmail == False:
                                recipient_email = emails[items]
                            else:
                                recipient_email = emails[items] + ">>>" + test_emailAddress

                            send_Email(emails[items], Admin_Name, domains[i], isEmailAccountValid, SMTP_server, port, sender, userName, userPassword, test_sendEmail, test_emailAddress) #call send_Email function (recipient, name, domain, isSent)  
                            isSent = True
                            mailSentNum = mailSentNum + 1
                            logging.info('Email sent')
                            logging.debug('Email sent: ' + str(isSent))
                            break
                        else:
                            isSent = False
                            reason = 'No valid web admin emails'
                            logging.info('Email not sent: Invalid web-admin email account.')
                            logging.debug('Email sent: ' + str(isSent))
                        items = items + 1
                        #logging.debug('items: ' + str(items)) 
                else:
                    isSent = False
                    reason = 'Canceled by user'
                    logging.info('Email not sent')
                    logging.debug('Email sent: ' + str(isSent))
    
                now = datetime.datetime.now() #Date/Time stamp
                timeNow = now.strftime("%Y-%m-%d %H:%M:%S") # Current date and time using strftime (for example: 2014-09-26 16:34)

                #logging.debug(str(nameServer))
                #logging.debug(str(nameServer_num))

                writer.writerow([domains[i], domainIP, 'invalid', emails[0], emails[1], emails[2], emails[3], emails[4], str(Admin_Name), 'not implemented', str(isSent), str(reason), recipient_email, nameServer[0], nameServer[1], nameServer[2], nameServer[3], nameServer[4], isValid_nameServer, timeNow])
                #logs
                logging.info('Send email notification desicion: END')
                logging.debug(str(domains[i]) + " " + str(domainIP) + " " + 'invalid' + " " + str(emails[0]) + " " + str(emails[1]) + " " + str(emails[2]) + " " + str(emails[3]) + " " + str(emails[4]) + " " + str(Admin_Name) + "address: n/a" + " False " + str(reason) + " " + str(recipient_email) + " " + str(nameServer) + " " + "isValid name server: " + str(isValid_nameServer) + " " + str(timeNow))     

            else:

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

                site_whois = get_whois(domain_url) #call get_whois function in order to create WHOIS.csv file with whois data

                recipient_email = "" 

                if get_name_servers == True:

                    nameServer = get_NameServers(WHOIS_file)
                    nameServer_num = len(nameServer)           #get total number of name servers
                    if nameServer_num == 0:
                        nameServer[0] = 'null'
                        nameServer[1] = 'null'
                        nameServer[2] = 'null'
                        nameServer[3] = 'null'
                        nameServer[4] = 'null'
                    elif nameServer_num == 1:
                        nameServer[1] = 'null'
                        nameServer[2] = 'null'
                        nameServer[3] = 'null'
                        nameServer[4] = 'null'
                    elif nameServer_num == 2:
                        nameServer[2] = 'null'
                        nameServer[3] = 'null'
                        nameServer[4] = 'null'
                    elif nameServer_num == 3:
                        nameServer[3] = 'null'
                        nameServer[4] = 'null'
                    elif nameServer_num == 4:
                        nameServer[4] = 'null'

                    nameServer[0] = clean_name_server(nameServer[0], nameServer) #call clean_name_server function in order to clean up all the garbage from the nameServer string
                    nameServer[1] = clean_name_server(nameServer[1], nameServer) #call clean_name_server function in order to clean up all the garbage from the nameServer string
                    nameServer[2] = clean_name_server(nameServer[2], nameServer) #call clean_name_server function in order to clean up all the garbage from the nameServer string
                    nameServer[3] = clean_name_server(nameServer[3], nameServer) #call clean_name_server function in order to clean up all the garbage from the nameServer string
                    nameServer[4] = clean_name_server(nameServer[4], nameServer) #call clean_name_server function in order to clean up all the garbage from the nameServer string

                    isValid_nameServer = False
                    isValid_nameServer = is_valid_NameServer(nameServer, isValid_nameServer, name_server_list)

                    os.remove(WHOIS_file) #remove WHOIS_file

                else:
                    n_counter = 0
                    isValid_nameServer = "Not tested"
                    nameServer = {}
                    while n_counter < 5:
                        nameServer[n_counter] = "Not requested"
                        n_counter = n_counter + 1 

                now = datetime.datetime.now() #Date/Time stamp
                timeNow = now.strftime("%Y-%m-%d %H:%M:%S") # Current date and time using strftime (for example: 2014-09-26 16:34)
                #write domain name and ip address, ip address and VALID comment
                writer.writerow([domains[i], domainIP, 'valid', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a','False','Valid Domain Address', recipient_email, nameServer[0], nameServer[1], nameServer[2], nameServer[3], nameServer[4], isValid_nameServer, timeNow])  
                #logs
                logging.info('Writing:[domains[i], domainIP, valid, n/a, n/a, n/a, n/a, n/a, n/a, n/a, False: Valid Domain Address, recipient_email, nameServer, date/time')
                logging.debug(str(domains[i]) + " " + str(domainIP) + " valid, emails[0]: n/a, emails[1]: n/a, emails[2]: n/a, emails[3]: n/a, emails[4]: n/a, Admin_Name: n/a, Address: n/a, False: Valid Domain Address, recipient_email: n/a, isValid_nameServer" + str(timeNow))

            print("\n")
            i += 1      #increase index by 1

    return invalidName, mailSentNum
    csvFile2.close()    #close the file
    logging.info('Finish write_csv function')
    

invalidName, mailSentNum = write_csv(ipList_file, mailSentNum, isEmailAccountValid, isSent, test_sendEmail, test_emailAddress, registrant_email, registrar_abuse_contact_email, e_mail, admin_email, tech_email, error_code, email_, reseller_email, get_name_servers, isValid_nameServer, name_server_list) #call write_csv function

invalidDomains = len(invalidName)
validDomains = n - len(invalidName)

print "\n=====================================================================================\n"

print "Summary:\n"
logging.info('Summary:')

print '1) A total number of validated IPs: ', num, '\n'
logging.debug('1) A total number of validated IPs: ' + str(num))

print '2) A total number of domain names in the test list: ', n, '\n'
logging.debug('2) A total number of domain names in the test list: ' + str(n))

print '3) A total number of invalid domain names in the test list: ', invalidDomains, '\n'
logging.debug('3) A total number of invalid domain names in the test list: ' + str(invalidDomains))

print '4) A total number of valid domain names in the test list: ', str(validDomains), '\n'
logging.debug('4) A total number of valid domain names in the test list: ' + str(validDomains))

print '5) Number of an eMail notifications sent to invalid domaina dministrators: ', str(mailSentNum), '\n'
logging.debug('5) Number of an eMail notifications sent to invalid domaina dministrators: ' + str(mailSentNum))

#os.remove(VCN_IP_RANGE) #remove VCN_IP_RANGE
print "\n=====================================================================================\n"
print('Domain-check project URL: https://github.com/ikostan/domain-check')
print 'FINISHED'
logging.info('FINISHED')

#THE END