'''
TITLE: IsoCHAT - Proxy Server
BY: Common Sense Cyber Group

Developers:
    Some guy they call Scooter
    Common Sense Cyber Group

Created: 08/06/2021
Updated: 12/10/2023

Version 1.2.1

License: Open GPL 3

Purpose:
    -This script functions as the proxy server between the secure chat clients
    -All this server does is accept connections from the chat clients, and then forwards the messages to their destined partner
    -For a more detailed look into the security features and how they are used, check out the IsoCHAT Informational Guide
    -Config file contains necessary configuration items to run server

To Do:
    -Determine deployment method (docker?)
    
'''

### IMPORT LIBRARIES ###
import socket                   #https://docs.python.org/3/library/socket.html - Used for setting up the socket connections to the users
from threading import Thread    #https://docs.python.org/3/library/threading.html - Used for threading socket connections to the users
import ssl                      #https://docs.python.org/3/library/ssl.html - Used for creating a secure socket between server and client
import time                     #https://docs.python.org/3/library/time.html - Used for validation of certs as well as waiting
from os.path import dirname     #https://docs.python.org/3/library/os.html - For getting the root folder the project is in
import logging                  #https://docs.python.org/3/library/logging.html - Saves generic error messages to logs so we can get stats on anything out of the ordinary
from datetime import datetime   #https://docs.python.org/3/library/datetime.html - For getting the current date
import sys                      #https://docs.python.org/3/library/sys.html - Used for error catching
import ipaddress                #https://docs.python.org/3/library/ipaddress.html - Used for validating the IP we get back using requests
import os                       #https://docs.python.org/3/library/os.html - For determining running OS
import subprocess               #https://docs.python.org/3/library/subprocess.html - Used for subprocessing other scripts on the host system
from getpass import getpass     #https://docs.python.org/3/library/getpass.html - For getting information about the current user running the script
import re                       #https://docs.python.org/3/library/re.html - Used for validation and sanitization

### DEFINE VARIABLES ###
user_list = []          #List to keep track of who is here and online
socket_count = 0        #Number of active connections to the server
disconnected_users = 0  #Tracking the number of users that have disconnected for closing the server listening
connected_username = "" #Holding the name of the connected user to the server
stop_threads = False    #Used for stopping the thread without throwing errors
user_dict = {}          #Used for TEMPORARILY storing username and IP so we can send messages to the correct person
key_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%^&*()_=+[{]}\\|:;<,>/?"])[A-Za-z\d@$!%^&*()_=+[{]}\\|:;<,>/?"]{12,}$')    #Regex pattern for encryption keys

#Set generic logging variables so we can get stats from the server
server_start = datetime.now()   #Used for getting the time the script started for uptime


### FUNCTIONS ###
#Function for defining logger for logging all server activities
def init_logger (server_log_location):
    #Set up logging for user activities
    logging_file = f'{server_log_location}{"proxy_server.log"}'         #Define log file location for windows
    logger = logging.getLogger('IsoCHAT Server Logging')  #Define log name
    logger.setLevel(logging.DEBUG)              #Set logger level
    fh = logging.FileHandler(logging_file)      #Set the file handler for the logger
    fh.setLevel(logging.DEBUG)                  #Set the file handler log level
    logger.addHandler(fh)                       #Add the file handler to logging
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')   #Format how the log messages will look
    fh.setFormatter(formatter)                  #Add the format to the file handler

    #Return the logger to be used in other functions
    return logger

#Function to read in configuration file in order to get important and relevant values
def read_config():
    #Set global variables
    global SERVER_PORT, SERVER_HOST, logger, max_connections, server_cert

    #Open the config file
    try:
        with open(f'{dirname(__file__)}/server.conf') as file:
            rows = file.readlines()

            for row in rows:
                #Pull out logger path
                try:
                    if "server_log_location" in row:
                        if str((row.split(":")[1].replace("\n", ""))) == "":
                            log_location = f'{dirname(__file__)}/'
                        else:
                            log_location = str((row.split(":")[1].replace("\n", "")))

                        #Init logger
                        logger = init_logger(log_location)
                        print("\n[*] Logger has been set up. Any further errors will be available in the log file: %s", log_location)
                except:
                        print("\n[!] Unable to read server_log_location from config file! Please check syntax!")
                        quit()

                #Pull out server IP
                try:
                    if "server_ip" in row:
                        SERVER_HOST = (row.split(":")[1].lower().replace("\n", ""))

                        #Validate IP
                        try:
                            test_ip = ipaddress.ip_address(SERVER_HOST)

                        except:
                            logger.error("Server_ip in config file is not a valid IP address!")
                            quit()

                except:
                        logger.error("Unable to read server IP from config file! Please check syntax!")
                        quit()

                #Pull out server port
                try:
                    if "server_port" in row:
                        SERVER_PORT = int((row.split(":")[1].lower().replace("\n", "")))

                        #Validate port
                        if SERVER_PORT < 0 or SERVER_PORT > 65535:
                            logger.error("Server_port in config file is not a valid port number!")
                            quit()

                except:
                        logger.error("Unable to read server port from config file! Please check syntax!")
                        quit()

                #Pull out concurrent connection count
                try:
                    if "concurrent_connections" in row:
                        max_connections = int((row.split(":")[1].lower().replace("\n", "")))

                        #Validate connection count
                        if max_connections < 2 or max_connections > 20:
                            logger.error("Concurrent Connections in config file is not valid! Must be between 2 and 20")

                except:
                        logger.error("Unable to read concurrent_connections from config file! Please check syntax!")
                        quit()

                #Pull out server cert location
                try:
                    if "server_cert" in row:
                        if row.split(":")[1].replace("\n", "") == "":
                            server_cert = f'{dirname(__file__)}/cert_generation/'
                            
                        else:
                            server_cert = str(row.split(":")[1].replace("\n", ""))
                except:
                        logger.error("Unable to read server_cert from config file! Please check syntax!")
                        quit()
    except:
        logger.critical("Issue with Config File: %s", sys.exc_info())
        print("[!] Issue with Config File: ", sys.exc_info())
        quit()

    #Close file to stay clean
    file.close()

#Function for creating certificates at startup if the user wants them auto-created
def auto_cert_gen():
    #Check to see if there are existing certificates and ask to overwrite them


    #For Windows OS
    if os.name == 'nt':
        try:
            #Call PS1 script to generate certs
            sub_out = subprocess.call(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "./cert_generation/windows_cert.ps1"])

            #Print output to screen for user
            print(sub_out.decode('utf-8'))

            return True

        except subprocess.CalledProcessError as e:
            print("\n[!] Error [!] While generating the certificates for IsoCHAT, the following error occurred: " + e + " [!]")
            return False
    
    #All others
    else:
        try:
            #Call Shell script to generate certs
            sub_out = subprocess.check_call(['bash', "./cert_generation/linux_cert.sh"])

            #Print output to screen for user
            print(sub_out.decode('utf-8'))

            return True
        
        except subprocess.CalledProcessError as e:
            print("\n[!] Error [!] While generating the certificates for IsoCHAT, the following error occurred: " + e + " [!]")
            return False

#Function to set up the sockets on the server and start listening for connections
def socket_setup():
    #Set global variables
    global client_sockets, s

    #Initialize and list all of the client connections
    client_sockets = set()

    #Set up the TCP socket
    s = socket.socket()

    #Make the port reusable
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    #Bind the socket to the specified IP address
    s.bind((SERVER_HOST, SERVER_PORT))

    #Grab some coffee and listen for connections
    s.listen(max_connections)
    logger.info("Server started listening for connections on %s:%s", SERVER_HOST, SERVER_PORT)

#Function to keep listening for a message on the user sockets. Forwards all messages to the other connected users (scalability for chat rooms)
def listen_for_client(cs):
    #Set global variables
    global user_list, socket_count, disconnected_users, connected_username, stop_threads, user_dict

    while True:
        #Stop thread if we get the request to
        if stop_threads:
            break

        try:
            #Keep listening for a message from `cs` socket
            msg = cs.recv(9999).decode()

        #If the user is no longer connected or we get an error on the socket thread, remove the socket and the username from who is on the server
        except Exception as e:
            logger.error("Socket Error: %s", e)

            try:
                client_sockets.remove(cs)
                user_list.remove(connected_username)
                user_dict[connected_username] = 0
                socket_count -= 1
                disconnected_users += 1

            except:
                socket_count -= 1
                disconnected_users += 1
                break

        #If we received a message with the <?online> tag set in the beginning, we need to look in the table afor the user, and send the response
        if "<?online>" in msg:
            try:
                search_user = msg.split(">")[1]
            except IndexError:
                pass

            if search_user in user_list:
                user_response = "<yes>"

            else:
                user_response = "<no>"

            for secure_client_socket in client_sockets:
                if secure_client_socket == cs:
                    secure_client_socket.send(user_response.encode())
            
        #Add the username to the list of connected users when they check in
        if "<!check_in>" in msg:
            connected_username = msg.split(">")[1]
            connected_username = connected_username.split("<")[0]

            #Is the user is already in the user list, send them the quit command so they close the session
            if connected_username in user_list:
                secure_client_socket.send("<!quit>".encode())
                socket_count -= 1
                disconnected_users += 1
                client_sockets.remove(cs)

            else:
                user_list.append(connected_username)

            #Map the username to an IP (TEMPORARILY - NEVER LOGGED) so we can forward the message to the correct person
            user_dict[connected_username] = cs

        #Help the client quit nicely when they request to close the session
        if "<!quit>" in msg:
            for secure_client_socket in client_sockets:
                if secure_client_socket == cs:
                    secure_client_socket.send("<!quit>".encode())
                    user_list.remove(connected_username)
                    user_dict[connected_username] = 0
                    socket_count -= 1
                    disconnected_users += 1
                    client_sockets.remove(cs)


        #Iterate over all connected sockets and forward the message on for processing. Only send the message to the intended user!
        if "!" not in msg and "?" not in msg and "<" not in msg and ">" not in msg:
            end_user = msg.split(";")[0]

            for secure_client_socket in client_sockets:
                try:
                    if secure_client_socket == user_dict[end_user]:
                        secure_client_socket.send(msg.encode())
                except:
                    for secure_client_socket in client_sockets:
                        if secure_client_socket == cs:
                            secure_client_socket.send("<!alone>".encode())


### MAIN ###
if __name__ == '__main__':
    #Validate the we were run as root/admin
    if os.name == 'nt':
        try:
            import ctypes
            pass

        except:
            print("\n[!] Must be run as an administrator! [!]")
            exit(1)

    elif os.geteuid() != 0:
        print("\n[!] Must be run as an administrator! [!]")
        exit(1)

    #Get the config so we know what IP to listen on
    read_config()

    #Grab the Server Key from the user for encryption (encrypts usernames only  within an already encrypted HTTPS session and also prevents unwanted parties from accessing/spoofing the chat session )
    print("\n\nPlease enter the SERVER encryption token for this chat session below.\nYour chat partner AND the proxy server will also need to use this same token in order to communicate properly!\n(This will not be visible as you type)")

    #Error checking to ensure that the user is entering a server key that is long enough
    while True:
        server_key = getpass("Token: ")

        #Check for complexity in the key
        if key_pattern.match(server_key):
            break

        else:
            print("\n[!] Error [!] Server Key must meet the following requirements!\n\t-Minimum of 12 Characters\n\t-Contains Numbers\n\t-Contains Special Characters\n\t-Contains upper and lowecase letters\n")

    #Call socket setup
    socket_setup()

    #Listen for new connections all the time
    while True:
        print("\n[**] IsoCHAT Proxy Server - Common Sense Cyber Group [**]\nListening for traffic on ", SERVER_HOST, " ", SERVER_PORT, "...")
        print("Server Uptime: %s", (datetime.now() - server_start))
        print(str(socket_count) + " Users connected to server", end="\n")
        if socket_count <= max_connections:
            if socket_count == max_connections:
                pass
            
            else:
                #Accept incoming client connections
                client_socket, client_address = s.accept()
                logger.info("User successfully connected to the server. Beginning certificate validations")

                #Prevent insecure TLS/SSL versions (ONLY use TLSv1_3)
                ssl.OP_NO_SSLv2
                ssl.OP_NO_SSLv3
                ssl.OP_NO_TLSv1
                ssl.OP_NO_TLSv1_1
                ssl.OP_NO_TLSv1_2

                #Now that we have the socket, wrap it in SSL so it is secure
                secure_client_socket = ssl.wrap_socket(client_socket, server_side=True, ca_certs=f'{server_cert}ca-chain-bundle.cert.pem', certfile=f'{server_cert}server.cert.pem',keyfile=f'{server_cert}server.key.pem', cert_reqs=ssl.CERT_REQUIRED,ssl_version=ssl.PROTOCOL_TLS)

                #Get the cert from the client for checking
                client_cert = secure_client_socket.getpeercert()
                
                #Get the common name out of the cert for verification (Add other fields for verification?)
                clt_subject = dict(item[0] for item in client_cert['subject'])

                #Validation for the client cert. If it does not have the correct cert, close
                if not client_cert:
                    time.sleep(2)
                    secure_client_socket.close()
                    logger.error("Unable to get client cert!")

                if "client" not in clt_subject['commonName'] or "SEC_IsoCHAT" not in clt_subject["organizationalUnitName"]:
                    time.sleep(2)
                    secure_client_socket.close()
                    logger.error("Unable to validate client cert!")

                #Get the validity period of the cert to ensure it is still valid
                if time.time() < ssl.cert_time_to_seconds(client_cert['notBefore']) or time.time() > ssl.cert_time_to_seconds(client_cert['notAfter']):
                    time.sleep(2)
                    secure_client_socket.close()
                    logger.error("Unable to validate client cert!")

                logger.info("Client cert passed verification!")

                #If the client connects via SSL and passes the verification, add the new connected client to the list of sockets
                client_sockets.add(secure_client_socket)
                socket_count += 1

                #Start a new thread that listens for the users messages
                t = Thread(target=listen_for_client, args=(secure_client_socket,))

                #Set up daemon so it ends with main thread and start it
                t.daemon = True
                t.start()

    #If we get to this point, close all of the client and server sockets, and shut down the threaded listener
    for cs in secure_client_socket:
        cs.close()
    stop_threads = True
    if t.is_alive():
        t.join()
    secure_client_socket.close()
    s.close()
    quit()
