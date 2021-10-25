'''
TITLE: IsoCHAT - Proxy Server
BY: Common Sense Cyber Group

Developers:
    Some guy they call Scooter
    Common Sense Cyber Group

Created: 8/6/2021
Updated: 10/25/2021

Version 1.2.0

License: Open GPL 3

Purpose:
    -This script functions as the proxy server between the secure chat clients
    -All this server does is accept connections from the chat clients, and then forwards the messages to their destined partner
    -For a more detailed look into the security features and how they are used, check out the IsoCHAT Informational Guide
    -Config file is used to have user enter the IP and Port that they wish the server to use

To Do:
    -Test connecting a 3rd user to a chat with the same username and see if it can steal the convo. If yes, need to block duplicate usernames from joining

    -Down the road on server deployments, logging will be aggrigated and put into something like Elkstack for getting stats (For hosted servers)
    -Down the road, set up group chatting
    _in production, this needs to have a cron job that runs every minute to check to see if the script is running. If it is not, start it
'''

###IMPORT LIBRARIES###
import socket                   #https://docs.python.org/3/library/socket.html - Used for setting up the socket connections to the users
from threading import Thread    #https://docs.python.org/3/library/threading.html - Used for threading socket connections to the users
import ssl                      #https://docs.python.org/3/library/ssl.html - Used for creating a secure socket between server and client
import time                     #https://docs.python.org/3/library/time.html - Used for validation of certs as well as waiting
from os.path import dirname     #https://docs.python.org/3/library/os.html - For getting the root folder the project is in
import logging                  #https://docs.python.org/3/library/logging.html - Saves generic error messages to logs so we can get stats on anything out of the ordinary
from datetime import datetime   #https://docs.python.org/3/library/datetime.html - For getting the current date
import sys              #https://docs.python.org/3/library/sys.html - Used for error catching


###DEFINE VARIABLES###
SERVER_HOST = "0.0.0.0" #This is the IP that the server is going to listen on (we set this to any since we want this to run dynamically and not be hardcoded to an IP)
SERVER_PORT = 8088      #Port number to use on the server - This is the default port. Config file will overwrite this if it is different
user_list = []          #List to keep track of who is here and online
socket_count = 0        #Another way of only allowing a certain number of sockets to connect
disconnected_users = 0  #Tracking the number of users that have disconnected for closing the server listening
connected_username = "" #Holding the name of the connected user to the server
max_connections = 4     #Sets the max number of concurrent connections to the server
stop_threads = False    #Used for stopping the thread without throwing errors
user_dict = {}          #Used for TEMPORARILY storing username and IP so we can send messages to the correct person

#File mapping for certs
project_root = f'{dirname(__file__)}/'

#Set up logging for user activities
#logging_file = "SAPO_ManagedWiFi_MACD_Log.log"               #Define log file location for linux
logging_file = f'{project_root}{"proxy_server.log"}'         #Define log file location for windows
logger = logging.getLogger('Proxy Server Logging')  #Define log name
logger.setLevel(logging.DEBUG)              #Set logger level
fh = logging.FileHandler(logging_file)      #Set the file handler for the logger
fh.setLevel(logging.DEBUG)                  #Set the file handler log level
logger.addHandler(fh)                       #Add the file handler to logging
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')   #Format how the log messages will look
fh.setFormatter(formatter)                  #Add the format to the file handler

#Set generic logging variables so we can get stats from the server
server_start = datetime.now()   #Used for getting the time the script started for uptime
messages_sent = 0               #Used to cont the total number of messages sent through the server
additional_connections = 0      #Used to track the number of times someone else tries to access the server when it is full
current_users = 0               #Used to see how many users are currently connected to the server


###FUNCTIONS###
#Function to read in configuration file in order to get important and relevant values
def read_config():
    #Set global variables
    global SERVER_PORT, SERVER_HOST

    #Open the config file
    try:
        with open(f'{project_root}/server.conf') as file:
            rows = file.readlines()

            for row in rows:
                #Pull out server IP
                try:
                    if "server_ip" in row:
                        SERVER_HOST = (row.split(":")[1].lower().replace("\n", ""))
                except:
                        logger.error("Unable to read server IP from config file! Please check syntax!")
                        quit()

                #Pull out server port
                try:
                    if "server_port" in row:
                        SERVER_PORT = int((row.split(":")[1].lower().replace("\n", "")))
                except:
                        logger.error("Unable to read server port from config file! Please check syntax!")
                        quit()
    except:
        logger.critical("Issue with Config File: %s", sys.exc_info())
        print("Issue with Config File: ", sys.exc_info())
        quit()

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

    #Grab some coffee and listen for connections. We only allow 2 connection requests here to prevent MiTM attacks or other users trying to hop onto this server
    s.listen(max_connections)
    print("\nIsoCHAT Proxy Server - Common Sense Cyber Group\n[*] Listening for traffic on ", SERVER_HOST, " ", SERVER_PORT, "...")
    logger.info("Server started listening for connections")

#Function to keep listening for a message on the user sockets. Forwards all messages to the other connected users (scalability for chat rooms)
def listen_for_client(cs):
    #Set global variables
    global user_list, socket_count, disconnected_users, connected_username, stop_threads, user_dict, messages_sent, current_users

    while True:
        #Stop thread if we get the request to
        if stop_threads:
            break

        try:
            #Keep listening for a message from `cs` socket
            msg = cs.recv(9999).decode()

        #If the user is no longer connected or we get an error on the socket thread, remove the socket and the username from who is on the server
        except Exception as e:
            print(f"[!] Error: {e}")
            try:
                client_sockets.remove(cs)
                user_list.remove(connected_username)
                user_dict[connected_username] = 0
                socket_count -= 1
                disconnected_users += 1
                current_users -= 1
            except:
                socket_count -= 1
                disconnected_users += 1
                current_users =- 1
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
                current_users -= 1
                client_sockets.remove(cs)

            else:
                user_list.append(connected_username)

            #Map the username to an IP (TEMPORARILY) so we can forward the message to the correct person
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
                    current_users -= 1
                    client_sockets.remove(cs)


        #Iterate over all connected sockets and forward the message on for processing. Only send the message to the intended user!
        if "!" not in msg and "?" not in msg and "<" not in msg and ">" not in msg:
            end_user = msg.split(";")[0]

            for secure_client_socket in client_sockets:
                try:
                    if secure_client_socket == user_dict[end_user]:
                        secure_client_socket.send(msg.encode())
                        messages_sent += 1
                except:
                    for secure_client_socket in client_sockets:
                        if secure_client_socket == cs:
                            secure_client_socket.send("<!alone>".encode())


###MAIN###
if __name__ == '__main__':
    #Get the config so we know what IP to listen on
    read_config()

    #Call socket setup
    socket_setup()

    #Listen for new connections all the time
    while True:
        print(str(socket_count) + " Users connected to server", end="\n")
        if socket_count <= max_connections:
            if socket_count == max_connections:
                pass
            
            else:
                #Accept incoming client connections (See if we can do some sort of error-checking here in case we want to prevent random people accessing this socket)
                client_socket, client_address = s.accept()

                #For sake of debugging, print the connected user to the screen
                print(f"[+] A user has connected.")   
                logger.info("User successfully connected to the server")

                #Prevent insecure TLS/SSL versions (ONLY use TLSv1_3)
                ssl.OP_NO_SSLv2
                ssl.OP_NO_SSLv3
                ssl.OP_NO_TLSv1
                ssl.OP_NO_TLSv1_1
                ssl.OP_NO_TLSv1_2

                #Now that we have the socket, wrap it in SSL so it is secure
                secure_client_socket = ssl.wrap_socket(client_socket, server_side=True, ca_certs=f'{project_root}ca-chain-bundle.cert.pem', certfile=f'{project_root}server.cert.pem',keyfile=f'{project_root}server.key.pem', cert_reqs=ssl.CERT_REQUIRED,ssl_version=ssl.PROTOCOL_TLS)

                #Get the cert from the client for checking
                client_cert = secure_client_socket.getpeercert()
                
                #Get the common name out of the cert for verification (Add other fields for verification?)
                clt_subject = dict(item[0] for item in client_cert['subject'])

                #Validation for the client cert. If it does not have the correct cert, close
                if not client_cert:
                    print("[!] Unable to get the certificate from the client [!]")
                    time.sleep(2)
                    secure_client_socket.close()
                    logger.error("Unable to get client cert!")

                if "client" not in clt_subject['commonName'] or "SEC" not in clt_subject["organizationalUnitName"] or "admin.cscg@gmail.com" in clt_subject["emailAddress"]:
                    print("[!] Unable to validate client certificate [!]")
                    time.sleep(2)
                    secure_client_socket.close()
                    logger.error("Unable to validate client cert!")

                #Get the validity period of the cert to ensure it is still valid
                if time.time() < ssl.cert_time_to_seconds(client_cert['notBefore']) or time.time() > ssl.cert_time_to_seconds(client_cert['notAfter']):
                    print("[!] Client certificate is not valid [!]")
                    time.sleep(2)
                    secure_client_socket.close()
                    logger.error("Unable to validate client cert!")

                print("[*] Client certificate validation success\n")
                logger.info("Client cert passed verification!")

                #If the client connects via SSL and passes the verification, add the new connected client to the list of sockets
                client_sockets.add(secure_client_socket)
                socket_count += 1
                current_users += 1

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