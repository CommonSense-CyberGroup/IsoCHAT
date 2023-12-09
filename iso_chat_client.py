'''
TITLE: IsoCHAT - Client
BY: Common Sense Cyber Group

Developers:
    Some guy they call Scooter
    Common Sense Cyber Group

Created: 08/05/2021
Updated: 12/08/2023

Version 1.1.3

License: Open GPL 3

Purpose:
    -This script is a secure chat program, using the XOR cipher as well as other obfuscation methods (Hex, Ascii. base64) to encrypt and send messages between 2 clients
    -The idea is to cut out a server in the middle that holds the conversations and have the two clinets communicate directly with eachother. 
        That way there is nothing sitting between their conversation taking out an additional point of compormise.
        All of the encryption/decryption is done client side so the server only sees the name of the user that the chat request is going to
    -For a more detailed look into the security features, check out the IsoCHAT Informational Guide    

To Do:
    -Pretty UI option as well instead of CLI only (possibility of both)
    -Add additional error checking for special symbols in username validation (include more wacky ascii characters)
'''

###IMPORT LIBRARIES###
from threading import Thread    #https://docs.python.org/3/library/threading.html - Used for threading socket connections to the proxy server
import secrets                   #https://docs.python.org/3/library/secrets.html - Used for generating random numbers for obfuscation
from os.path import dirname     #https://docs.python.org/3/library/os.html - For setting up the root dir of the script so we can save log file, and access other scripts/info
from getpass import getpass     #https://docs.python.org/3/library/getpass.html - For getting information about the current user running the script
from colorama import Fore, Style        #https://pypi.org/project/colorama/ - For making the CLI version of this script a little prettier
import hashlib                  #https://docs.python.org/3/library/hashlib.html - For hashing the messages to ensure there has been no tampering
import base64                   #https://docs.python.org/3/library/base64.html - For encoding the message payload to base64
from datetime import datetime   #https://docs.python.org/3/library/datetime.html - For getting the current date
import time                     #https://docs.python.org/3/library/time.html - For waiting on different things
import socket                   #https://docs.python.org/3/library/socket.html - Used for setting up the socket connections to the proxy server
import ssl                      #https://docs.python.org/3/library/ssl.html - Used for encrypting client sockets to the proxy server for secure communication
import ipaddress                #https://docs.python.org/3/library/ipaddress.html - Used for validating the IP we get back using requests
import sys                      #https://docs.python.org/3/library/sys.html - Used for error catching


### DEFINE VARIABLES ###
project_root = f'{dirname(__file__)}/' #Holds the root of the project for output
stop_threads = False                #Used for stopping the thread without throwing errors


### FUNCTIONS ###
#Function to read in configuration file in order to get important and relevant values
def read_config():
    #Set global variables
    global SERVER_PORT, SERVER_HOST, USER1, USER2, CERT_LOCATION

    #Open the config file
    try:
        with open(f'{dirname(__file__)}/server.conf') as file:
            rows = file.readlines()

            for row in rows:
                #Pull out server IP
                try:
                    if "server_ip" in row:
                        SERVER_HOST = (row.split(":")[1].lower().replace("\n", ""))

                        #Validate IP
                        try:
                            test_ip = ipaddress.ip_address(SERVER_HOST)

                        except:
                            print(Fore.RED + "Invalid IP address in config file!" + Style.RESET_ALL)
                            quit()

                except:
                        print(Fore.RED + "Unable to read server IP from config file! Please check syntax!" + Style.RESET_ALL)
                        quit()

                #Pull out server port
                try:
                    if "server_port" in row:
                        SERVER_PORT = int((row.split(":")[1].lower().replace("\n", "")))

                        #Validate port
                        if SERVER_PORT < 0 or SERVER_PORT > 65535:
                            print(Fore.RED + "Invalid port in config file!" + Style.RESET_ALL)
                            quit()

                except:
                        print(Fore.RED + "Unable to read server port from config file! Please check syntax!" + Style.RESET_ALL)
                        quit()

                #Pull out username 1
                try:
                    if "user_1_endpoint" in row:
                        USER1 = int((row.split(":")[1].replace("\n", "")))

                        #Validate user1
                        if any(char in "'`~!@#$%^&*()_=+[{]}\\|:;<,>/?' " for char in USER1):
                            print(Fore.RED + "Invalid user_1_endpoint from config file! Please check syntax and remove special characters!" + Style.RESET_ALL)
                            quit()

                except:
                        print(Fore.RED + "Unable to read user_1_endpoint from config file! Please check syntax!" + Style.RESET_ALL)
                        quit()

                #Pull out username 2
                try:
                    if "user_2_endpoint" in row:
                        USER1 = int((row.split(":")[1].replace("\n", "")))

                        #Validate user2
                        if any(char in "'`~!@#$%^&*()_=+[{]}\\|:;<,>/?' " for char in USER2):
                            print(Fore.RED + "Invalid user_2_endpoint from config file! Please check syntax and remove special characters!" + Style.RESET_ALL)
                            quit()

                except:
                        print(Fore.RED + "Unable to read user_2_endpoint from config file! Please check syntax!" + Style.RESET_ALL)
                        quit()

                #Pull out client cert location
                try:
                    if "certificate_path" in row:
                        if row.split(":")[1].replace("\n", "") == "":
                            CERT_LOCATION = f'{dirname(__file__)}/'
                            
                        else:
                            CERT_LOCATION = str(row.split(":")[1].replace("\n", ""))

                except:
                        print(Fore.RED + "Unable to read certificate_path from config file! Please check syntax!" + Style.RESET_ALL)
                        quit()
    except:
        print("[!] Issue with client config file: ", sys.exc_info())
        quit()

    #Close file to stay clean
    file.close()

#Function to get the chat startup information from the user
def pre_chat():
    #Set up global variables
    global key

    #Show the user the welcome prompt
    print(Fore.LIGHTBLUE_EX + "\nIsoCHAT - Common Sense Cyber Group\n\n")

    #Ask the user to enter the key they will use for the XOR cipher
    print(Fore.LIGHTYELLOW_EX + "BE SURE TO READ AND FOLLOW THE INFORMATION GUIDE BEFORE FIRST USE!!!" + Fore.LIGHTCYAN_EX + "\n\nPlease enter the encryption token for this chat session below.\nYour chat partner will also need to use this same token in order to communicate properly!\n(This will not be visible as you type)" + Style.RESET_ALL)
    
    #Error checking to ensure that the user is entering a key that is long enough
    while True:
        key = getpass("Token: ")

        #Check for complexity in the key
        if len(key) < 12:
            print(Fore.RED + "\n[!] Error [!] Key must meet the following requirements!\n\t-Minimum of 12 Characters\n\t-Contains Numbers\n\t-Contains Special Characters\n\t-Contains upper and lowecase letters\n" + Style.RESET_ALL)
        elif not any(char.islower() for char in key):
            print(Fore.RED + "\n[!] Error [!] Key must meet the following requirements!\n\t-Minimum of 12 Characters\n\t-Contains Numbers\n\t-Contains Special Characters\n\t-Contains upper and lowecase letters\n" + Style.RESET_ALL)
        elif not any(char.isupper() for char in key):
            print(Fore.RED + "\n[!] Error [!] Key must meet the following requirements!\n\t-Minimum of 12 Characters\n\t-Contains Numbers\n\t-Contains Special Characters\n\t-Contains upper and lowecase letters\n" + Style.RESET_ALL)
        elif not any(char in "'`~!@#$%^&*()_=+[{]}\\|:;<,>/?'" for char in key):
            print(Fore.RED + "\n[!] Error [!] Key must meet the following requirements!\n\t-Minimum of 12 Characters\n\t-Contains Numbers\n\t-Contains Special Characters\n\t-Contains upper and lowecase letters\n" + Style.RESET_ALL)
        elif not any(char.isdigit() for char in key):
            print(Fore.RED + "\n[!] Error [!] Key must meet the following requirements!\n\t-Minimum of 12 Characters\n\t-Contains Numbers\n\t-Contains Special Characters\n\t-Contains upper and lowecase letters\n" + Style.RESET_ALL)
        else:
            break
    
    #Prompt the user with additional information, asking them to accept warnings and continue to enable to start the chat service
    while True:
        print(Fore.LIGHTYELLOW_EX + "\n\n\tPlease read and accept the following before continuing!\n\tBy using this secure chat program, you understand that although all possible steps have been taken\n\tto ensure security during your chat session, there is always the possibility\n\tof the for sniffing and data exposure when using the public internet. By selecting to continue, you accept that \n\tthis program and its developers/maintainers are not responsilbe for what you or your partners\n\tsay online and cannot be held accountable!\n\tBy choosing to continue, you accept all accountability for what is done with and said\n\twhile using this application!" + Style.RESET_ALL)
        warning_response = input("Continue? (y/n): ")

        #Error checking for warning response
        if warning_response.lower() == "n":
            quit()

        elif warning_response.lower() == "y":
                print(Fore.LIGHTGREEN_EX + "Happy Chatting :)" + Style.RESET_ALL)
                break
        
        else:
            print(Fore.RED + "[!] Error [!] You must enter 'y' or 'n' to continue!" + Style.RESET_ALL)

    #This will only be hit if the user passes the key checks, as well as hits 'y' on the caution prompt
    #Call the chat_setup function to get chat info and then begin
    chat_session_setup()

#Function to set up the chat for the user (selecting endpoints and such)
def chat_session_setup():
    #Set up global variables
    global key, secure_client_socket, user_2_endpoint, user_1_endpoint, session_start_time, t, proxy_server_ip, proxy_server_port

    #Convert the user key to binary and remove the spaces
    key = ''.join(format(ord(x), 'b') for x in key)

    #Set up the current username
    if USER1 == "":
        print(Fore.LIGHTCYAN_EX + "\nEnter your desired username for this session (no special characters allowed)" + Style.RESET_ALL)
        
        while True:
            user_1_endpoint = input("Enter your username: ")

            #Check username for valid characters
            if any(char in "'`~!@#$%^&*()_=+[{]}\\|:;<,>/?' " for char in user_1_endpoint):
                print(Fore.RED + "\n\t[!] ERROR: Invalid character in username! [!]" + Style.RESET_ALL)
                time.sleep(3)
                val1 = False
                
            else:
                val1 = True

            if val1:
                break

    else:
        print(Fore.LIGHTCYAN_EX + "\nFor this chat session, your username will be " + USER1 + " (defined from the config file)" + Style.RESET_ALL)
        time.sleep(1)

    #Get the username of the other user that we need to contact
    if USER2 == "":
        print(Fore.LIGHTCYAN_EX + "\nEnter the username of the person you want to chat with for this session (no special characters allowed)" + Style.RESET_ALL)

        while True:
            user_2_endpoint = input("Enter partner username: ")

            #Check username for valid characters
            if any(char in "'`~!@#$%^&*()_=+[{]}\\|:;<,>/?' " for char in user_2_endpoint):
                    print(Fore.RED + "\n\t[!] ERROR: Invalid character in partner username! [!]" + Style.RESET_ALL)
                    time.sleep(3)
                    val2 = False
                    break
                
            else:
                val2 = True

            if val2:
                break

    else:
        print(Fore.LIGHTCYAN_EX + "\nFor this chat session, your partner will be " + USER2 + " (defined from the config file)" + Style.RESET_ALL)
        time.sleep(1)

    #Ask the user which server they wish to connect to
    if SERVER_HOST == "" or SERVER_PORT == "":
        print(Fore.LIGHTCYAN_EX + "\nPlease select one of the following server info to connect to (your partner must be on the same server!):\n" + Style.RESET_ALL)

        while True:
            proxy_server_ip = input("Server IP: ")
            proxy_server_port = input("Server Port: ")

            try: 
                test_ip = ipaddress.ip_address(proxy_server_ip)
            except:
                print(Fore.RED + "\n\t[!] ERROR: Please check that you entered a valid IP for the server and a proper port number! [!]\n" + Style.RESET_ALL)

            if proxy_server_port != "":
                break

            else:
                print(Fore.RED + "\n\t[!] ERROR: Please check that you entered a valid IP for the server and a proper port number! [!]\n" + Style.RESET_ALL)
    
    else:
        while True:
            print(Fore.LIGHTCYAN_EX + "\nPlease confirm the proxy server info below is correct:\nProxy Server: " + SERVER_HOST + "\nProxy Server Port: " + SERVER_PORT + "" + Style.RESET_ALL)

            valid_server_info = input("Is the proxy server info correct? (y/n): ")

            if valid_server_info.lower() != "y" or valid_server_info != "n":
                print(Fore.RED + "\n\t[!] ERROR: Please check that you entered a valid IP for the server and a proper port number! [!]\n" + Style.RESET_ALL)

            if valid_server_info.lower() == "y":
                break

            else:
                while True:
                    proxy_server_ip = input("Server IP: ")
                    proxy_server_port = input("Server Port: ")

                    try: 
                        test_ip = ipaddress.ip_address(proxy_server_ip)
                    except:
                        print(Fore.RED + "\n\t[!] ERROR: Please check that you entered a valid IP for the server and a proper port number! [!]\n" + Style.RESET_ALL)

                    if proxy_server_port != "":
                        break

                    else:
                        print(Fore.RED + "\n\t[!] ERROR: Please check that you entered a valid IP for the server and a proper port number! [!]\n" + Style.RESET_ALL)

                break

    #Connect to the cloud server/proxy for forwarding communication back and forth and let the user know what is happening as they wait
    print(Fore.LIGHTRED_EX + "\n\tCreating a secure connection to the communication proxy. Please wait.")

    #Set up the secure socket
    #Set up the SSL context - Require a cert and set ciphers to ECDHE
    context = ssl.SSLContext(ssl_version=ssl.PROTOCOL_TLS)
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_ciphers = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"

    #Load CA certificate with which the client will validate the server certificate
    try:
        context.load_verify_locations(f'{project_root}ca-chain-bundle.cert.pem')

        #Load client certificate
        context.load_cert_chain(certfile=f'{project_root}client.cert.pem', keyfile=f'{project_root}client.key.pem')

    except:
        print(Fore.RED + "\n\t[!] Unable to load the client certificates for the SSL connection! Please be sure to read the user guide to complete the setup! [!]" + Style.RESET_ALL)
        quit()

    #Initialize the TCP socket to the proxy server and connect
    try:

        #Create and wrap socket
        secure_client_socket = context.wrap_socket(socket.socket())
        secure_client_socket.connect((proxy_server_ip, int(proxy_server_port)))

        #Get the server cert for verification
        server_cert = secure_client_socket.getpeercert()


        #Validate whether the Certificate is indeed issued to the server
        subject = dict(item[0] for item in server_cert['subject'])

        if not server_cert:
            print(Fore.RED + "\n\t[!] Unable to retrieve server certificate [!]" + Style.RESET_ALL)
            secure_client_socket.close()
            quit()
            
        if 'server' not in subject['commonName'] or "SEC_IsoCHAT" not in subject["organizationalUnitName"]:
            print(Fore.RED + "\n\t[!] Unable to validate certificate [!]" + Style.RESET_ALL)
            secure_client_socket.close()
            quit()

        #Validate the server cert to ensure it is not expired
        if time.time() > ssl.cert_time_to_seconds(server_cert['notAfter']) or time.time() < ssl.cert_time_to_seconds(server_cert['notBefore']):
            print(Fore.RED + "\n\t[!] Server cert is not valid [!]" + Style.RESET_ALL)
            secure_client_socket.close()
            quit()

        #Send the check in message to the server
        check_in = f'<!check_in>{user_1_endpoint}'
        secure_client_socket.send(check_in.encode())

    except:
        print(Fore.RED + "\n\t[!] ERROR: Unable to connect to the proxy server! Check your connection! [!]" + Style.RESET_ALL)
        secure_client_socket.close()
        time.sleep(3)
        quit()

    #Ensure that the other party is online on the server (wait 2min for them to join), otherwise quit
    print(Fore.LIGHTMAGENTA_EX + "\n\tPlease wait while we ensure the other user is online and on the server.\n\tIf we do not get a response in 2min, IsoCHAT will be closed." + Style.RESET_ALL)

    #Check the username to see if they are online or not
    user_2_online = user_onilne_checker()

    #Continue based upon the other user being online or not  
    if not user_2_online:
        print(Fore.RED + "\n\n\t[!] ERROR: User is not online after 2min of waiting! Closing IsoCHAT! [!]" + Style.RESET_ALL)
        secure_client_socket.close()
        time.sleep(3)
        quit()

    #Thread the listener function so we can start listening for messages. Set the daemon so it starts and ends with the main thread and then kick it off
    t = Thread(target=chat_service_listener)
    t.daemon = True
    t.start()

    #Call the messenger function to kick off what we came here for
    session_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    messenger()

#Function used to get response from proxy server to see if the other user is online
def user_onilne_checker():
    timer = 0

    #Listen for a message coming in from the proxy server telling us that the user is online
    while True:
        online_question = f'<?online>{user_2_endpoint}'
        secure_client_socket.send(online_question.encode())

        #Grab the response from the server and read it
        response = secure_client_socket.recv(9999).decode()

        #If the server says that the user is online, continue to the messenger function. Otherwise wait until we hit 2min
        if "<yes>" in response:
            return True
        
        else:
            time.sleep(1)
            timer += 1

            #Print a timer so the user doesn't get antsy
            print("Time Elapsed (s): ", timer, end="\r")

            if timer == 120:
                return False

#Function to kick off the chat service listener (using subprocessing/threading so it doesn't take up CPU cycles here)
def chat_service_listener():
    #Set global variables
    global stop_threads, secure_client_socket

    #Listen for a message coming in from the proxy server
    while True:
        try:
            received_payload = secure_client_socket.recv(9999).decode()

            if received_payload == "<!quit>":
                print(Fore.LIGHTYELLOW_EX + "\n\t[!] Listening Thread Stopping [!]" + Style.RESET_ALL)
                time.sleep(1)
                break

            if received_payload == "<!alone>":
                print(Fore.LIGHTYELLOW_EX + "\n\t[!] Partner disconnected from the server! Quitting [!]" + Style.RESET_ALL)
                time.sleep(2)
                secure_client_socket.close()
                quit()

            #If we receive a message, send it to the decode function to process and print
            decode_response_message(received_payload)

        except KeyboardInterrupt:
            secure_client_socket.close()
            quit()
    
        except ConnectionResetError:
            print(Fore.RED + "\n\t[!] Lost our connection to the server! [!]" + Style.RESET_ALL)
            time.sleep(2)
            quit()

#Function to read the response from the other end of the conversation and return the decoded message
def decode_response_message(received_payload):
    #Set global variables
    global message_text, stop_threads, end_line

    #Split up the response so wee can decode it
    try:
        #First, check to see if the user sending the message is from our partner. If not, delete the message and return to the listener
        verified_partner = received_payload.split(";")[1]

        if verified_partner != user_2_endpoint:
            received_payload = ""
            print(Fore.RED + "\n\t[*] Another user tried sending a message! Message was deleted before we looked at it! [*]\n" + Style.RESET_ALL)
            return

        #Compare the message timestamp to make sure it was sent within the acceptable time frame (prevents replay/time based attackes)
        time_delta = datetime.strptime(str(datetime.now()), "%Y-%m-%d %H:%M:%S.%f") - datetime.strptime(received_payload.split(";")[2], "%Y-%m-%d %H:%M:%S.%f")

        if int(time_delta.total_seconds()) > 5:
            received_payload = ""
            print(Fore.RED + "\n\t[!] Message took a long time to be received! Deleted message and closing for possible replay attack! [!]\n" + Style.RESET_ALL)
            secure_client_socket.send("<!quit>".encode())
            time.sleep(2)
            secure_client_socket.close()
            quit()

        message_response_payload = received_payload.split(";")[3]

        #Decode the response so we can figure out what is what
        if "30303" in message_response_payload:
            #Decode hex payload
            decoded_payload = bytes.fromhex(message_response_payload).decode('utf-8')
        else:
            base64_bytes = message_response_payload.encode('ascii')
            message_bytes = base64.b64decode(base64_bytes)
            decoded_payload = message_bytes.decode('ascii')

        #Seperate out the hash, and then hash the message again to ensure that nothing was changed during transmission
        response_hash = decoded_payload[-64:]
        cypher_text = decoded_payload.split(response_hash)[0]

        data = hashlib.sha512(str(cypher_text).encode())
        verified_hash = data.hexdigest()

        if response_hash == verified_hash:
            #Decrypt our message now that we know there has been no tampering
            #Make the key the same length of the message for comparison
            i = 0
            decode_key = ""
            for x in cypher_text:
                try:
                    decode_key += key[i]
                except IndexError:
                    i = 0
                    decode_key += key[i]
                i += 1

            #Decrypt the received message text using XOR
            decoded_message = ""
            x = 0
            while x <= len(cypher_text) -1:
                if cypher_text[x] == "0":
                    decoded_message += decode_key[x]
                if cypher_text[x] == "1":
                    if decode_key[x] == "1":
                        decoded_message += "0"
                    if decode_key[x] == "0":
                        decoded_message += "1"
                x += 1
        
            #Turn decoded message to a string and throw it to the screen
            response_text = ''.join(chr(int(decoded_message[i*8:i*8+8],2)) for i in range(len(decoded_message)//8)) 

            #Verify there is nothing malicious in the response message text
            bad_chars = ["=!", "!=", "<script>", "</script>", "{", "}", ";", '"', "'", "%", "="]
            for char in bad_chars:
                if char in response_text:
                    response_text.replace(char, "")

                    #Let the user know that there were some bad characters in the response text:
                    print(Fore.LIGHTYELLOW_EX + "\n\t[!] The response text inclueded a restricted character and it was removed: ", char, " [!]" + Style.RESET_ALL)
                    return

            #Print the message to the screen for the user to see
            print(Fore.LIGHTCYAN_EX + f'\n[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] {user_2_endpoint}> ' + Style.RESET_ALL + response_text + Fore.LIGHTMAGENTA_EX)
            print(Fore.LIGHTCYAN_EX + "", end=end_line)
            return

        if response_hash != verified_hash:
            print(Fore.RED + "[!] Message payload hash did not match! Closing in the case that someone is tampering with the communication!" + Style.RESET_ALL)
            secure_client_socket.send("<!quit>".encode())
            time.sleep(2)
            secure_client_socket.close()
            quit()
            
    except IndexError:
        pass
    
    except UnicodeDecodeError:
        pass

    except KeyboardInterrupt:
        secure_client_socket.close()
        stop_threads = True
        t.join()
        quit()
    
    except ConnectionResetError:
        print(Fore.RED + "\n\t[!] Lost our connection to the server! [!]" + Style.RESET_ALL)
        secure_client_socket.send("<!quit>".encode())
        time.sleep(2)
        quit()

#Function to do all of the heavy listening for the secure messenger
def messenger():
    #Set global variables
    global message_text, stop_threads, end_line

    end_line = f'\r{user_1_endpoint}> '

    #Right now, we are just testing the implimentation of encrypting and encoding the messages, and then decosing them as well. Still need to ficure out how we will show the chat stream to the user in a CLI
    print(Fore.LIGHTBLUE_EX + "\n\n~~~~~~ Welcome to the messenger! Type '!quit' to exit the chat or '!help' for commands ~~~~~~" + Style.RESET_ALL)

    while True:
        message_text = input(Fore.LIGHTMAGENTA_EX + f'{user_1_endpoint}> ' + Style.RESET_ALL)

        #Quits out of the current session and closes socket on the server
        if message_text == "!quit":
            print(Fore.RED + "\n\t[!] Quitting the IsoCHAT Session [!]" + Style.RESET_ALL)
            secure_client_socket.send("<!quit>".encode())
            time.sleep(2)
            secure_client_socket.close()
            quit()

        #Lists the commands available to the user
        elif message_text == "!help":
            print("\tPossible Commands:\n\t\t!quit - Quit the chat and close the server socket\n\t\t!session - Shows current socket session information\n")

        #Shows session info about the current connected socket
        elif message_text == "!session":
            print("\tCurrent socket sesion info (WORK IN PROGRESS!):\n\t", f'Session connected since: {session_start_time}', "\n\t", f'Socket: {secure_client_socket}', "\n\t", f'Chatting with: {user_2_endpoint}', "\n\t", f'Socket Timeout: {secure_client_socket.gettimeout}', "\n\t", f'Cipher Used: {secure_client_socket.cipher}', "\n\t" + f'Socket Version: {secure_client_socket.version}')


        else:
            #Turn the message to binary
            binary_message = ''.join(format(ord(i), '08b') for i in message_text)

            #Make the key the same length of the message for comparison
            i = 0
            full_key = ""
            for x in binary_message:
                try:
                    full_key += key[i]
                except IndexError:
                    i = 0
                    full_key += key[i]
                i += 1

            #Encrypt the message_text using XOR
            encrypted_message = ""
            x = 0
            while x <= len(binary_message) -1:
                if binary_message[x] == full_key[x]:
                    encrypted_message += "0"
                if binary_message[x] != full_key[x]:
                        encrypted_message += "1"
                x += 1

            #Create the message payload and hash it to make sure nothing happens in transit
            payload_hash = hashlib.sha512(encrypted_message.encode())
            full_message_payload = f'{encrypted_message}{payload_hash.hexdigest()}'

            #Randomly encode the message payload to base64 or hex for further obfuscation
            guess_me = secrets.choice("12")
            if guess_me == "1":
                #Encode Payload to Base64
                message_bytes = full_message_payload.encode('ascii')
                base64_bytes = base64.b64encode(message_bytes)
                encoded_full_message_payload = base64_bytes.decode('ascii')
                
            if guess_me == "2":
                #Encode Payload to hex
                base_bytes = full_message_payload.encode('utf-8')
                encoded_full_message_payload = base_bytes.hex()
            
            #Define the final payload before sending it
            final_payload = f'{user_2_endpoint};{user_1_endpoint};{datetime.now()};{encoded_full_message_payload}'

            #Send the message
            secure_client_socket.send(final_payload.encode())

    #Stay clean and close the socket if we get here
    secure_client_socket.close()

###MAIN###
if __name__ == '__main__':
    #Error checking in the case the user hits ctrl-c in a cmd prompt running this script
    try:
        #Call the pre-chat function to 
        pre_chat()

    except KeyboardInterrupt:
        try:
            secure_client_socket.send("<!quit>".encode())
            time.sleep(2)
            secure_client_socket.close()
            quit()
        except:
            quit()
    
    except ConnectionResetError:
        print(Fore.RED + "\n\t[!] Lost our connection to the server! [!]" + Style.RESET_ALL)
        secure_client_socket.send("<!quit>".encode())
        time.sleep(2)
        secure_client_socket.close()
        quit()

'''
End of script
'''