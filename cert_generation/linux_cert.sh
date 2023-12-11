#!/bin/bash

# Set up variables
SSL_CONFIG_FILE="openssl.cnf"
SSL_BACKUP_FILE="openssl.cnf.bak"

SSL_CHAT_CONFIGURATION="[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = Country Code
ST = State
L = Location
O = Organization Name
OU = Organizational Unit Name
CN = Common Name

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[server]
basicConstraints = CA:FALSE
nsCertType = server
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth

[client]
basicConstraints = CA:FALSE
nsCertType = client
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = clientAuth

[alt_names]
DNS.1 = Server Common Name
DNS.2 = Another Server Common Name
"

## Validations
# Check if the script was run as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root. Please close and re-run the script with root privileges."
   exit 1

## OpenSSL Installation
# Check if openssl is installed
if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is not installed. Installing now..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # For Debian/Ubuntu based systems
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get install openssl
        # For CentOS/RHEL based systems
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install openssl
        # For Fedora based systems
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install openssl
        fi

    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # For macOS, install Homebrew if it's not installed yet
        if ! command -v brew >/dev/null 2>&1; then
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        # Install openssl using Homebrew
        brew install openssl

    elif [[ "$OSTYPE" == "cygwin" ]]; then
        # For Cygwin
        sudo apt-cyg install openssl

    else
        echo "Unsupported OS distribution. Please install openssl manually."
    fi
    echo "openssl installed successfully!"
else
    echo "openssl is already installed!"
fi

## OpenSSL Configuration
# Check if the openssl.cnf file exists
if [ -f $SSL_CONFIG_FILE ]; then
    # If it exists, create a backup and replace the contents
    cp $SSL_CONFIG_FILE $SSL_BACKUP_FILE
    echo "$SSL_CHAT_CONFIGURATION" > $SSL_CONFIG_FILE
else
    # If it doesn't exist, create a new file with the provided configuration
    echo "$SSL_CHAT_CONFIGURATION" > $CONFIG_FILE
fi

echo "Existing OpenSSL config file backed up to openssl.cnf.bak and new config file created for IsoCHAT use!"

## Generate Certs and Sign with CA
# Generate client key
openssl genpkey -algorithm RSA -out client.key.pem

# Generate server key
openssl genpkey -algorithm RSA -out server.key.pem

# Generate CA key
openssl genpkey -algorithm RSA -out ca.key.pem

# Generate CA certificate
openssl req -new -key ca.key.pem -out ca.csr.pem -subj "/C=US/ST=Oceania/L=Airstrip One/O=CSCG/OU=SEC_IsoCHAT/CN=CA"
openssl x509 -req -in ca.csr.pem -out ca.crt.pem -signkey ca.key.pem -days 365

# Generate a Certificate Signing Request (CSR) for the client
openssl req -new -key client.key.pem -out client.csr.pem -subj "/C=US/ST=Oceania/L=Airstrip One/O=CSCG/OU=SEC_IsoCHAT/CN=client"

# Generate a Certificate Signing Request (CSR) for the server
openssl req -new -key server.key.pem -out server.csr.pem -subj "/C=US/ST=Oceania/L=Airstrip One/O=CSCG/OU=SEC_IsoCHAT/CN=server"

# Sign the client's CSR with the CA private key to create a client certificate
openssl x509 -req -in client.csr.pem -out client.crt.pem -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial -days 365

# Sign the server's CSR with the CA private key to create a server certificate
openssl x509 -req -in server.csr.pem -out server.crt.pem -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial -days 365

# Concatenate CA certificate and client certificate
cat ca.crt.pem client.crt.pem > ca-chain-bundle.cert.pem

# Concatenate CA certificate and server certificate
cat ca.crt.pem server.crt.pem > ca-chain-bundle.server.cert.pem

echo "Client and server certificates generated successfully and signed by CA."