# Set up variables
$SSL_CONFIG_FILE = "openssl.cnf"
$SSL_BACKUP_FILE = "openssl.cnf.bak"

$SSL_CHAT_CONFIGURATION = @"
[req]
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
"@

##Validations
# Check if the script was run as administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as administrator. Please close and re-run the script with administrator privileges."
    exit 1
}

## OpenSSL Installation
# Check if openssl is installed
if (-not (Get-Command "openssl.exe" -ErrorAction SilentlyContinue)) {
    # You need to manually download and install OpenSSL on Windows: https://slproweb.com/products/Win32OpenSSL.html
    Write-Host "OpenSSL is not installed and needs to be manually installed on Windows: https://slproweb.com/products/Win32OpenSSL.html"
    exit 2

} else {
    Write-Host "openssl is already installed!"
}

## OpenSSL Configuration
# Check if the openssl.cnf file exists
if (Test-Path $SSL_CONFIG_FILE) {
    # If it exists, create a backup and replace the contents
    Copy-Item $SSL_CONFIG_FILE $SSL_BACKUP_FILE
    Set-Content -Path $SSL_CONFIG_FILE -Value $SSL_CHAT_CONFIGURATION
} else {
    # If it doesn't exist, create a new file with the provided configuration
    Set-Content -Path $SSL_CONFIG_FILE -Value $SSL_CHAT_CONFIGURATION
}

Write-Host "Existing OpenSSL config file backed up to openssl.cnf.bak and new config file created for IsoCHAT use!"

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
Get-Content ca.crt.pem, client.crt.pem | Set-Content -Path ca-chain-bundle.cert.pem

# Concatenate CA certificate and server certificate
Get-Content ca.crt.pem, server.crt.pem | Set-Content -Path ca-chain-bundle.server.cert.pem

Write-Host "Client and server certificates generated successfully and signed by CA."

exit 0