██████╗░░█████╗░███╗░░░███╗██╗███████╗░█████╗░███████╗██╗░░██╗
██╔══██╗██╔══██╗████╗░████║██║██╔════╝██╔══██╗██╔════╝╚██╗██╔╝
██████╔╝██║░░██║██╔████╔██║██║██████╗░██║░░██║█████╗░░░╚███╔╝░
██╔══██╗██║░░██║██║╚██╔╝██║██║╚════██╗██║░░██║██╔══╝░░░██╔██╗░
██║░░██║╚█████╔╝██║░╚═╝░██║██║██████╔╝╚█████╔╝███████╗██╔╝╚██╗
╚═╝░░╚═╝░╚════╝░╚═╝░░░░░╚═╝╚═╝╚═════╝░░╚════╝░╚══════╝╚═╝░░╚═╝

Creating a Self-Signed Public Certificate for HTTPS Authentication

Project Overview:
In this project, we will generate a self-signed public certificate (X.509) to authenticate an HTTPS application. The certificate will be created using OpenSSL and must adhere to specific requirements outlined below. 

Project Requirements:
1. Provide a ReadMe file for each step and command.
2. Certificate must meet the policy and all requirements outlined below.

Steps to Create the Certificate:

Step 1: Generate a Private Key
openssl genrsa -out private_key.pem 3072
- This command generates a 3072-bit RSA private key and saves it as private_key.pem.

Step 2: Create a Certificate Signing Request (CSR)
openssl req -new -key private_key.pem -out csr.pem -subj "/CN=usca.edu"
- This command creates a Certificate Signing Request (CSR) using the private key and sets the common name (CN) to usca.edu.

Step 3: Create the Self-Signed Certificate
openssl x509 -req -in csr.pem -signkey private_key.pem -out public_cert.pem -days 365 -extfile san.ext -sha384
- This command creates a self-signed X.509 certificate using the CSR, private key, and specified parameters.
- The certificate is valid for 365 days.
- The -extfile option specifies a file (san.ext) containing Subject Alternative Name (SAN) information.

Step 4: Export the Certificate with Private Key
openssl pkcs12 -export -out certificate.pfx -inkey private_key.pem -in public_cert.pem -passout pass:your_password
- This command exports the certificate and private key into a PKCS#12 file (certificate.pfx) protected by a password.

Certificate Requirements and Compliance:

Cryptographic Parameters RSA: The certificate is generated using RSA encryption.
3072-bit Key Length: The private key has a length of 3072 bits.
Hash Algorithm SHA384: The certificate is signed using SHA-384 hash algorithm.
Validity Period One Year: The certificate is valid for one year.
Subject CN = usca.edu: The common name of the subject is set to usca.edu.
Subject Alternative Name: The certificate includes SANs for www.usca.edu and specified IP addresses.
Certificate Version V3: The certificate is version 3, supporting both client and server authentication.
