import ssl
import socket
import hashlib
import OpenSSL
import base64
import os
from datetime import datetime

def get_cert_chain(domain, port=443):
    """Retrieve the full certificate chain from the given domain."""
    context = ssl.create_default_context()

    with socket.create_connection((domain, port)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            # Extract the peer's certificate (leaf certificate)
            leaf_cert_der = ssock.getpeercert(binary_form=True)
            leaf_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, leaf_cert_der)
            
            # Get the entire certificate chain
            chain = [leaf_cert]
            for der_cert in ssock.get_verified_chain():
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)
                chain.append(cert)
    
    return chain

def get_spki_sha256(cert):
    """Generate SHA-256 fingerprint of the certificate's public key (SPKI)."""
    public_key = cert.get_pubkey()
    
    # Get the public key in DER format
    public_key_der = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1, public_key)
    
    # Compute the SHA-256 hash of the public key
    sha256_hash = hashlib.sha256(public_key_der).digest()
    
    # Return the Base64 encoded SHA-256 hash (fingerprint)
    fingerprint = base64.b64encode(sha256_hash).decode()
    return fingerprint

def save_cert(cert, folder):
    """Save the certificate in both PEM and DER formats to a specified folder with CN as filename."""
    # Save in PEM format
    cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    pem_filename = os.path.join(folder, f"{cert.get_subject().CN}.pem")
    with open(pem_filename, "wb") as pem_file:
        pem_file.write(cert_pem)
    print(f"Certificate saved as {pem_filename}")
    
    # Save in DER format
    cert_der = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
    der_filename = os.path.join(folder, f"{cert.get_subject().CN}.der")
    with open(der_filename, "wb") as der_file:
        der_file.write(cert_der)
    print(f"Certificate saved as {der_filename}")

def create_domain_folder(domain):
    """Create a folder for the domain to store certificates."""
    domain_folder = domain
    if not os.path.exists(domain_folder):
        os.makedirs(domain_folder)
    return domain_folder

def get_expiry_date(cert):
    """Get the expiry date of the certificate."""
    # Extract the notAfter field (expiry date)
    not_after = cert.get_notAfter().decode('utf-8')
    # Convert it from ASN.1 format (UTC time) to a more readable format
    expiry_date = datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
    return expiry_date.strftime('%Y-%m-%d %H:%M:%S')

def process_cert_chain(cert_chain, domain_folder):
    """Process each certificate in the chain: Save in both formats, display SPKI SHA-256, and expiry date."""
    print(f"\nCertificate Chain for {domain_folder}:\n" + "="*40)
    
    for idx, cert in enumerate(cert_chain):
        # Save the certificate in both PEM and DER formats
        save_cert(cert, domain_folder)
        
        # Get the CN (Common Name) of the certificate
        subject = cert.get_subject().CN
        
        # Get the SPKI SHA-256 fingerprint
        spki_fingerprint = get_spki_sha256(cert)
        
        # Get the expiry date
        expiry_date = get_expiry_date(cert)
        
        # Print certificate details
        print(f"\nCertificate {idx+1}: {subject}")
        print(f"SPKI SHA-256 Fingerprint: {spki_fingerprint}")
        print(f"Expiry Date: {expiry_date}")

def main():
    domain = input("Enter domain (e.g., example.com): ").strip()
    
    try:
        # Get certificate chain for the given domain
        cert_chain = get_cert_chain(domain)
        
        # Create a folder for storing the certificates
        domain_folder = create_domain_folder(domain)
        
        # Process and save the certificate chain in both PEM and DER formats
        process_cert_chain(cert_chain, domain_folder)

    except Exception as e:
        print(f"Error retrieving certificates: {e}")

if __name__ == "__main__":
    main()