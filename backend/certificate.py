import subprocess
import ssl
import socket
import datetime

class Certificate:
    def __init__(self, url):
        self.url = url
        self.cert_info = self.get_certificate_info()
    
    def get_certificate_info(self):
        cert_info = {}
        context = ssl.create_default_context()
        with socket.create_connection((self.url, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=self.url) as sslsock:
                # get the SSL/TLS certificate presented by the server
                cert = sslsock.getpeercert(binary_form=True)
                x509 = ssl.DER_cert_to_PEM_cert(cert)
                cert_info['pem'] = x509.decode()
                
                # parse the certificate and extract the subject, issuer, and validity period
                cert = sslsock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                cert_info['subject'] = subject
                cert_info['issuer'] = issuer
                cert_info['not_before'] = not_before
                cert_info['not_after'] = not_after

                # verify the certificate chain using the openssl verify command
                openssl_command = f"openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt <(echo '{x509.decode()}')"
                process = subprocess.run(openssl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output = process.stdout.decode().strip()
                if output == f"{x509.decode()}: OK":
                    cert_info['chain_verified'] = True
                else:
                    cert_info['chain_verified'] = False

                # check for certificate revocation using the openssl crl command
                openssl_command = f"openssl crl -noout -issuer -lastupdate -nextupdate -fingerprint -hash -in /etc/ssl/certs/ca-certificates.crl -inform DER"
                process = subprocess.run(openssl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                crl_info = process.stdout.decode().strip().split('\n')
                crl_hash = crl_info[4].split('=')[1].replace(':', '').lower()
                openssl_command = f"openssl crl -noout -in /etc/ssl/certs/ca-certificates.crl -inform DER -hash -crldays 1 -lastupdate -nextupdate -fingerprint -issuer -nameopt RFC2253 -out /dev/stdout | grep -A1 {crl_hash}"
                process = subprocess.run(openssl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output = process.stdout.decode().strip().split('\n')
                crl_issuer = output[0].split('=')[1]
                crl_info = dict(x.split(': ') for x in output[1].split(', '))
                crl_lastupdate = datetime.datetime.strptime(crl_info['Last Update'], '%b %d %H:%M:%S %Y %Z')
                crl_nextupdate = datetime.datetime.strptime(crl_info['Next Update'], '%b %d %H:%M:%S %Y %Z
            # check the validity period of the certificate
            cert_not_before = cert.get_notBefore().decode('utf-8')
            cert_not_after = cert.get_notAfter().decode('utf-8')
            not_before_date = datetime.datetime.strptime(cert_not_before, '%Y%m%d%H%M%SZ')
            not_after_date = datetime.datetime.strptime(cert_not_after, '%Y%m%d%H%M%SZ')
            current_time = datetime.datetime.utcnow()

            if current_time < not_before_date:
                validity_status = "Certificate is not yet valid."
            elif current_time > not_after_date:
                validity_status = "Certificate has expired."
            else:
                validity_status = "Certificate is valid."
