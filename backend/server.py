from flask import Flask, request
from certificate import Certificate

app = Flask(__name__)

@app.route('/certificate', methods=['GET'])
def get_certificate_info():
    url = request.args.get('url')
    if not url:
        return 'URL is missing', 400
    
    cert = Certificate(url)
    cert_info = {
        'subject': cert.cert_info['subject'],
        'issuer': cert.cert_info['issuer'],
        'not_before': cert.cert_info['not_before'].strftime('%Y-%m-%d %H:%M:%S'),
        'not_after': cert.cert_info['not_after'].strftime('%Y-%m-%d %H:%M:%S'),
        'chain_verified': cert.cert_info['chain_verified'],
        'validity_status': cert.get_validity_status()
    }
    
    return cert_info, 200

if __name__ == '__main__':
    app.run(debug=True)