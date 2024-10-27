from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

hostName = "localhost"
serverPort = 8080

# Initialize SQLite database connection
db_conn = sqlite3.connect("totally_not_my_privateKeys.db")
cursor = db_conn.cursor()

# Create the keys table if it doesn't exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS keys (
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
""")
db_conn.commit()

# Generate RSA private keys
def generate_key(expiry_hours):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expiry = int((datetime.datetime.utcnow() + datetime.timedelta(hours=expiry_hours)).timestamp())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem, expiry

# Store keys in the database: one valid and one expired
valid_key_pem, valid_key_exp = generate_key(1)  # Expires in 1 hour
expired_key_pem, expired_key_exp = generate_key(-1)  # Already expired
cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (valid_key_pem, valid_key_exp))
cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_key_pem, expired_key_exp))
db_conn.commit()

# Helper function for Base64 URL encoding
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            cursor.execute("SELECT key, exp FROM keys WHERE exp >= ?", (int(datetime.datetime.utcnow().timestamp()),))
            result = cursor.fetchone() if 'expired' not in params else None
            
            # If expired is requested or no valid key found, try fetching an expired key
            if 'expired' in params or not result:
                cursor.execute("SELECT key, exp FROM keys WHERE exp < ?", (int(datetime.datetime.utcnow().timestamp()),))
                result = cursor.fetchone()
                
            if result:
                pem, exp = result
                headers = {"kid": "goodKID" if exp >= datetime.datetime.utcnow().timestamp() else "expiredKID"}
                private_key = serialization.load_pem_private_key(pem, password=None)
                
                token_payload = {
                    "user": "username",
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                }
                encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
                return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            # Fetch all non-expired keys from the database for JWKS
            cursor.execute("SELECT key FROM keys WHERE exp >= ?", (int(datetime.datetime.utcnow().timestamp()),))
            keys = cursor.fetchall()
            jwks_keys = []
            
            for (pem,) in keys:
                private_key = serialization.load_pem_private_key(pem, password=None)
                numbers = private_key.private_numbers()
                
                jwks_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                })
                
            response = {"keys": jwks_keys}
            self.wfile.write(bytes(json.dumps(response), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started http://{hostName}:{serverPort}")
    
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
    db_conn.close()
