from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import sqlite3
import base64
import json
import jwt
import datetime
import os

# Database setup
DB_FILE = "totally_not_my_privateKeys.db"

def init_db():
    """Initialize the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Key management functions
def save_private_key(private_key, exp_time):
    """Save a private key to the database."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp_time))
    conn.commit()
    conn.close()

def get_private_key(expired=False):
    """Retrieve a private key from the database, expired or valid."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if expired:
        cursor.execute("SELECT key FROM keys WHERE exp < ?", (int(datetime.datetime.utcnow().timestamp()),))
    else:
        cursor.execute("SELECT key FROM keys WHERE exp >= ?", (int(datetime.datetime.utcnow().timestamp()),))
    result = cursor.fetchone()
    conn.close()
    if result:
        return serialization.load_pem_private_key(result[0], password=None)
    return None

def generate_keys():
    """Generate an initial set of keys for the database."""
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    save_private_key(valid_key, int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()))
    save_private_key(expired_key, int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp()))

# Base64 encoding helper
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('utf-8')

# HTTP server setup
hostName = "localhost"
serverPort = 8080

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            # Select the key based on expiration request
            expired = 'expired' in params
            private_key = get_private_key(expired=expired)
            if not private_key:
                self.send_response(404)
                self.end_headers()
                return
            
            # Generate JWT
            headers = {"kid": "goodKID" if not expired else "expiredKID"}
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1) if not expired else datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            }
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT key FROM keys WHERE exp >= ?", (int(datetime.datetime.utcnow().timestamp()),))
            keys = []
            for row in cursor.fetchall():
                private_key = serialization.load_pem_private_key(row[0], password=None)
                numbers = private_key.private_numbers().public_numbers
                keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e),
                })
            conn.close()

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps({"keys": keys}), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    # Initialize database and generate initial keys
    if not os.path.exists(DB_FILE):
        init_db()
        generate_keys()
    
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
