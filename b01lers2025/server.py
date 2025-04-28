import base64
import flask
import os
import sqlite3
import tempfile
import urllib

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

try:
    with open("flag.txt") as file:
        flag = file.read().strip()
    assert(len(flag) > 100)
except FileNotFoundError:
    flag = "bctf{fake}"

db_file = tempfile.NamedTemporaryFile("x", suffix=".db")
readonly = False

def execute(query, parameters=()):
    if readonly:
        db = sqlite3.connect(f"file:{db_file.name}?mode=ro", uri=True)
    else:
        db = sqlite3.connect(db_file.name)
    cursor = db.cursor()
    result = cursor.execute(query, parameters).fetchone()
    db.commit()
    cursor.close()
    db.close()
    return result

execute("CREATE TABLE users(name varchar(100), auth_secret varchar(100))")
execute("INSERT INTO users VALUES ('admin', ?)", [flag])
execute("INSERT INTO users VALUES ('guest', '123')")
readonly = True

sha = SHA256.new()
sha.update(flag.encode())
key = sha.digest()[:16]

app = flask.Flask(__name__)

@app.route("/", methods=["GET"])
def get():
    encoded1 = flask.request.args.get("username", None)
    encoded2 = flask.request.args.get("password", None)

    if encoded1 and encoded2:
        ciphertext1 = bytes.fromhex(encoded1)
        ciphertext2 = bytes.fromhex(encoded2)

        cipher = AES.new(key, AES.MODE_CBC, ciphertext1[:16])
        padded1 = cipher.decrypt(ciphertext1[16:])
        cipher = AES.new(key, AES.MODE_CBC, ciphertext2[:16])
        padded2 = cipher.decrypt(ciphertext2[16:])

        username = padded1.decode("ascii", errors="replace").rstrip(" ")
        password = padded2.decode("ascii", errors="replace").rstrip(" ")

        try:
            query = f"SELECT * FROM users WHERE name='{username}' AND auth_secret='{password}'"
            user = execute(query)
        except sqlite3.Error as e:
            flask.abort(500, f"Database error: {e}")

        if not user:
            flask.abort(400, "Incorrect username or password")

        text = f"Welcome, {username}!"
    else:
        text = "Login to continue."

    return f"""
        <html>
            <body>
                {text} <br>
                <form method="POST">
                    User: <input type="text" name="username" />
                    Password: <input type="text" name="password" />
                    <input type="submit" value="Submit" />
                </form>
            </body>
        </html>
    """

@app.route("/", methods=["POST"])
def post():
    username = flask.request.form.get("username")
    if not username: flask.abort(400, "Missing username parameter")
    password = flask.request.form.get("password")
    if not password: flask.abort(400, "Missing password parameter")

    allowed_characters = "abcdefghijklmnopqrstuvwxyz1234567890_{}"

    for c in username:
        if not c in allowed_characters:
            flask.abort(400, "Illegal character in username")
    for c in password:
        if not c in allowed_characters:
            flask.abort(400, "Illegal character in password")

    padded1 = (username + " " * (-len(username) % AES.block_size)).encode()
    padded2 = (password + " " * (-len(password) % AES.block_size)).encode()

    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext1 = cipher.iv + cipher.encrypt(padded1)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext2 = cipher.iv + cipher.encrypt(padded2)
    
    encoded1 = ciphertext1.hex()
    encoded2 = ciphertext2.hex()

    return flask.redirect(f"/?username={encoded1}&password={encoded2}")
    
app.secret_key = get_random_bytes(8)
if __name__ == "__main__":
    app.run("0.0.0.0", os.environ.get("PORT", 8080))
