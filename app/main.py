"""
Deliberately Vulnerable FastAPI Application
-------------------------------------------
This app is INTENTIONALLY INSECURE for DevSecOps pipeline demonstration.
Each vulnerability is labeled with which security tool is expected to catch it.
DO NOT deploy this to production.
"""

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
import sqlite3
import subprocess
import hashlib

# ── VULN-1 (SAST): Hardcoded credentials ─────────────────────────────────────
SECRET_KEY = "hardcoded_secret_abc123"
DB_PASS    = "admin123"
API_KEY    = "sk-prod-abc123xyz789"
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(title="Vulnerable FastAPI App")


# ── Database setup (in-memory SQLite) ────────────────────────────────────────
def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        "CREATE TABLE users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'password123', 'admin')")
    conn.execute("INSERT INTO users VALUES (2, 'alice', 'alice456',    'user')")
    conn.commit()
    return conn


DB = init_db()
# ─────────────────────────────────────────────────────────────────────────────


# ── Route 1: Home (clean, no vulnerability) ───────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html><body>
      <h1>Vulnerable FastAPI Demo</h1>
      <ul>
        <li><a href="/search">Search</a></li>
        <li><a href="/login">Login</a></li>
        <li><a href="/admin">Admin Panel</a></li>
        <li><a href="/ping?host=localhost">Ping</a></li>
        <li><a href="/file?name=readme.txt">Read File</a></li>
        <li><a href="/hash">Hash Tool</a></li>
      </ul>
    </body></html>
    """


# ── Route 2: Reflected XSS ────────────────────────────────────────────────────
# VULN-2 (DAST): User input is interpolated directly into the HTML response.
# Payload: /search?q=<script>alert(1)</script>
@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    results = f"<h2>Search results for: {q}</h2>" if q else ""
    return f"""
    <html><body>
      <h1>Search</h1>
      <form method="get" action="/search">
        <input name="q" value="{q}" placeholder="Search..." style="width:300px">
        <button type="submit">Search</button>
      </form>
      {results}
    </body></html>
    """


# ── Route 3a: Login form ──────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
def login_form():
    return """
    <html><body>
      <h1>Login</h1>
      <form method="post" action="/login">
        <p><input name="username" placeholder="Username" style="width:200px"></p>
        <p><input name="password" type="password" placeholder="Password" style="width:200px"></p>
        <button type="submit">Login</button>
      </form>
    </body></html>
    """


# ── Route 3b: SQL Injection ───────────────────────────────────────────────────
# VULN-3 (SAST + DAST): String concatenation builds the SQL query.
# Bypass payload: username=admin'--  password=anything
@app.post("/login", response_class=HTMLResponse)
def login(username: str = Form(...), password: str = Form(...)):
    query = (
        f"SELECT * FROM users "
        f"WHERE username='{username}' AND password='{password}'"
    )
    result = DB.execute(query).fetchone()
    if result:
        return f"""
        <html><body>
          <p style="color:green"><strong>Welcome, {result[1]}!</strong> (role: {result[3]})</p>
          <a href="/login">Try again</a>
        </body></html>
        """
    return """
    <html><body>
      <p style="color:red"><strong>Invalid credentials.</strong></p>
      <a href="/login">Try again</a>
    </body></html>
    """


# ── Route 4: Broken Access Control ────────────────────────────────────────────
# VULN-4 (DAST): No authentication check — anyone can reach the admin panel.
@app.get("/admin", response_class=HTMLResponse)
def admin():
    users = DB.execute("SELECT id, username, role FROM users").fetchall()
    rows = "".join(f"<tr><td>{u[0]}</td><td>{u[1]}</td><td>{u[2]}</td></tr>" for u in users)
    return f"""
    <html><body>
      <h1>Admin Panel</h1>
      <table border='1'><tr><th>ID</th><th>Username</th><th>Role</th></tr>{rows}</table>
    </body></html>
    """


# ── Route 5: Command Injection ────────────────────────────────────────────────
# VULN-5 (SAST + DAST): shell=True with unsanitized user input.
# Injection payload: /ping?host=localhost;cat+/etc/passwd
@app.get("/ping", response_class=HTMLResponse)
def ping(host: str = "localhost"):
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    output = result.stdout or result.stderr
    return f"<html><body><pre>{output}</pre></body></html>"


# ── Route 6: Path Traversal ───────────────────────────────────────────────────
# VULN-6 (SAST + DAST): File path built from user input with no sanitization.
# Traversal payload: /file?name=../../etc/passwd
@app.get("/file", response_class=HTMLResponse)
def read_file(name: str = "variables.txt"):
    with open(f"/app/files/{name}") as f:
        content = f.read()
    return f"<html><body><pre>{content}</pre></body></html>"


# ── Route 7a: Hash form ───────────────────────────────────────────────────────
@app.get("/hash", response_class=HTMLResponse)
def hash_form():
    return """
    <html><body>
      <h1>Hash Tool</h1>
      <form method="post" action="/hash">
        <p><input name="value" placeholder="Value to hash" style="width:300px"></p>
        <button type="submit">Hash (MD5)</button>
      </form>
    </body></html>
    """


# ── Route 7b: Insecure Cryptography ──────────────────────────────────────────
# VULN-7 (SAST): MD5 is cryptographically broken; never use it for passwords.
@app.post("/hash", response_class=HTMLResponse)
def hash_password(value: str = Form(...)):
    hashed = hashlib.md5(value.encode()).hexdigest()
    return f"""
    <html><body>
      <h1>Hash Result</h1>
      <p><strong>Input:</strong> {value}</p>
      <p><strong>Algorithm:</strong> MD5</p>
      <p><strong>Hash:</strong> <code>{hashed}</code></p>
      <a href="/hash">Hash another</a>
    </body></html>
    """
