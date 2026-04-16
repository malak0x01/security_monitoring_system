import re
import sqlite3
from flask import Flask, render_template, request
from datetime import datetime

app = Flask(__name__)

# ---------------------------
# DATABASE SETUP
# ---------------------------
def init_db():
    conn = sqlite3.connect("database.db", timeout=10)
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS logs")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT,
        password TEXT
    )
    """)

    cursor.execute("DELETE FROM users")
    cursor.execute("INSERT INTO users VALUES ('admin', '1234')")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        ip TEXT,
        time TEXT,
        attack_type TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip TEXT,
        time TEXT,
        attack_type TEXT,
        message TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()


# ---------------------------
# DETECTION SYSTEM
# ---------------------------
def detect_attack(username, password):
    data = username + " " + password

    patterns = [
        (r"(\bor\b|\band\b).=.", "SQL Injection - HIGH"),
        (r"('|--|#)", "SQL Injection - MEDIUM"),
        (r"(union\s+select)", "SQL Injection - HIGH"),
        (r"(sleep\(|benchmark\()", "Time-Based Injection - HIGH"),
        (r"(<script>.*</script>)", "XSS - HIGH"),
        (r"(onerror=|onload=)", "XSS - MEDIUM")
    ]

    for pattern, attack_name in patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return attack_name

    return "Normal"



def analyze_attack_details(attack_type, username, password):
    data = (username + " " + password).lower()

    if "SQL Injection" in attack_type:
        if "union" in data:
            intent = "Dump database using UNION"
        elif "or" in data:
            intent = "Bypass login authentication"
        else:
            intent = "Manipulate SQL query"

        suggestion = "Use parameterized queries"
        risk = "HIGH"

    elif "XSS" in attack_type:
        intent = "Execute JavaScript in victim browser"
        suggestion = "Escape HTML + use CSP"
        risk = "HIGH" if "HIGH" in attack_type else "MEDIUM"

    else:
        intent = "Suspicious activity"
        suggestion = "Monitor logs"
        risk = "LOW"

    return intent, suggestion, risk

    
# ---------------------------
# ALERT SYSTEM
# ---------------------------
def create_alert(cursor, username, ip, attack_type, password):
    
    intent, suggestion, risk = analyze_attack_details(attack_type, username, password)

    if risk == "HIGH":
        message = " HIGH RISK ATTACK DETECTED"
    elif risk == "MEDIUM":
        message = " Medium risk activity"
    else:
        message = " Suspicious activity"

    cursor.execute("""
        INSERT INTO alerts (username, ip, time, attack_type, message)
        VALUES (?, ?, ?, ?, ?)
    """, (
        username,
        ip,
        str(datetime.now()),
        attack_type,
        message
    ))

    print(f"""
    [ALERT GENERATED]
    User: {username}
    IP: {ip}
    Type: {attack_type}
    Intent: {intent}
    Risk: {risk}
    Suggestion: {suggestion}
    """)

    
    
   

# ---------------------------
# ROUTES
# ---------------------------

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        attack_type = detect_attack(username, password)

        ip = request.remote_addr
        time = datetime.now()

        conn = sqlite3.connect("database.db", timeout=10)
        cursor = conn.cursor()

        # LOGGING
        cursor.execute(
            "INSERT INTO logs (username, password, ip, time, attack_type) VALUES (?, ?, ?, ?, ?)",
            (username, password, ip, str(time), attack_type)
        )

        # ALERT
        if attack_type != "Normal":
            create_alert(cursor, username, ip, attack_type, password)
            print(f"[ALERT] {attack_type} from {ip}")

        # VULNERABLE QUERY (intentional)
        try:
         query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
         result = cursor.execute(query).fetchone()
        except sqlite3.OperationalError as e:
            print(f"SQL Error (Expected during attack): {e}")
            result = None

        conn.commit()
        conn.close()

        if result:
            return f"Logged in successfully! Welcome {username}"
        else:
            return f"Login failed for user: {username} "

    return render_template("login.html")


# ---------------------------
# VIEW LOGS
# ---------------------------
@app.route("/logs")
def show_logs():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    logs = cursor.execute("SELECT * FROM logs").fetchall()
    conn.close()

    return render_template("logs.html", logs=logs)


# ---------------------------
# VIEW ALERTS
# ---------------------------
@app.route("/alerts")
def show_alerts():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    alerts = cursor.execute("SELECT * FROM alerts").fetchall()
    conn.close()

    return render_template("alerts.html", alerts=alerts)


@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    total_logs = cursor.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    total_alerts = cursor.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    attack_stats = cursor.execute("""
        SELECT attack_type, COUNT(*) 
        FROM logs 
        GROUP BY attack_type
    """).fetchall()

    conn.close()

    
    labels = [row[0] for row in attack_stats]
    values = [row[1] for row in attack_stats]

    return render_template(
        "dashboard.html",
        total_logs=total_logs,
        total_alerts=total_alerts,
        labels=labels,
        values=values
    )

# ---------------------------
# RUN SERVER
# ---------------------------
app.run(debug=True)