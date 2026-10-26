import os, sqlite3, secrets, logging
from flask import Flask, g, request, session, redirect, render_template_string, abort, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("PORTAL_SECRET_KEY") or secrets.token_hex(32)
production_mode = os.environ.get("APP_ENV", "development").lower() == "production"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=production_mode,
    MAX_CONTENT_LENGTH=16 * 1024,
)
DB = os.environ.get("PORTAL_DB", "finance_demo.db")
logging.basicConfig(level=logging.INFO)
HTML = """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Secure Finance Portal</title><style>
body{margin:0;background:#f2f5fb;color:#172033;font:16px system-ui}header{background:#14213d;color:white;padding:22px 6%;display:flex;justify-content:space-between}main{max-width:850px;margin:30px auto;padding:0 18px}.card{background:white;border:1px solid #dce3ef;border-radius:14px;padding:22px;margin:16px 0}input,select,button{font:inherit;padding:11px;border:1px solid #cbd5e1;border-radius:8px;margin:6px 0;width:100%}button{background:#3159d9;color:white;border:0;cursor:pointer}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #e5eaf2}.muted{color:#64748b}.pill{background:#e8efff;color:#2447a8;border-radius:20px;padding:5px 9px;font-size:13px}</style></head><body><header><b>◈ Secure Finance Portal</b><span>{{ user or 'Security lab demo' }}</span></header><main>{% for m in get_flashed_messages() %}<div class=card>{{m}}</div>{% endfor %}
{% if not user %}<section class=card style=max-width:450px;margin:60px auto><span class=pill>LOCAL DEMO</span><h1>Welcome back</h1><p class=muted>Demonstrating secure authentication and access control.</p><form method=post><input type=hidden name=csrf_token value="{{csrf}}"><label>Email</label><input type=email name=email required><label>Password</label><input type=password name=password required><button>Sign in</button></form><small>Demo credentials are in README.md</small></section>
{% else %}<h1>Account overview</h1><p class=muted>Your records are filtered by your authenticated user ID.</p><div class=grid><section class=card><small>Total income</small><h2>₹{{'%.2f'|format(income)}}</h2></section><section class=card><small>Total expenses</small><h2>₹{{'%.2f'|format(expense)}}</h2></section><section class=card><small>Balance</small><h2>₹{{'%.2f'|format(income-expense)}}</h2></section></div><section class=card><h2>Add transaction</h2><form method=post action=/add><input type=hidden name=csrf_token value="{{csrf}}"><div class=grid><label>Type<select name=kind><option value=expense>Expense</option><option value=income>Income</option></select></label><label>Amount (₹)<input type=number name=amount min=0.01 max=10000000 step=0.01 required></label></div><label>Description<input name=description maxlength=100 required></label><button>Add transaction</button></form></section><section class=card><h2>Transactions</h2>{% if rows %}<table><tr><th>Type</th><th>Description</th><th>Amount</th><th></th></tr>{% for r in rows %}<tr><td>{{r.kind|title}}</td><td>{{r.description}}</td><td>₹{{'%.2f'|format(r.amount)}}</td><td><form method=post action="/delete/{{r.id}}"><input type=hidden name=csrf_token value="{{csrf}}"><button>Delete</button></form></td></tr>{% endfor %}</table>{% else %}<p class=muted>No transactions yet.</p>{% endif %}</section><section class=card><h2>Security controls</h2><div class=grid><p>✓ Password hashing<br>✓ CSRF protection</p><p>✓ Parameterized SQL<br>✓ User isolation</p><p>✓ Server-side validation<br>✓ Security headers</p></div><form method=post action=/logout><input type=hidden name=csrf_token value="{{csrf}}"><button>Log out</button></form><small>Educational prototype; never use real financial data.</small></section>{% endif %}</main></body></html>"""

def db():
    if "db" not in g:
        g.db=sqlite3.connect(DB); g.db.row_factory=sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    c=g.pop("db",None)
    if c: c.close()

def init_db():
    c=sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,password_hash TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('income','expense')),amount REAL NOT NULL CHECK(amount>0),description TEXT NOT NULL)")
    for email,pw in [("alice@example.com","AliceDemo!23"),("bob@example.com","BobDemoPass!23")]:
        if not c.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone():
            c.execute("INSERT INTO users(email,password_hash) VALUES(?,?)",(email,generate_password_hash(pw)))
    c.commit(); c.close()

def token():
    if "_csrf" not in session: session["_csrf"]=secrets.token_urlsafe(32)
    return session["_csrf"]

def check_csrf():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("_csrf", "")
    if not submitted or not expected or not secrets.compare_digest(submitted, expected):
        # Never log the submitted token or session contents.
        logging.warning("csrf_rejected method=%s path=%s", request.method, request.path)
        abort(400, "Invalid CSRF token")

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapped(*a,**kw):
        if "uid" not in session: return redirect("/")
        return fn(*a,**kw)
    return wrapped

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    r.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    )
    r.headers["Cache-Control"] = "no-store"
    if production_mode:
        # Render terminates HTTPS before forwarding requests to the Python service.
        r.headers["Strict-Transport-Security"] = "max-age=31536000"
    return r

@app.errorhandler(400)
def bad_request(_error):
    # Log the event category/path, never the submitted form contents.
    logging.warning("bad_request method=%s path=%s", request.method, request.path)
    return "Request rejected. Check your submitted input and try again.", 400

@app.errorhandler(404)
def not_found(_error):
    return "Page or record not found.", 404

@app.errorhandler(500)
def internal_error(error):
    # Keep details in server logs; return no stack trace to the browser.
    app.logger.error("internal_error path=%s type=%s", request.path, type(error).__name__)
    return "An unexpected error occurred. Please try again later.", 500

@app.route("/",methods=["GET","POST"])
def home():
    if request.method=="POST":
        check_csrf(); email=request.form.get("email","").strip().lower(); pw=request.form.get("password","")
        u=db().execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        if u and check_password_hash(u["password_hash"],pw):
            session.clear(); session["uid"]=u["id"]; session["email"]=u["email"]; session["_csrf"]=secrets.token_urlsafe(32)
            logging.info("login success user_id=%s",u["id"]); return redirect("/")
        logging.warning("login_failed")
        flash("Invalid email or password.")
    csrf=token()
    if "uid" not in session: return render_template_string(HTML,user=None,csrf=csrf)
    rows=db().execute("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC",(session["uid"],)).fetchall()
    inc=sum(x["amount"] for x in rows if x["kind"]=="income"); exp=sum(x["amount"] for x in rows if x["kind"]=="expense")
    return render_template_string(HTML,user=session["email"],csrf=csrf,rows=rows,income=inc,expense=exp)

@app.post("/add")
@login_required
def add():
    check_csrf()
    try: amount=float(request.form.get("amount",""))
    except ValueError: abort(400,"Amount must be numeric")
    desc=request.form.get("description","").strip(); kind=request.form.get("kind","")
    if not 0<amount<=10000000 or kind not in ("income","expense") or not desc or len(desc)>100: abort(400,"Invalid transaction fields")
    db().execute("INSERT INTO transactions(user_id,kind,amount,description) VALUES(?,?,?,?)",(session["uid"],kind,amount,desc)); db().commit()
    logging.info("transaction_created user_id=%s", session["uid"])
    flash("Transaction added."); return redirect("/")

@app.post("/delete/<int:tid>")
@login_required
def delete(tid):
    check_csrf()
    cur=db().execute("DELETE FROM transactions WHERE id=? AND user_id=?",(tid,session["uid"])); db().commit()
    if not cur.rowcount: abort(404)
    logging.info("transaction_deleted user_id=%s transaction_id=%s", session["uid"], tid)
    flash("Transaction deleted."); return redirect("/")

@app.post("/logout")
@login_required
def logout():
    check_csrf()
    logging.info("logout user_id=%s", session["uid"])
    session.clear()
    return redirect("/")

init_db()
if __name__=="__main__": app.run(host="127.0.0.1",port=int(os.environ.get("PORT","5000")),debug=False)
