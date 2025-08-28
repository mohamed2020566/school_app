# -*- coding: utf-8 -*-
import os
import sqlite3
import datetime
import secrets
from functools import wraps
from io import StringIO, BytesIO
from hashlib import sha256
import smtplib
from email.message import EmailMessage
import json
import requests

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_file, flash
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")
DB_PATH = os.path.join(os.path.dirname(__file__), "school.db")

# ====== SMTP (اختياري) ======
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
MAIL_FROM = os.environ.get("MAIL_FROM", "no-reply@example.com")

# ====== Chargily Pay (V2) ======
CHARGILY_SECRET_KEY = os.environ.get("CHARGILY_SECRET_KEY")  # sk_test_xxx أو sk_live_xxx
CHARGILY_LIVE = os.environ.get("CHARGILY_LIVE", "0") == "1"
CHARGILY_SUCCESS_URL = os.environ.get("CHARGILY_SUCCESS_URL", "http://localhost:5000/account")
CHARGILY_BASE = "https://pay.chargily.net/api/v2" if CHARGILY_LIVE else "https://pay.chargily.net/test/api/v2"

# إعدادات الاشتراك
TRIAL_DAYS = 7
BILLING_DAYS = 30
MONTHLY_PRICE_DZD = int(os.environ.get("MONTHLY_PRICE_DZD", "1000"))

# =============================
# DB helpers
# =============================
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def column_exists(cur, table, column):
    cur.execute("PRAGMA table_info({})".format(table))
    return any(r["name"] == column for r in cur.fetchall())

def init_db():
    conn = get_db()
    cur = conn.cursor()

    # users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','teacher')) DEFAULT 'teacher',
            trial_started_at TEXT,
            trial_ends_at TEXT
        );
    """)
    for col, ddl in [
        ("email", "ALTER TABLE users ADD COLUMN email TEXT UNIQUE"),
        ("username", "ALTER TABLE users ADD COLUMN username TEXT"),
        ("role", "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'teacher'"),
        ("trial_started_at", "ALTER TABLE users ADD COLUMN trial_started_at TEXT"),
        ("trial_ends_at", "ALTER TABLE users ADD COLUMN trial_ends_at TEXT"),
    ]:
        try:
            if not column_exists(cur, "users", col):
                cur.execute(ddl)
        except Exception:
            pass

    # classes
    cur.execute("""CREATE TABLE IF NOT EXISTS classes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL);""")

    # students
    cur.execute("""CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        birthdate TEXT,
        class_id INTEGER,
        phone TEXT,
        guardian_name TEXT,
        FOREIGN KEY(class_id) REFERENCES classes(id) ON DELETE SET NULL
    );""")

    # subjects
    cur.execute("""CREATE TABLE IF NOT EXISTS subjects (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL);""")

    # grades
    cur.execute("""CREATE TABLE IF NOT EXISTS grades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        subject_id INTEGER NOT NULL,
        class_id INTEGER NOT NULL,
        term TEXT DEFAULT 'الفصل 1',
        score REAL NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
        FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
        FOREIGN KEY(class_id) REFERENCES classes(id) ON DELETE CASCADE
    );""")

    # attendance
    cur.execute("""CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('present','absent','late')),
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(student_id, date),
        FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
    );""")

    # password resets
    cur.execute("""CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );""")

    # subscriptions
    cur.execute("""CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('active','canceled')),
        current_period_start TEXT NOT NULL,
        current_period_end TEXT NOT NULL,
        cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );""")

    conn.commit()

    # seed admin
    cur.execute("SELECT COUNT(*) AS c FROM users;")
    if cur.fetchone()["c"] == 0:
        pwd_hash = sha256("admin".encode("utf-8")).hexdigest()
        cur.execute("INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
                    ("admin", "admin@example.com", pwd_hash, "admin"))
        conn.commit()

    # seed subjects
    cur.execute("SELECT COUNT(*) AS c FROM subjects;")
    if cur.fetchone()["c"] == 0:
        for sub in ["العربية", "التربية الإسلامية", "التربية المدنية", "الرياضيات", "العلوم الطبيعية","العلوم الفيزيائية والتكنولوجيا","الإعلام الآلي","الإنجليزية","التاريخ","الجغرافيا","الفرنسية","الفنون التشكيلية","التربية الموسيقية","الرياضة"]:
            try:
                cur.execute("INSERT INTO subjects (name) VALUES (?)", (sub,))
            except Exception:
                pass
        conn.commit()

    conn.close()

# =============================
# Helpers
# =============================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def has_trial_access(user_row):
    if not user_row:
        return False
    te = user_row["trial_ends_at"]
    if not te:
        return False
    try:
        ends = datetime.datetime.fromisoformat(te).date()
    except Exception:
        return False
    return datetime.date.today() <= ends

def active_subscription_for(user_id):
    conn = get_db()
    cur = conn.cursor()
    today = datetime.date.today().isoformat()
    cur.execute("""
        SELECT * FROM subscriptions
        WHERE user_id = ? AND status = 'active' AND current_period_end >= ?
        ORDER BY current_period_end DESC LIMIT 1
    """, (user_id, today))
    row = cur.fetchone()
    conn.close()
    return row

def subscription_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (session.get("user_id"),))
        user = cur.fetchone()
        conn.close()
        if user and (has_trial_access(user) or active_subscription_for(user["id"])):
            return f(*args, **kwargs)
        flash("هذه الصفحة تتطلب اشتراكًا نشطًا أو فترة تجريبية. يمكنك البدء من صفحة التسعير.", "error")
        return redirect(url_for("pricing"))
    return wrapped

def send_reset_email(to_email, reset_url):
    if SMTP_HOST and SMTP_USER and SMTP_PASS and MAIL_FROM:
        try:
            msg = EmailMessage()
            msg["Subject"] = "إعادة تعيين كلمة المرور"
            msg["From"] = MAIL_FROM
            msg["To"] = to_email
            msg.set_content(f"اضغط الرابط لإعادة تعيين كلمة المرور:\n{reset_url}\n\nصالح لمدة ساعة.")
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
            return True
        except Exception:
            flash(f"تعذّر إرسال البريد (وضع التطوير): رابط إعادة التعيين: {reset_url}", "error")
            return False
    else:
        flash(f"وضع التطوير: رابط إعادة التعيين: {reset_url}", "ok")
        return False

def create_subscription_month(user_id: int):
    """فعّل/مدّد الاشتراك 30 يومًا للمستخدم."""
    today = datetime.date.today()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM subscriptions
        WHERE user_id=? AND status='active'
        ORDER BY current_period_end DESC LIMIT 1
    """, (user_id,))
    last = cur.fetchone()
    period_start = today
    if last and datetime.date.fromisoformat(last["current_period_end"]) >= today:
        period_start = datetime.date.fromisoformat(last["current_period_end"]) + datetime.timedelta(days=1)
    period_end = (period_start + datetime.timedelta(days=BILLING_DAYS - 1))
    cur.execute("""
        INSERT INTO subscriptions (user_id,status,current_period_start,current_period_end,cancel_at_period_end)
        VALUES (?,?,?,?,0)
    """, (user_id, 'active', period_start.isoformat(), period_end.isoformat()))
    conn.commit()
    conn.close()
    return period_end

# =============================
# Auth
# =============================
@app.route("/")
def root():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip() or None
        email = (request.form.get("email", "") or "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("الإيميل وكلمة المرور مطلوبة", "error")
            return render_template("register/index.html")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cur.fetchone():
            conn.close()
            flash("هذا الإيميل مسجل مسبقًا", "error")
            return render_template("register/index.html")

        pwd_hash = sha256(password.encode("utf-8")).hexdigest()
        cur.execute("INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
                    (username, email, pwd_hash, "teacher"))
        conn.commit()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()
        session.update({"user_id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]})
        flash("تم إنشاء الحساب! يمكنك بدء التجربة من التسعير.", "ok")
        return redirect(url_for("pricing"))
    return render_template("register/index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email", "") or "").strip().lower()
        password = request.form.get("password", "")
        pwd_hash = sha256(password.encode("utf-8")).hexdigest()
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ? AND password_hash = ?", (email, pwd_hash))
        user = cur.fetchone()
        conn.close()
        if user:
            session.update({"user_id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]})
            return redirect(url_for("dashboard"))
        flash("بيانات الدخول غير صحيحة", "error")
    return render_template("login/index.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = (request.form.get("email", "") or "").strip().lower()
        if not email:
            flash("يرجى إدخال الإيميل", "error")
            return render_template("forgot/index.html")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        if not user:
            conn.close()
            flash("لا يوجد حساب بهذا الإيميل", "error")
            return render_template("forgot/index.html")
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat()
        cur.execute("INSERT INTO password_resets (user_id, token, expires_at, used) VALUES (?,?,?,0)",
                    (user["id"], token, expires_at))
        conn.commit()
        conn.close()
        reset_url = url_for("reset_password", token=token, _external=True)
        ok = send_reset_email(email, reset_url)
        if ok:
            flash("تم إرسال رابط إعادة التعيين إلى بريدك", "ok")
        return redirect(url_for("login"))
    return render_template("forgot/index.html")

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM password_resets WHERE token = ? AND used = 0", (token,))
    req = cur.fetchone()
    if not req:
        conn.close()
        flash("رابط غير صالح أو مستخدم", "error")
        return redirect(url_for("login"))
    try:
        exp = datetime.datetime.fromisoformat(req["expires_at"])
    except Exception:
        exp = datetime.datetime.utcnow() - datetime.timedelta(seconds=1)
    if datetime.datetime.utcnow() > exp:
        conn.close()
        flash("انتهت صلاحية الرابط", "error")
        return redirect(url_for("forgot"))

    if request.method == "POST":
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        if not new or new != confirm:
            flash("الرجاء إدخال كلمة مرور والتأكيد صحيحًا", "error")
            return render_template("reset/index.html", token=token)
        pwd_hash = sha256(new.encode("utf-8")).hexdigest()
        cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pwd_hash, req["user_id"]))
        cur.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (req["id"],))
        conn.commit()
        conn.close()
        flash("تم تغيير كلمة المرور. سجّل الدخول الآن.", "ok")
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset/index.html", token=token)

# =============================
# Subscriptions & Payments
# =============================
@app.route("/pricing")
@login_required
def pricing():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    user = cur.fetchone()
    sub = active_subscription_for(session["user_id"])
    on_trial = has_trial_access(user)
    trial_used = bool(user["trial_started_at"])
    conn.close()
    return render_template("pricing/index.html",
                           on_trial=on_trial,
                           trial_used=trial_used,
                           sub=sub,
                           monthly_price=MONTHLY_PRICE_DZD)

@app.route("/subscribe", methods=["POST"])
@login_required
def subscribe():
    action = request.form.get("action")
    user_id = session["user_id"]

    if action == "start_trial":
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if user["trial_started_at"]:
            conn.close()
            flash("لقد استخدمت الفترة التجريبية مسبقًا.", "error")
        else:
            ends = datetime.date.today() + datetime.timedelta(days=TRIAL_DAYS)
            cur.execute("UPDATE users SET trial_started_at=?, trial_ends_at=? WHERE id=?",
                        (datetime.date.today().isoformat(), ends.isoformat(), user_id))
            conn.commit()
            conn.close()
            flash(f"بدأت الفترة التجريبية حتى {ends.isoformat()}", "ok")
        return redirect(url_for("account"))

    elif action == "cancel":
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            UPDATE subscriptions
            SET cancel_at_period_end=1
            WHERE user_id=? AND status='active' AND cancel_at_period_end=0
        """, (user_id,))
        conn.commit()
        conn.close()
        flash("سيُلغى الاشتراك بنهاية الفترة الحالية.", "ok")
        return redirect(url_for("account"))

    else:
        flash("طلب غير معروف", "error")
        return redirect(url_for("pricing"))

@app.route("/pay/start", methods=["POST"])
@login_required
def pay_start():
    """إنشاء Checkout عبر Chargily وإعادة توجيه المستخدم لصفحة الدفع."""
    if not CHARGILY_SECRET_KEY:
        flash("لم يتم ضبط مفاتيح Chargily. أضف CHARGILY_SECRET_KEY.", "error")
        return redirect(url_for("pricing"))

    payload = {
        "amount": int(MONTHLY_PRICE_DZD),
        "currency": "dzd",
        "success_url": CHARGILY_SUCCESS_URL,
        "metadata": {
            "user_id": session["user_id"],
            "plan": "monthly"
        },
        "locale": "ar"
    }
    try:
        resp = requests.post(
            f"{CHARGILY_BASE}/checkouts",
            headers={
                "Authorization": f"Bearer {CHARGILY_SECRET_KEY}",
                "Content-Type": "application/json"
            },
            data=json.dumps(payload),
            timeout=20
        )
        data = resp.json()
        if resp.status_code >= 400:
            flash(f"فشل إنشاء الدفع: {data}", "error")
            return redirect(url_for("pricing"))
        checkout_url = data.get("checkout_url")
        if not checkout_url:
            flash("لم نستلم رابط الدفع من البوابة.", "error")
            return redirect(url_for("pricing"))
        return redirect(checkout_url)
    except Exception as e:
        flash(f"خطأ أثناء الاتصال ببوابة الدفع: {e}", "error")
        return redirect(url_for("pricing"))

@app.route("/webhooks/chargily", methods=["POST"])
def chargily_webhook():
    """Webhook من Chargily: عند status=paid نفعل شهر اشتراك للمستخدم."""
    try:
        evt = request.get_json(force=True, silent=True) or {}
    except Exception:
        return ("invalid json", 400)

    # قد تختلف البنية باختلاف الإصدارات—نعالج الحالتين:
    entity = evt.get("entity")
    status = evt.get("status")
    metadata = evt.get("metadata") or {}

    if not entity and isinstance(evt.get("data"), dict):
        data = evt["data"]
        entity = data.get("entity") or entity
        status = data.get("status") or status
        metadata = data.get("metadata") or metadata

    user_id = (metadata or {}).get("user_id")
    if entity == "checkout" and status in ("paid", "succeeded", "success"):
        try:
            user_id = int(user_id)
        except Exception:
            return ("missing user_id", 400)
        period_end = create_subscription_month(user_id)

        # إزالة أي إلغاء مؤجل
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""UPDATE subscriptions SET cancel_at_period_end=0
                       WHERE user_id=? AND status='active'""", (user_id,))
        conn.commit()
        conn.close()
        return ("ok", 200)

    return ("ignored", 200)

@app.route("/account")
@login_required
def account():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    user = cur.fetchone()
    cur.execute("""
        SELECT * FROM subscriptions
        WHERE user_id=? ORDER BY current_period_end DESC
    """, (session["user_id"],))
    subs = cur.fetchall()
    conn.close()
    sub_active = active_subscription_for(session["user_id"])
    return render_template("account/index.html",
                           user=user,
                           sub_active=sub_active,
                           subs=subs,
                           TRIAL_DAYS=TRIAL_DAYS, BILLING_DAYS=BILLING_DAYS)

# =============================
# Dashboard (محمي بالاشتراك/التجربة)
# =============================
@app.route("/dashboard")
@login_required
@subscription_required
def dashboard():
    conn = get_db()
    cur = conn.cursor()

    # معلومات عامة
    cur.execute("SELECT COUNT(*) AS c FROM students;")
    students_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM classes;")
    classes_count = cur.fetchone()["c"]

    # تنبيهات آخر 7 أيام
    seven_days_ago = (datetime.date.today() - datetime.timedelta(days=7)).isoformat()
    cur.execute("""
        SELECT s.first_name || ' ' || s.last_name AS name, c.name AS class_name, a.date, a.status
        FROM attendance a
        JOIN students s ON s.id = a.student_id
        LEFT JOIN classes c ON c.id = s.class_id
        WHERE a.status IN ('absent','late') AND a.date >= ?
        ORDER BY a.date DESC LIMIT 10
    """, (seven_days_ago,))
    alerts = cur.fetchall()

    # حالة الاشتراك/التجربة لعرض أزرار CTA
    cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    user = cur.fetchone()
    conn.close()

    sub_active = active_subscription_for(session["user_id"])
    on_trial = has_trial_access(user)

    return render_template("dashboard/index.html",
                           students_count=students_count,
                           classes_count=classes_count,
                           alerts=alerts,
                           sub_active=sub_active,
                           on_trial=on_trial)


# =============================
# Classes (أقسام) — endpoint ثابت "classes"
# =============================
@app.route("/classes", methods=["GET", "POST"], endpoint="classes")
@login_required
@subscription_required
def classes_view():
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if name:
            try:
                cur.execute("INSERT INTO classes (name) VALUES (?)", (name,))
                conn.commit()
                flash("تمت إضافة القسم", "ok")
            except sqlite3.IntegrityError:
                flash("هذا القسم موجود بالفعل", "error")
    cur.execute("SELECT * FROM classes ORDER BY name;")
    rows = cur.fetchall()
    conn.close()
    return render_template("classes/index.html", classes=rows)

@app.route("/classes/delete/<int:class_id>", methods=["POST"])
@login_required
@subscription_required
def delete_class(class_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM classes WHERE id = ?", (class_id,))
    conn.commit()
    conn.close()
    flash("تم حذف القسم", "ok")
    return redirect(url_for("classes"))

@app.route("/classes/edit/<int:class_id>", methods=["POST"])
@login_required
@subscription_required
def edit_class(class_id):
    new_name = request.form.get("name", "").strip()
    if new_name:
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("UPDATE classes SET name = ? WHERE id = ?", (new_name, class_id))
            conn.commit()
            flash("تم تعديل اسم القسم", "ok")
        except sqlite3.IntegrityError:
            flash("اسم القسم مستخدم سابقًا", "error")
        conn.close()
    return redirect(url_for("classes"))

# =============================
# Students
# =============================
@app.route("/students", methods=["GET", "POST"])
@login_required
@subscription_required
def students():
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        birthdate = request.form.get("birthdate", "")
        class_id = request.form.get("class_id") or None
        phone = request.form.get("phone", "").strip()
        guardian_name = request.form.get("guardian_name", "").strip()
        cur.execute("""INSERT INTO students (first_name,last_name,birthdate,class_id,phone,guardian_name)
                       VALUES (?,?,?,?,?,?)""",
                    (first_name, last_name, birthdate, class_id, phone, guardian_name))
        conn.commit()
        flash("تمت إضافة التلميذ/ـة", "ok")

    search = request.args.get("q", "").strip()
    if search:
        q = f"%{search}%"
        cur.execute("""SELECT s.*, c.name as class_name FROM students s
                       LEFT JOIN classes c ON c.id = s.class_id
                       WHERE s.first_name LIKE ? OR s.last_name LIKE ? OR c.name LIKE ?
                       ORDER BY s.last_name, s.first_name""", (q, q, q))
    else:
        cur.execute("""SELECT s.*, c.name as class_name FROM students s
                       LEFT JOIN classes c ON c.id = s.class_id
                       ORDER BY s.last_name, s.first_name""")
    students = cur.fetchall()
    cur.execute("SELECT * FROM classes ORDER BY name;")
    classes = cur.fetchall()
    conn.close()
    return render_template("students/index.html", students=students, classes=classes, search=search)

@app.route("/students/delete/<int:student_id>", methods=["POST"])
@login_required
@subscription_required
def delete_student(student_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM students WHERE id = ?", (student_id,))
    conn.commit()
    conn.close()
    flash("تم حذف التلميذ", "ok")
    return redirect(url_for("students"))

@app.route("/students/<int:student_id>")
@login_required
@subscription_required
def student_profile(student_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""SELECT s.*, c.name as class_name FROM students s
                   LEFT JOIN classes c ON c.id = s.class_id WHERE s.id = ?""", (student_id,))
    s = cur.fetchone()
    cur.execute("""SELECT sub.name as subject_name, g.term, g.score, g.created_at
                   FROM grades g JOIN subjects sub ON sub.id = g.subject_id
                   WHERE g.student_id = ? ORDER BY sub.name, g.term""", (student_id,))
    grades = cur.fetchall()
    cur.execute("SELECT AVG(score) AS avg_score FROM grades WHERE student_id = ?", (student_id,))
    avg_row = cur.fetchone()
    avg_score = avg_row["avg_score"] if (avg_row and avg_row["avg_score"] is not None) else None
    cur.execute("""SELECT date, status FROM attendance WHERE student_id = ? ORDER BY date DESC LIMIT 60""", (student_id,))
    attendance = cur.fetchall()
    conn.close()
    return render_template("student_profile/index.html", s=s, grades=grades, avg_score=avg_score, attendance=attendance)

@app.route("/students/<int:student_id>/export_csv")
@login_required
@subscription_required
def student_export_csv(student_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""SELECT s.first_name || ' ' || s.last_name AS name, c.name AS class_name, s.birthdate, s.phone, s.guardian_name
                   FROM students s LEFT JOIN classes c ON c.id = s.class_id WHERE s.id = ?""", (student_id,))
    s = cur.fetchone()
    cur.execute("""SELECT sub.name as subject_name, g.term, g.score FROM grades g
                   JOIN subjects sub ON sub.id = g.subject_id WHERE g.student_id = ?
                   ORDER BY sub.name, g.term""", (student_id,))
    grades = cur.fetchall()
    cur.execute("""SELECT date, status FROM attendance WHERE student_id = ? ORDER BY date DESC""", (student_id,))
    attendance = cur.fetchall()
    conn.close()

    si = StringIO()
    si.write("التلميذ,القسم,تاريخ الميلاد,الهاتف,ولي الأمر\n")
    si.write(f"{s['name']},{s['class_name'] or ''},{s['birthdate'] or ''},{s['phone'] or ''},{s['guardian_name'] or ''}\n\n")
    si.write("المادة,الفصل,الدرجة\n")
    for g in grades:
        si.write(f"{g['subject_name']},{g['term']},{g['score']}\n")
    si.write("\nالتاريخ,الحالة\n")
    for a in attendance:
        si.write(f"{a['date']},{a['status']}\n")

    mem = BytesIO(si.getvalue().encode('utf-8-sig'))
    return send_file(mem, as_attachment=True, download_name=f"student_{student_id}_report.csv", mimetype="text/csv")

# =============================
# Grades
# =============================
@app.route("/grades", methods=["GET", "POST"])
@login_required
@subscription_required
def grades_page():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM classes ORDER BY name;")
    classes = cur.fetchall()
    cur.execute("SELECT * FROM subjects ORDER BY name;")
    subjects = cur.fetchall()

    selected_class_id = request.values.get("class_id") or ""
    selected_subject_id = request.values.get("subject_id") or ""
    selected_term = request.values.get("term") or "الفصل 1"

    students = []
    if selected_class_id:
        cur.execute("SELECT * FROM students WHERE class_id = ? ORDER BY last_name, first_name;", (selected_class_id,))
        students = cur.fetchall()

    if request.method == "POST" and selected_class_id and selected_subject_id:
        for s in students:
            key = f"score_{s['id']}"
            score_val = request.form.get(key)
            if not score_val:
                continue
            try:
                score = float(score_val)
            except Exception:
                continue
            cur.execute("""INSERT INTO grades (student_id, subject_id, class_id, term, score)
                           VALUES (?,?,?,?,?)""", (s["id"], selected_subject_id, selected_class_id, selected_term, score))
        conn.commit()
        flash("تم حفظ الدرجات", "ok")

    conn.close()
    return render_template("grades/index.html",
                           classes=classes, subjects=subjects,
                           selected_class_id=selected_class_id,
                           selected_subject_id=selected_subject_id,
                           selected_term=selected_term,
                           students=students)

# =============================
# Attendance
# =============================
@app.route("/attendance", methods=["GET", "POST"])
@login_required
@subscription_required
def attendance_page():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM classes ORDER BY name;")
    classes = cur.fetchall()

    selected_class_id = request.values.get("class_id") or ""
    selected_date = request.values.get("date") or datetime.date.today().isoformat()

    students = []
    if selected_class_id:
        cur.execute("SELECT * FROM students WHERE class_id = ? ORDER BY last_name, first_name;", (selected_class_id,))
        students = cur.fetchall()

    if request.method == "POST" and selected_class_id:
        for s in students:
            status = request.form.get(f"status_{s['id']}", "present")
            try:
                cur.execute("""INSERT OR REPLACE INTO attendance (student_id, date, status)
                               VALUES (?,?,?)""", (s["id"], selected_date, status))
            except sqlite3.IntegrityError:
                pass
        conn.commit()
        flash("تم حفظ الحضور/الغياب", "ok")

    thirty_days_ago = (datetime.date.today() - datetime.timedelta(days=30)).isoformat()
    cur.execute("""SELECT s.first_name || ' ' || s.last_name AS name,
                          SUM(CASE WHEN a.status='absent' THEN 1 ELSE 0 END) AS absent_days,
                          SUM(CASE WHEN a.status='late' THEN 1 ELSE 0 END) AS late_days
                   FROM students s
                   LEFT JOIN attendance a ON a.student_id = s.id AND a.date >= ?
                   WHERE (? = '' OR s.class_id = ?)
                   GROUP BY s.id
                   ORDER BY absent_days DESC, late_days DESC
                   LIMIT 20""", (thirty_days_ago, selected_class_id, selected_class_id))
    stats = cur.fetchall()
    conn.close()
    return render_template("attendance/index.html",
                           classes=classes,
                           selected_class_id=selected_class_id,
                           selected_date=selected_date,
                           students=students,
                           stats=stats)

# =============================
# Reports
# =============================
@app.route("/reports", methods=["GET", "POST"])
@login_required
@subscription_required
def reports():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM classes ORDER BY name;")
    classes = cur.fetchall()
    selected_class_id = request.values.get("class_id") or ""
    conn.close()
    return render_template("reports/index.html",
                           classes=classes,
                           selected_class_id=selected_class_id)

@app.route("/reports/class_grades_csv/<int:class_id>")
@login_required
@subscription_required
def report_class_grades_csv(class_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""SELECT s.id as student_id, s.first_name || ' ' || s.last_name AS student_name,
                          sub.name AS subject_name, g.term, g.score
                   FROM grades g
                   JOIN students s ON s.id = g.student_id
                   JOIN subjects sub ON sub.id = g.subject_id
                   WHERE g.class_id = ?
                   ORDER BY s.last_name, s.first_name, sub.name, g.term""", (class_id,))
    rows = cur.fetchall()
    conn.close()
    si = StringIO()
    si.write("التلميذ,المادة,الفصل,الدرجة\n")
    for r in rows:
        si.write(f"{r['student_name']},{r['subject_name']},{r['term']},{r['score']}\n")
    mem = BytesIO(si.getvalue().encode('utf-8-sig'))
    return send_file(mem, as_attachment=True, download_name=f"class_{class_id}_grades.csv", mimetype="text/csv")

@app.route("/reports/class_attendance_csv/<int:class_id>")
@login_required
@subscription_required
def report_class_attendance_csv(class_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""SELECT s.first_name || ' ' || s.last_name AS student_name, a.date, a.status
                   FROM attendance a JOIN students s ON s.id = a.student_id
                   WHERE s.class_id = ? ORDER BY a.date DESC, student_name""", (class_id,))
    rows = cur.fetchall()
    conn.close()
    si = StringIO()
    si.write("التلميذ,التاريخ,الحالة\n")
    for r in rows:
        si.write(f"{r['student_name']},{r['date']},{r['status']}\n")
    mem = BytesIO(si.getvalue().encode('utf-8-sig'))
    return send_file(mem, as_attachment=True, download_name=f"class_{class_id}_attendance.csv", mimetype="text/csv")

# =============================
# Settings
# =============================
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST" and request.form.get("form_name") == "subject_add":
        sub_name = request.form.get("name", "").strip()
        if sub_name:
            try:
                cur.execute("INSERT INTO subjects (name) VALUES (?)", (sub_name,))
                conn.commit()
                flash("تمت إضافة المادة", "ok")
            except sqlite3.IntegrityError:
                flash("المادة موجودة سابقًا", "error")

    if request.method == "POST" and request.form.get("form_name") == "user_add":
        username = request.form.get("username", "").strip() or None
        email = (request.form.get("email", "") or "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "teacher")
        if not email or not password:
            flash("الإيميل وكلمة المرور مطلوبة", "error")
        else:
            try:
                pwd_hash = sha256(password.encode("utf-8")).hexdigest()
                cur.execute("INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
                            (username, email, pwd_hash, role))
                conn.commit()
                flash("تمت إضافة المستخدم", "ok")
            except sqlite3.IntegrityError:
                flash("الإيميل مستخدم بالفعل", "error")

    if request.method == "POST" and request.form.get("form_name") == "change_password":
        old = request.form.get("old", "")
        new = request.form.get("new", "")
        cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        u = cur.fetchone()
        if u and sha256(old.encode("utf-8")).hexdigest() == u["password_hash"]:
            cur.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                        (sha256(new.encode("utf-8")).hexdigest(), session["user_id"]))
            conn.commit()
            flash("تم تغيير كلمة المرور", "ok")
        else:
            flash("كلمة المرور القديمة غير صحيحة", "error")

    cur.execute("SELECT * FROM subjects ORDER BY name;")
    subjects = cur.fetchall()

    cur.execute("SELECT id, username, email, role FROM users ORDER BY username, email;")
    users = cur.fetchall()

    conn.close()
    return render_template("settings/index.html", subjects=subjects, users=users)

# =============================
# Entry
# =============================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # بلا reloader لتفادي تشغيل نسختين → أقفال أكثر
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False, threaded=True)
