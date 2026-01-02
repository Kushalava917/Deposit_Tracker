from flask import Flask, render_template, request, redirect, url_for, session, flash, get_flashed_messages, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
from xhtml2pdf import pisa
from io import BytesIO
import os

app = Flask(__name__)

# ---------- CONFIG ----------
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if "sslmode" not in DATABASE_URL:
    DATABASE_URL += "?sslmode=require"

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "nova_secret_key"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
}

db = SQLAlchemy(app)

# ---------- MODELS ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'user'
class Investment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    roi = db.Column(db.Float, nullable=False)
    duration_months = db.Column(db.Integer, nullable=False)
    start_date = db.Column(db.String(50), nullable=False)

    user = db.relationship('User', backref=db.backref('investments', lazy=True))

# ---------- ROUTES ----------
@app.route("/")
def home():
    if "user_id" in session:
        role = session.get("role")
        return redirect(url_for(f"{role}_dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["role"] = user.role
            flash(f"✅ Welcome back, {username}!", "success")
            return redirect(url_for(f"{user.role}_dashboard"))
        else:
            flash("⚠️ Invalid username or password", "danger")
            return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("👋 You have been logged out successfully", "info")
    return redirect(url_for("login"))


# ---------- USER DASHBOARD ----------
@app.route("/user/dashboard")
def user_dashboard():
    if "user_id" not in session or session.get("role") != "user":
        return redirect(url_for("login"))
    user_id = session["user_id"]
    investments = Investment.query.filter_by(user_id=user_id).all()

    total_investment = sum(i.amount for i in investments)
    total_interest = 0

    for inv in investments:
        t = inv.duration_months / 12  # convert months to years
        total_interest += inv.amount * (inv.roi / 100) * t  # simple interest

    total_maturity = total_investment + total_interest

    return render_template("user_dashboard.html",
                           investments=investments,
                           total_investment=total_investment,
                           total_interest=total_interest,
                           total_maturity=total_maturity)


@app.route("/user/report")
def user_report():
    if "user_id" not in session or session.get("role") != "user":
        return redirect(url_for("login"))

    user_id = session["user_id"]
    user = User.query.get(user_id)
    investments = Investment.query.filter_by(user_id=user_id).all()

    total_investment = sum(i.amount for i in investments)
    total_interest = sum(i.amount * (i.roi * (i.duration_months / 12) / 100) for i in investments)
    total_maturity = total_investment + total_interest

    html = render_template("user_report.html", user=user, investments=investments,
                           total_investment=total_investment, total_interest=total_interest,
                           total_maturity=total_maturity, now=datetime.now())

    pdf = BytesIO()
    pisa.CreatePDF(BytesIO(html.encode("utf-8")), pdf)
    response = make_response(pdf.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "inline; filename=Investment_Report.pdf"
    return response


@app.route("/calculator")
def calculator_home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("calculator_home.html")


@app.route("/calculator/<scheme>", methods=["GET", "POST"])
def calculator_scheme(scheme):
    schemes = {
        "regular": 7.0,
        "fixed": 9.0,
        "senior": 8.5,
        "recurring": 7.5
    }

    roi = schemes.get(scheme.lower())
    if not roi:
        return "❌ Invalid scheme", 404

    result = None
    if request.method == "POST":
        amount = float(request.form["amount"])
        months = int(request.form["months"])
        time_years = months / 12
        maturity = amount * (1 + (roi * time_years / 100))
        interest = maturity - amount
        result = {"amount": amount, "roi": roi, "months": months, "interest": interest, "maturity": maturity}

    return render_template("calculator_scheme.html", scheme=scheme.capitalize(), roi=roi, result=result)


@app.route("/admin/add-deposit/<int:user_id>", methods=["GET", "POST"])
def add_deposit(user_id):
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    user = User.query.get(user_id)
    if not user:
        return "❌ User not found", 404

    if request.method == "POST":
        # Convert and validate inputs
        try:
            amount = float(request.form["amount"])
            roi = float(request.form["roi"])
            duration = int(request.form["duration"])
        except (ValueError, KeyError):
            return render_template("add_deposit.html", user=user, error="Invalid input values")

        start_date = request.form.get("start_date")
        # Optional: validate date format (YYYY-MM-DD)
        try:
            # store as string, but ensure it's a valid date
            datetime.strptime(start_date, "%Y-%m-%d")
        except Exception:
            return render_template("add_deposit.html", user=user, error="Invalid start date format. Use YYYY-MM-DD")

        investment = Investment(
            user_id=user_id,
            amount=amount,
            roi=roi,
            duration_months=duration,
            start_date=start_date
        )
        db.session.add(investment)
        db.session.commit()
        flash(f"✅ Deposit of ₹{amount} added successfully for {user.username}", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_deposit.html", user=user)


# ---------- ADMIN DASHBOARD ----------
@app.route("/admin/dashboard")
def admin_dashboard():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    users = User.query.filter(User.role == "user").all()
    return render_template("admin_dashboard.html", users=users)


@app.route("/admin/analytics")
def admin_analytics():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    total_users = User.query.filter_by(role="user").count()
    total_investments = db.session.query(func.sum(Investment.amount)).scalar() or 0
    avg_roi = db.session.query(func.avg(Investment.roi)).scalar() or 0

    # Total maturity projection
    all_investments = Investment.query.all()
    total_maturity = sum([inv.amount * (1 + (inv.roi * (inv.duration_months / 12) / 100)) for inv in all_investments])

    return render_template("admin_analytics.html",
                           total_users=total_users,
                           total_investments=total_investments,
                           avg_roi=round(avg_roi, 2),
                           total_maturity=round(total_maturity, 2))


@app.route("/admin/create-user", methods=["GET", "POST"])
def create_user():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if username exists
        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("⚠️ Username already exists", "warning")
            return render_template("create_user.html")

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(username=username, password=hashed_password, role="user")
        db.session.add(new_user)
        db.session.commit()

        flash(f"✅ User '{username}' created successfully", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("create_user.html")


# ---------- SETUP ROUTE ----------
@app.route("/init-db")
def init_db():
    from flask import jsonify
    with app.app_context():
        db.create_all()
    return jsonify({"status": "✅ Tables created successfully"})


@app.route("/create-admin")
def create_admin():
    existing = User.query.filter_by(username="admin").first()
    if not existing:
        hashed = generate_password_hash("admin123", method="pbkdf2:sha256")
        admin = User(username="admin", password=hashed, role="admin")
        db.session.add(admin)
        db.session.commit()
        return "✅ Admin created (username: admin, password: admin123)"
    return "Admin already exists."


# ---------- MAIN ----------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run()
