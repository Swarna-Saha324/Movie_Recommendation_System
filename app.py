import os
import random
import string
import pickle
import requests
import pandas as pd
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_dance.contrib.google import make_google_blueprint, google
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import smtplib
from email.mime.text import MIMEText


# -------------------- EMAIL SENDER --------------------
def send_email(receiver, subject, body):
    sender_email = "malihasama73@gmail.com"
    app_password = "bgxl kytd cgqq fumd"  # Gmail App Password

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, app_password)
        server.sendmail(sender_email, receiver, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print("EMAIL ERROR:", e)
        return False


# -------------------- CONFIGURATION --------------------
app = Flask(__name__, template_folder="templates")
CORS(app)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{os.getenv('DB_USER', 'flaskuser')}:{os.getenv('DB_PASSWORD', 'flaskpassword')}"
    f"@{os.getenv('DB_HOST', 'localhost')}:{os.getenv('DB_PORT', '3306')}/{os.getenv('DB_NAME', 'movie_db')}"
)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "supersecretkey")
app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER", "static/uploads")
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH", 5242880))
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# -------------------- DATABASE --------------------
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Admin(db.Model):
    __tablename__ = "admins"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()


# -------------------- UTILITIES --------------------
s = URLSafeTimedSerializer(app.config["SECRET_KEY"])


def get_field(req, name, default=None):
    if req.is_json:
        return req.get_json().get(name, default)
    return req.form.get(name, default)


# -------------------- ROUTES --------------------
@app.route("/")
def Home():
    return render_template("Home.html")


@app.route("/Login")
def Login():
    return render_template("Login.html")


# -------------------- USER SIGNUP --------------------
@app.route("/signup_user", methods=["POST"])
def signup_user():
    username = get_field(request, "username")
    email = get_field(request, "email")
    password = get_field(request, "password")

    if not username or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400

    hashed_password = generate_password_hash(password)
    user = User(username=username, email=email, password_hash=hashed_password, is_verified=False)
    db.session.add(user)
    db.session.commit()

    token = s.dumps(email, salt="email-confirm")
    verify_link = url_for("verify_email", token=token, _external=True)

    print(f"\n [DEBUG] Email verification link for {email}: {verify_link}\n")

    return jsonify({"message": "User signup successful! Check console for verification link."})


# -------------------- ADMIN SIGNUP --------------------
@app.route("/signup_admin", methods=["POST"])
def signup_admin():
    username = get_field(request, "username")
    email = get_field(request, "email")
    password = get_field(request, "password")

    if not username or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    if Admin.query.filter_by(email=email).first():
        return jsonify({"error": "Admin email already exists"}), 400

    hashed_password = generate_password_hash(password)
    admin = Admin(username=username, email=email, password_hash=hashed_password)

    db.session.add(admin)
    db.session.commit()

    print(f"\n[DEBUG] New admin created: {email}\n")

    return jsonify({"message": "Admin signup successful!"})


# -------------------- EMAIL VERIFICATION --------------------
@app.route("/verify/<token>")
def verify_email(token):
    try:
        email = s.loads(token, salt="email-confirm", max_age=3600)
    except SignatureExpired:
        return "<h3>Verification link expired. Please sign up again.</h3>"

    user = User.query.filter_by(email=email).first()
    if not user:
        return "<h3>Invalid verification link.</h3>"

    user.is_verified = True
    db.session.commit()

    return "<h3>Email verified successfully! You can now log in.</h3>"


# -------------------- LOGIN --------------------
@app.route("/login_user", methods=["POST"])
def login_user_route():
    email = get_field(request, "email")
    password = get_field(request, "password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = user.id
    return jsonify({"message": "User login successful!"})


@app.route("/login_admin", methods=["POST"])
def login_admin_route():
    email = get_field(request, "email")
    password = get_field(request, "password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    admin = Admin.query.filter_by(email=email).first()
    if not admin or not check_password_hash(admin.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    session["admin_id"] = admin.id
    return jsonify({"message": "Admin login successful!"})


# -------------------- FORGOT PASSWORD --------------------
@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    email = get_field(request, "email")

    if not email:
        return jsonify({"error": "Email required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "No account with that email"}), 404

    code = "".join(random.choices(string.digits, k=6))
    user.password_hash = generate_password_hash(code)
    db.session.commit()

    body = f"Your Movie App temporary login code is: {code}"
    send_email(email, "Movie App Password Reset Code", body)

    return jsonify({"message": "A 6-digit code has been sent to your email."})


# -------------------- LOGOUT --------------------
@app.route("/Logout")
def Logout():
    session.clear()
    return render_template("logout.html")


# -------------------- MOVIE RECOMMENDER --------------------
MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")
MOVIE_PKL = os.path.join(MODEL_DIR, "movie_list.pkl")
SIM_PKL = os.path.join(MODEL_DIR, "similarity.pkl")

with open(MOVIE_PKL, "rb") as f:
    movies_dict = pickle.load(f)

movies = pd.DataFrame(movies_dict) if isinstance(movies_dict, dict) else movies_dict

with open(SIM_PKL, "rb") as f:
    similarity = pickle.load(f)

TMDB_API_KEY = os.environ.get("TMDB_API_KEY", "a3e6e7e2eccefd2b27bb909e4d6b7095")


def fetch_poster_url(movie_id):
    try:
        url = f"https://api.themoviedb.org/3/movie/{movie_id}"
        params = {"api_key": TMDB_API_KEY, "language": "en-US"}

        r = requests.get(url, params=params, timeout=5)
        if r.status_code != 200:
            return "https://via.placeholder.com/300x450?text=No+Image"

        data = r.json()
        poster_path = data.get("poster_path")

        if not poster_path:
            return "https://via.placeholder.com/300x450?text=No+Image"

        return "https://image.tmdb.org/t/p/w500" + poster_path

    except Exception:
        return "https://via.placeholder.com/300x450?text=No+Image"


@app.route("/Movie_Recommendations")
def Movie_Recommendations():
    movie_list = movies["title"].values.tolist()
    return render_template("Movie_Recommendations.html", movies=movie_list)


# -------------------- RECOMMEND API --------------------
@app.route("/recommend", methods=["POST"])
def recommend_api():
    if "user_id" not in session and "admin_id" not in session:
        return jsonify({"error": "You must log in to view movie recommendations."}), 401

    payload = request.get_json()
    if not payload or "movie" not in payload:
        return jsonify({"error": "Missing 'movie' in request body"}), 400

    movie_name = payload["movie"].strip().lower()
    matches = movies[movies["title"].str.lower() == movie_name]

    if matches.empty:
        return jsonify({"error": f"Movie '{movie_name}' not found"}), 404

    idx = matches.index[0]
    distances = sorted(list(enumerate(similarity[idx])), reverse=True, key=lambda x: x[1])

    recommended = []
    for i in distances[1:6]:
        rec_idx = i[0]
        rec_title = movies.iloc[rec_idx].title
        rec_id = int(movies.iloc[rec_idx].movie_id)
        poster = fetch_poster_url(rec_id)

        recommended.append({
            "title": rec_title,
            "movie_id": rec_id,
            "poster": poster
        })

    return jsonify({"results": recommended})


# -------------------- ADMIN PANEL --------------------
@app.route("/admin_panel")
def admin_panel():
    is_admin = "admin_id" in session

    if "user_id" not in session and not is_admin:
        return redirect(url_for("Login"))

    return render_template("admin_panel.html", is_admin=is_admin)


# -------------------- MAIN --------------------
if __name__ == "__main__":
    app.run(debug=True)
