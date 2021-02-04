import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from flask_babel import Babel, gettext
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)
app.config["BABEL_DEFAULT_LOCALE"] = "en"

# Global variable
LANGUAGES = {
    "en": "English",
    "es": "Spanish"
}

# Babel translation initialization
babel = Babel(app)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure response aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///WHO.db")

@app.route("/")
def unath():
    """Unauthenticated homepage"""
    return render_template("unauth.html")


@app.route("/home")
@login_required
def auth():
    """Authenticated homepage"""
    return render_template("auth.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST
    if request.method == "POST":

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE email = ?", request.form.get("email"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("403: Incorrect Username and/or Password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to authenticated homepage
        return redirect("/home")

    else:
        return render_template("unauth.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register new user"""

    # User reached route via POST
    if request.method == "POST":

        # Checks if email has already been used to register account
        rows = db.execute("SELECT * FROM users WHERE email = ?", request.form.get("email"))
        if len(rows) == 1:
            return apology("400: Email already used to register account")

        # Submits user's input
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        db.execute("INSERT INTO users (name, email, hash) VALUES(?, ?, ?)", name, email, generate_password_hash(password))

        return redirect("/home")

    else:
        return render_template("register.html")


@app.route("/account")
@login_required
def account():
    """Allows user to view their account profile"""

    row = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    print(row)
    return render_template("account.html", row=row)


@app.route("/change", methods=["POST", "GET"])
@login_required
def change():
    """Allows user to change thier account information"""

    if request.method == "POST":
        # Submits user's input
        name = request.form.get("name")
        password = request.form.get("password")
        db.execute("UPDATE users SET name = ?, hash = ? WHERE id = ?", name, generate_password_hash(password), session["user_id"])
        return redirect("/account")

    else:
        return redirect("/account")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to unauthorized homepage
    return redirect("/")


# https://stackoverflow.com/questions/61124433/how-to-use-translation-in-flask
# Translation feature does not work
# @app.route("/language/<language>")
# def set_language(language=None):
#     session["language"] = language
#     return redirect("/home")


# @babel.localeselector
# def get_locale():
#     try:
#         language = session["language"]
#     except KeyError:
#         language = None
#     if language is not None:
#         return language
#     return request.accept_languages.best_match(LANGUAGES.keys())


# @app.context_processor
# def inject_conf_var():
#     return dict(
#         AVAILABE_LANGUAGES=LANGUAGES,
#         CURRENT_LANGUAGE=session.get("language", request.accept_languages.best_match(LANGUAGES.keys())))


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(str(e.code) + ": " + e.name)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)