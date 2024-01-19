from flask import Flask, Blueprint, render_template, request, redirect, url_for, flash, session
from email_validator import validate_email, EmailNotValidError
import sqlite3
from flask_bcrypt import Bcrypt
import re
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dkfsdlf'
app.permanent_session_lifetime = timedelta(days=2)
bcrypt = Bcrypt(app)


connect = sqlite3.connect('database.db')
cursor = connect.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        email TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')
connect.commit()
connect.close()


def is_valid_email(email):
    # Simple email validation using a regular expression
    pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    return bool(re.match(pattern, email))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.permanent = True
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            flash("Please complete all the fields", 'error')
            return redirect(url_for("login"))
        query = "SELECT email, password FROM users WHERE email=?"
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        # if user[2] == 1:
            # session["user"] = user
            # return redirect(url_for('admin'))
        if user and bcrypt.check_password_hash(user[1], password):
            user = user[1]
            session["user"] = user
            print("User:", user)
            print("Session email:", session["user"])
            return redirect(url_for("myaccount"))
        else:
            flash("Email not found", 'error')
    if 'user' in session:
        return redirect(url_for("myaccount"))
    
    return render_template("login.html")


@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get("repeat_password")
        if not email or not password or not confirm_password:
            flash("Please complete all the fields", 'error')
            return redirect(url_for("sign_up"))
        if not is_valid_email(email):
            flash('Invalid email. Please try again.', 'error')
            return redirect(url_for("sign_up"))
        
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_email = cursor.fetchone()

        if existing_email:
            flash("Email already exists", 'error')
            return redirect(url_for("sign_up"))

        if password != confirm_password:
            flash("Passwords don't match")
            return redirect(url_for("sign_up"))
        if len(password) < 8:
           flash("Password is too short")
           return redirect(url_for("sign_up"))
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
            conn.commit()
            cursor.close()
            conn.close()
            flash("You have successfully registered", 'success')
            return redirect(url_for("login"))

    return render_template("sign_up.html")  

@app.route('/')
@app.route('/home')
def home():    
    return render_template("home.html")

@app.route('/my-account', methods=['POST', 'GET'])
def myaccount():
    if 'user' in session:
        user = session["user"]
        if request.method == 'POST':
            session.pop('user', None)
            return redirect(url_for('login'))
        return render_template("myaccount.html")
    else:
        return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(debug=True)