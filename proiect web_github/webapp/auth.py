from flask import Flask, Blueprint, render_template, request, redirect, url_for, flash, session
from email_validator import validate_email, EmailNotValidError
import sqlite3
from flask_bcrypt import Bcrypt
import re
from datetime import timedelta

bcrypt = Bcrypt()
#Creaza baza de date

# conn = sqlite3.connect('database.db')
# cursor = conn.cursor()
# cursor.execute('INSERT INTO utilizatori (email, password) VALUES ("antonio123", "parola123")')
# conn.commit()
# conn.close()






# connection = sqlite3.connect('products.db')

#     # Create a cursor object to execute SQL commands
# cursor = connection.cursor()

#     # Define the SQL command to create the table
# create_table_query = '''
# CREATE TABLE IF NOT EXISTS products (
#     id INTEGER PRIMARY KEY,
#     name TEXT NOT NULL,
#     categorie TEXT NOT NULL,
#     image BLOB
# );
# '''

#     # Execute the SQL command to create the table
# cursor.execute(create_table_query)

#     # Commit the changes and close the connection
# connection.commit()
# connection.close()







auth = Blueprint('auth', __name__)

def is_valid_email(email):
    # Simple email validation using a regular expression
    pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    return bool(re.match(pattern, email))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.permanent = True
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            flash("Please complete all the fields", 'error')
            return redirect(url_for("auth.login"))
        query = "SELECT email, password, admin FROM utilizatori WHERE email=?"
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        if user[2] == 1:
            session["user"] = user
            return redirect(url_for('auth.admin'))
        if user and bcrypt.check_password_hash(user[1], password):
            user = user[1]
            session["user"] = user
            print("User:", user)
            print("Session email:", session["user"])
            return redirect(url_for("auth.my_account"))
        else:
            flash("Email not found", 'error')
    if 'user' in session:
        return redirect(url_for("auth.my_account"))
    
    return render_template("login.html")


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get("repeat_password")
        if not email or not password or not confirm_password:
            flash("Please complete all the fields", 'error')
            return redirect(url_for("auth.sign_up"))
        if not is_valid_email(email):
            flash('Invalid email. Please try again.', 'error')
            return redirect(url_for("auth.sign_up"))
        
        cursor.execute("SELECT * FROM utilizatori WHERE email = ?", (email,))
        existing_email = cursor.fetchone()

        if existing_email:
            flash("Email already exists", 'error')
            return redirect(url_for("auth.sign_up"))

        if password != confirm_password:
            flash("Passwords don't match")
            return redirect(url_for("auth.sign_up"))
        if len(password) < 8:
           flash("Password is too short")
           return redirect(url_for("auth.sign_up"))
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute("INSERT INTO utilizatori (email, password) VALUES (?, ?)", (email, hashed_password))
            conn.commit()
            cursor.close()
            conn.close()
            flash("You have successfully registered", 'success')
            return redirect(url_for("auth.login"))

    return render_template("sign_up.html")  

@auth.route('/')
@auth.route('/home')
def home():    
    return render_template("home.html")


@auth.route('/my-account', methods=['POST', 'GET'])
def my_account():
    if 'user' in session:
        user = session["user"]
        if request.method == 'POST':
            session.pop('user', None)
            return redirect(url_for('auth.login'))
        return render_template("my_account.html")
    else:
        return redirect(url_for("auth.login"))
    
@auth.route('/admin', methods=['POST', 'GET'])
def admin():
    if request.method == "POST":
        name = request.form.get("name")
        category = request.form.get("category")
        connection = sqlite3.connect('products.db')
        cursor = connection.cursor()
        cursor.execute("INSERT INTO products (name, categorie) VALUES (?, ?)", (name, category))
        connection.commit()
        cursor.close()
        connection.close()
        flash('produs inserat', 'success')
        print('produs inserat')
    return render_template("admin.html") 

@auth.route('/produse', methods=['GET'])
def produse():
    connection = sqlite3.connect('products.db')
    cursor = connection.cursor()
    query = "SELECT * FROM products"
    cursor.execute(query)
    produse = cursor.fetchall()
    cursor.close()
    connection.close()
    
    return render_template("produse.html", produse=produse)
