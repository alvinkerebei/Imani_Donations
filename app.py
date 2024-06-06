from email.mime.text import MIMEText
import smtplib
from flask import Flask, flash, render_template, session, redirect, url_for, request
from functools import wraps
from flask_mail import Mail, Message
import pymongo, os
import pyotp
from flask import Flask, flash, render_template
from email.mime.text import MIMEText
import smtplib
from flask import Flask, jsonify, request, session, redirect, url_for
from passlib.hash import pbkdf2_sha256
import pyotp
import uuid
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Message  

app = Flask(__name__)
app.secret_key= 'alvinsecretkey'

EMAIL_ADDRESS='kerebeialvin69@gmail.com'
EMAIL_PASSWORD='yfan yhnw kere obsr'
mail = Mail(app)

def send_mail(to_address, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To']= to_address

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_address, msg.as_string())

# Database
client = pymongo.MongoClient('localhost', 27017)
db = client.imanidonationdb

def login_required(f):
  @wraps(f)
  def wrap(*args, **kwargs):
    if 'logged_in' in session:
      return f(*args, **kwargs)
    else:
      return redirect('/')
  
  return wrap

@app.route('/')
def home():
  return render_template('index.html')

@app.route('/donordash/')
@login_required
def donordash():
  return render_template('donordash.html')



@app.route('/donor/signup', methods=['POST', 'GET'])
def signup():
    if request.method == "POST":
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not name or not password:
            flash("All fields are required.", "error")
            return redirect(url_for('signup'))

        donor = {
            "_id": uuid.uuid4().hex,
            "name": name,
            "email": email,
            "password": pbkdf2_sha256.hash(password)
        }

        if db.donor.find_one({"$or": [{"email": email}, {"name": name}]}):
            flash("Username or Email is already in use.", "error")
            return redirect(url_for('signup'))

        db.donor.insert_one(donor)
        flash("Signup is a Success! Check your email for OTP.", "success")
        
        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        otp = totp.now()

        send_mail(email, 'Account Activation OTP', f'Your OTP is: {otp}')
        
        session['logged_in'] = True
        session['signup'] = email
        session['totp_secret'] = totp_secret
        session['name'] = name

        # Debug logging
        print(f"Signup - Email: {session['signup']}, TOTP Secret: {session['totp_secret']}")

        return redirect(url_for('verifyotp'))

    return render_template('signup.html')


@app.route('/donor/verifyotp', methods=['POST', 'GET'])
def verifyotp():
    if 'signup' not in session:
        flash("Not in session", 'error')
        return redirect(url_for('signup'))

    if request.method == 'POST':
        donor_otp = request.form.get('otp')
        email = session.get('signup')
        totp_secret = session.get('totp_secret')
        
        # Debug logging
        print(f"Verify OTP - Form OTP: {donor_otp}")
        print(f"Verify OTP - Session Email: {email}")
        print(f"Verify OTP - Session TOTP Secret: {totp_secret}")

        donor = db.donor.find_one({"email": email})

        if not donor:
            flash("Email doesn't exist", 'error')
            return redirect(url_for('signup'))

        totp = pyotp.TOTP(totp_secret)
        if totp.verify(donor_otp, valid_window=1):
            flash("OTP is correct! You may now login", 'success')
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP.", 'error')

    return render_template('verify_otp.html')

@app.route('/donor/login', methods=['POST','GET'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        donor = db.donor.find_one({"email": email })

        if donor and pbkdf2_sha256.verify(password, donor['password']):
            totp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(totp_secret)
            otp = totp.now()

            session['totp_secret'] = totp_secret
            session['logged_in'] = True
            session['login'] = {
                '_id': donor['_id'],
                'name': donor['name'],
                'email': donor['email']
            }

            send_mail(email, 'Login Verification Code:', f'Your Verification Code is: {otp}')
            
            flash("Check Email for Verification Code",'success')
            return redirect(url_for('twoFA'))
        else:
            flash("Invalid Email or Password", 'error')


    return render_template('login.html')

@app.route('/donor/twoFA', methods=['POST', 'GET'])
def twoFA():
    if 'login' not in session:
        flash("Not in session", 'error')
        return redirect(url_for('login'))
    else:
        if request.method == 'POST':
            donor_otp = request.form.get('otp')
            totp_secret = session['totp_secret']
            print(f"Form OTP: {donor_otp}")
            print(f"Session TOTP Secret: {totp_secret}")    

            totp = pyotp.TOTP(totp_secret)
            if totp.verify(donor_otp, valid_window=1):
                flash("Verification Complete!", 'success')
                return redirect(url_for('donordash'))
            else:
                flash("Invalid OTP", 'error')

    return render_template('twoFA.html')

@app.route('/donor/forgot_pass', methods=['POST', 'GET'])
def forgot_pass():
    if request.method == 'POST':
        email = request.form.get('email')
        donor = db.donor.find_one({"email": email})

        if donor:
            totp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(totp_secret)
            otp = totp.now()

            session['totp_secret'] = totp_secret
            session['forgotpass'] = email

            send_mail(donor['email'], 'Password Reset Code', f"Your reset code is: {otp}") 

            flash("Password Reset Code has been sent to your Email")
            return redirect(url_for('verify_forgotpass'))
        else:
            flash ("Invalid Email", 'error')
            return redirect(url_for('login'))
    
    elif request.method == 'GET':
        return render_template('forgot_pass.html')

    return render_template('forgot_pass.html')

@app.route('/donor/verify_forgotpass', methods = ['POST', 'GET'])
def verify_forgotpass():
    if 'forgotpass' not in session:
        flash('Not in Session', 'error')
        return redirect(url_for('forgot_pass'))
    else:
        if request.method == 'POST':
            donor_otp = request.form.get('otp')
            totp_secret = session['totp_secret']
            print(f"Form OTP: {donor_otp}")
            print(f"Session TOTP Secret: {totp_secret}")   

            totp = pyotp.TOTP(totp_secret)
            if totp.verify(donor_otp, valid_window=1):
                flash("Reset Code is Valid... You may Change Your Password", 'success')
                return redirect(url_for('changepass'))
            else:
                flash("Invalid Code", 'error')

    return render_template('verify_forgotpass.html')

@app.route('/donor/changepass', methods=['POST','GET'])
def changepass():
    if 'forgotpass' not in session:
        flash('Not in Session', 'error')
        return redirect(url_for('forgot_pass'))
    else:
        if request.method == 'POST':
            newPassword = request.form.get('newpassword')
            confirmPassword = request.form.get('cpassword')
            
            email = session['forgotpass']

            if newPassword != confirmPassword:
                flash("Password DO NOT Match!", 'error')
            else:
                hashedPass = pbkdf2_sha256.hash(newPassword)
                db.donor.update_one({'email': email},{'$set': {'password': hashedPass}})
                flash("Password Reset Successfully. Login with your new Password", 'success')

                session.pop('forgotpass', None)
                return redirect('login')

    return render_template('changepass.html')

@app.route('/donor/signout')
def signout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)