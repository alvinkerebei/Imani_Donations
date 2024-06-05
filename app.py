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



app.secret_key= '6c9d66617a40fccb1e64d4a52be26562'

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

def reset_token(self):
    if 'reset_pass' not in session:
        return redirect(url_for('reset_token'))
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        email = session['reset_pass']
        totp_secret = session['top_secret']
        donor = db.donor.find_one ({"email": email})

        if donor:
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(otp):
                return redirect(url_for('changepass'))
            else:
                flash('invalid OTP', 'error')

    return render_template ('reset_token.html')

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



@app.route('/donor/signup', methods=['POST','GET'])
def signup():
    if request.method == "POST":
# Create the user object
        donor = {
        "_id": uuid.uuid4().hex,
        "name": request.form.get('name'),
        "email": request.form.get('email'),
        "password": request.form.get('password')
        }

    # Encrypt the password
        donor['password'] = pbkdf2_sha256.hash(donor['password'])

        if not donor.get('email') or not donor.get('name') or not donor.get('password'):
            flash("All fields are required.", "error")
            return redirect(url_for('signup'))

        if db.donor.find_one({"$or": [{"email": donor['email']}, {"name": donor['name']}]}):
            flash("Username or Email is already in use.", "error")
            return redirect(url_for('signup'))
        else:
            # Insert the new user into the 'customer' collection in the database.
            db.donor.insert_one(donor)
            flash("Signup is a Success! Check your email for OTP.", "success")
            totp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(totp_secret).now()
            send_mail(donor['email'], 'Account Activation OTP', f'Your OTP is:{totp_secret}' )
            session['logged_in'] = True
            session['donor'] = donor['email']
            session['totp_secret'] = totp_secret
            return redirect(url_for('verifyotp'))
        
    return render_template('signup.html')

@app.route('/donor/verifyotp', methods=['POST','GET'])
def verifyotp():
 if 'donor' not in session:
     return redirect(url_for('signup'))
 
 if request.method == 'POST':
        donor_otp = request.form.get('otp')
        email = session['donor']
        totp_secret = session['totp_secret']
        print(f"Form OTP: {donor_otp}")
        print(f"Session Email: {email}")
        print(f"Session TOTP Secret: {totp_secret}")
        donor = db.donor.find_one({"email": email})

        if donor:
            totp = pyotp.TOTP(totp_secret)
            if totp == donor_otp:
                flash("OTP is correct! You may now login", 'success')
                return redirect(url_for('login'))
            else:
                flash("Invalid OTP.",'error')
        flash()

 return render_template('verify_otp.html')

@app.route('/donor/login', methods=['POST','GET'])
def login():

    if request.method == "POST":
        donor = db.donor.find_one({"email": request.form.get('email') })

        if donor and pbkdf2_sha256.verify(request.form.get('password'), donor['password']):
            if donor['verified']:
                return None
        else:
            return jsonify({ "error": "Email not verified. Please check your email." })
        return jsonify({ "error": "Invalid login credentials" }), 401

    return render_template('login.html')

@app.route('/donor/signout')
def signout(self):
    session.clear()
    return redirect('/')

# @app.route('/donor/reset_pass', methods=['POST', 'GET'])
# def reset_pass(self):

#     email = request.form.get('email')        
#     donor = db.donor.find_one({"email": email})  # Adjust collection name if necessary

#     if not email:
#         return jsonify({"error": "Invalid Email"})
#     else:
#         totp_secret = pyotp.random_base32()
#         totp = pyotp.TOTP(totp_secret)
#         otp=totp.now()
#         send_mail(donor['email'], 'Password Reset OTP', f'Your OTP is:{otp}' )
#         session['reset_pass'] = email
#         session['totp_secret'] = totp_secret

#         return redirect(url_for(''))

if __name__ == "__main__":
    app.run(debug=True)