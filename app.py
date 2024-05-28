from email.mime.text import MIMEText
import smtplib
from flask import Flask, flash, render_template, session, redirect, url_for, request
from functools import wraps
from flask_mail import Mail, Message
import pymongo, os
import pyotp

app = Flask(__name__)

app.config['SECRET_KEY']= '9272db82db33bbefff713184ca1dfcbe'

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

def generate_verification_token(email):
    totp = pyotp.TOTP(pyotp.random_base32(), interval=600)  # Token valid for 10 minutes
    return totp.now(), totp.secret

def send_verification_email(email, token):
    msg = Message('Email Verification', sender='kerebeialvin69@gmail.com', recipients=[email])
    link = url_for('verify_email', token=token, _external=True)
    msg.body = f'Your verification link is {link}'
    mail.send(msg)


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

# Routes
from donor import routes

@app.route('/')
def home():
  return render_template('home.html')

@app.route('/donordash/')
@login_required
def donordash():
  return render_template('donordash.html')

@app.route('/reset_pass')
def resetpass():
  return render_template('reset_pass.html')

@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    donor = db.donor.find_one({ "verification_token": token })
    if donor:
        # Verify the token
        totp = pyotp.TOTP(donor['totp_secret'])
        if totp.verify(token):
            # Update the user's status to verified
            db.donor.update_one({ "_id": donor['_id'] }, { "$set": { "verified": True }, "$unset": { "verification_token": "", "totp_secret": "" } })
            flash('Your email has been verified. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired verification link.', 'error')
    else:
        flash('Invalid verification link.', 'error')

    return redirect(url_for('signup'))


if __name__ == "__main__":
    app.run(debug=True)
