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
from passlib.hash import pbkdf2_sha256
import pyotp
import uuid
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Message 
from werkzeug.utils import secure_filename 
from datetime import timedelta

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

#handling pictures
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DEFAULT_PROFILE_PICTURE'] = 'static/default.jpg'
app.config['PERMANENT_SESSION_TIME'] = timedelta(minutes=1)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
  @wraps(f)
  def wrap(*args, **kwargs):
    if 'logged_in' in session:
      return f(*args, **kwargs)
    else:
      return redirect('/')
  
  return wrap

@app.before_request
def make_sesh_permanent():
    session.permanent = True

@app.before_request
def update_sesh_life():
    session.modified =True

@app.route('/')
def home():
  return render_template('index.html')

@app.route('/donordash/')
@login_required
def donordash():
  return render_template('dash.html')

@app.route('/doneedash/')
@login_required
def doneedash():
  return render_template('dash.html')

@app.route('/donorhome/')
def donorhome():
    return render_template('donorhome.html')

@app.route('/doneehome/')
def doneehome():
    return render_template('doneehome.html')

@app.route('/donor/donor_signup', methods=['POST', 'GET'])
def donor_signup():
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
            return redirect(url_for('donor_signup'))

        db.donor.insert_one(donor)
        flash("Signup is a Success! Check your email for OTP.", "success")
        
        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        otp = totp.now()

        send_mail(email, 'Account Activation OTP', f'Your OTP is: {otp}')
        
        session['logged_in'] = True
        session['donor_signup'] = email
        session['totp_secret'] = totp_secret
        session['name'] = name

        # Debug logging
        print(f"Signup - Email: {session['donor_signup']}, TOTP Secret: {session['totp_secret']}")

        return redirect(url_for('verifyotp'))

    return render_template('signup.html', form_action=url_for('donor_signup'))


@app.route('/donor/verifyotp', methods=['POST', 'GET'])
def verifyotp():
    if 'donor_signup' not in session:
        flash("Not in session", 'error')
        return redirect(url_for('donor_signup'))

    if request.method == 'POST':
        donor_otp = request.form.get('otp')
        email = session.get('donor_signup')
        totp_secret = session.get('totp_secret')
        
        # Debug logging
        print(f"Verify OTP - Form OTP: {donor_otp}")
        print(f"Verify OTP - Session Email: {email}")
        print(f"Verify OTP - Session TOTP Secret: {totp_secret}")

        donor = db.donor.find_one({"email": email})

        if not donor:
            flash("Email doesn't exist", 'error')
            return redirect(url_for('donor_signup'))

        totp = pyotp.TOTP(totp_secret)
        if totp.verify(donor_otp, valid_window=1):
            flash("OTP is correct! You may now login", 'success')
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP.", 'error')

    return render_template('verify_otp.html', form_action=url_for('verifyotp'))

@app.route('/donor/donor_login', methods=['POST','GET'])
def donor_login():
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
            session['donor_login'] = {
                '_id': donor['_id'],
                'name': donor['name'],
                'email': donor['email']
            }

            send_mail(email, 'Login Verification Code:', f'Your Verification Code is: {otp}')
            
            flash("Check Email for Verification Code",'success')
            return redirect(url_for('twoFA'))
        else:
            flash("Invalid Email or Password", 'error')


    return render_template('login.html', form_action=url_for('donor_login'), forgot_pass_url=url_for('forgot_pass'))

@app.route('/donor/twoFA', methods=['POST', 'GET'])
def twoFA():
    if 'donor_login' not in session:
        flash("Not in session", 'error')
        return redirect(url_for('donor_login'))
    else:
        if request.method == 'POST':
            donor_otp = request.form.get('otp')
            totp_secret = session['totp_secret']
            print(f"Form OTP: {donor_otp}")
            print(f"Session TOTP Secret: {totp_secret}")    

            totp = pyotp.TOTP(totp_secret)
            if totp.verify(donor_otp, valid_window=1):
                flash("Verification Complete!", 'success')
                return redirect(url_for('donorhome'))
            else:
                flash("Invalid OTP", 'error')

    return render_template('twoFA.html', form_action=url_for('twoFA'))

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
            return redirect(url_for('donor_login'))
    
    elif request.method == 'GET':
        return render_template('forgot_pass.html')

    return render_template('forgot_pass.html', form_action=url_for('forgot_pass'))

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

    return render_template('verify_forgotpass.html', form_action=url_for('verify_forgotpass'))

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
                return redirect('donor_login')

    return render_template('changepass.html', form_action=url_for('changepass'))

@app.route('/donor/profile', methods=['GET', 'POST'])
def profile():
    if'donor_login' in session:
        donor = session['donor_login']
    else:
        flash("Login to see profile details")
        return redirect(url_for('donor_login'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        password = request.form.get('password')
        profile_picture = request.files.get('profile_picture')   
      
        # Update user details
        update_data = {
            'name': name,
            'email': email,
            'phone': phone,
            'address': address,
        }
        
        if password:
            update_data['password'] = pbkdf2_sha256.hash(password) 

    if profile_picture and allowed_file(profile_picture.filename):
        filename = secure_filename(profile_picture.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        profile_picture.save(filepath)
        normalized_filepath = filepath.replace('\\', '/')
        update_data['profile_picture'] = filepath
        session['donor_login']['profile_picture'] = normalized_filepath
    else:
    # Use the existing profile picture or the default one
        if 'profile_picture' not in donor:
            update_data['profile_picture'] = app.config['DEFAULT_PROFILE_PICTURE']

        print(update_data)

        # Update the user in the database
        db.donor.update_one({'_id': donor['_id']}, {'$set': update_data})
        
        # Update session data
        session_data = session.get('donor_login')
        for key, value in update_data.items():
            session_data[key] = value
        session['donor_login'] = session_data
        
        flash("Profile updated successfully.", "success")
        return redirect(url_for('profile'))
    
    return render_template('donorprofile.html', donor=donor)

@app.route('/donor/make_donation')
def make_donation():
    return render_template('donorhome.html')

@app.route('/donor/signout')
def signout():
    session.clear()
    return redirect('/')

#DONEE BACKEND

@app.route('/donee/donee_signup', methods=['POST', 'GET'])
def donee_signup():
    if request.method == "POST":
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not name or not password:
            flash("All fields are required.", "error")
            return redirect(url_for('donee_signup'))

        donee = {
            "_id": uuid.uuid4().hex,
            "name": name,
            "email": email,
            "password": pbkdf2_sha256.hash(password)
        }

        if db.donee.find_one({"$or": [{"email": email}, {"name": name}]}):
            flash("Username or Email is already in use.", "error")
            return redirect(url_for('donee_signup'))

        db.donee.insert_one(donee)
        flash("Signup is a Success! Check your email for OTP.", "success")
        
        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        otp = totp.now()

        send_mail(email, 'Account Activation OTP', f'Your OTP is: {otp}')
        
        session['logged_in'] = True
        session['donee_signup'] = email
        session['totp_secret'] = totp_secret
        session['name'] = name

        # Debug logging
        print(f"Signup - Email: {session['donee_signup']}, TOTP Secret: {session['totp_secret']}")

        return redirect(url_for('verifyotp2'))

    return render_template('signup.html', form_action=url_for('donee_signup'))

@app.route('/donee/verifyotp2', methods=['POST', 'GET'])
def verifyotp2():
    if 'donee_signup' not in session:
        flash("Not in session", 'error')
        return redirect(url_for('donee_signup'))

    if request.method == 'POST':
        donee_otp = request.form.get('otp')
        email = session.get('donee_signup')
        totp_secret = session.get('totp_secret')
        
        # Debug logging
        print(f"Verify OTP - Form OTP: {donee_otp}")
        print(f"Verify OTP - Session Email: {email}")
        print(f"Verify OTP - Session TOTP Secret: {totp_secret}")

        donee = db.donee.find_one({"email": email})

        if not donee:
            flash("Email doesn't exist", 'error')
            return redirect(url_for('donee_signup'))

        totp = pyotp.TOTP(totp_secret)
        if totp.verify(donee_otp, valid_window=1):
            flash("OTP is correct! You may now login", 'success')
            return redirect(url_for('donee_login'))
        else:
            flash("Invalid OTP.", 'error')

    return render_template('verify_otp.html', form_action=url_for('verifyotp2'))

@app.route('/donee/donee_login', methods=['POST','GET'])
def donee_login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        donee = db.donee.find_one({"email": email })

        if donee and pbkdf2_sha256.verify(password, donee['password']):
            totp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(totp_secret)
            otp = totp.now()

            session['totp_secret'] = totp_secret
            session['logged_in'] = True
            session['donee_login'] = {
                '_id': donee['_id'],
                'name': donee['name'],
                'email': donee['email']
            }

            send_mail(email, 'Login Verification Code:', f'Your Verification Code is: {otp}')
            
            flash("Check Email for Verification Code",'success')
            return redirect(url_for('twoFA2'))
        else:
            flash("Invalid Email or Password", 'error')

    return render_template('login.html', form_action=url_for('donee_login'), forgot_pass_url=url_for('forgot_pass2'))

@app.route('/donee/twoFA2', methods=['POST', 'GET'])
def twoFA2():
    if 'donee_login' not in session:
        flash("Not in session", 'error')
        return redirect(url_for('donee_login'))
    else:
        if request.method == 'POST':
            donee_otp = request.form.get('otp')
            totp_secret = session['totp_secret']
            print(f"Form OTP: {donee_otp}")
            print(f"Session TOTP Secret: {totp_secret}")    

            totp = pyotp.TOTP(totp_secret)
            if totp.verify(donee_otp, valid_window=1):
                flash("Verification Complete!", 'success')
                return redirect(url_for('doneehome'))
            else:
                flash("Invalid OTP", 'error')

    return render_template('twoFA.html', form_action=url_for('twoFA2'))

@app.route('/donee/forgot_pass2', methods=['POST', 'GET'])
def forgot_pass2():
    if request.method == 'POST':
        email = request.form.get('email')
        donee = db.donee.find_one({"email": email})

        if donee:
            totp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(totp_secret)
            otp = totp.now()

            session['totp_secret'] = totp_secret
            session['forgotpass2'] = email

            send_mail(donee['email'], 'Password Reset Code', f"Your reset code is: {otp}") 

            flash("Password Reset Code has been sent to your Email")
            return redirect(url_for('verify_forgotpass2'))
        else:
            flash ("Invalid Email", 'error')
            return redirect(url_for('donee_login'))
    
    elif request.method == 'GET':
        return render_template('forgot_pass.html', form_action=url_for('forgot_pass2'))
    
@app.route('/donee/verify_forgotpass2', methods = ['POST', 'GET'])
def verify_forgotpass2():
    if 'forgotpass2' not in session:
        flash('Not in Session', 'error')
        return redirect(url_for('forgot_pass2'))
    else:
        if request.method == 'POST':
            donee_otp = request.form.get('otp')
            totp_secret = session['totp_secret']
            print(f"Form OTP: {donee_otp}")
            print(f"Session TOTP Secret: {totp_secret}")   

            totp = pyotp.TOTP(totp_secret)
            if totp.verify(donee_otp, valid_window=1):
                flash("Reset Code is Valid... You may Change Your Password", 'success')
                return redirect(url_for('changepass2'))
            else:
                flash("Invalid Code", 'error')

    return render_template('verify_forgotpass.html', form_action=url_for('verify_forgotpass2'))

@app.route('/donee/changepass2', methods=['POST','GET'])
def changepass2():
    if 'forgotpass2' not in session:
        flash('Not in Session', 'error')
        return redirect(url_for('forgot_pass2'))
    else:
        if request.method == 'POST':
            newPassword = request.form.get('newpassword')
            confirmPassword = request.form.get('cpassword')
            
            email = session['forgotpass2']

            if newPassword != confirmPassword:
                flash("Password DO NOT Match!", 'error')
            else:
                hashedPass = pbkdf2_sha256.hash(newPassword)
                db.donee.update_one({'email': email},{'$set': {'password': hashedPass}})
                flash("Password Reset Successfully. Login with your new Password", 'success')

                session.pop('forgotpass2', None)
                return redirect('donee_login')

    return render_template('changepass.html', form_action=url_for('changepass2'))

@app.route('/donee/profile2', methods=['GET', 'POST'])
def profile2():
    if'donee_login' in session:
        donee = session['donee_login']
    else:
        flash("Login to see profile details")
        return redirect(url_for('donee_login'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        password = request.form.get('password')
        
        # Update user details
        update_data = {
            'name': name,
            'email': email,
            'phone': phone,
            'address': address,
        }
        
        if password:
            update_data['password'] = pbkdf2_sha256.hash(password)
        
        # Update the user in the database
        db.donee.update_one({'_id': donee['_id']}, {'$set': update_data})
        
        # Update session data
        donee.update(update_data)
        session.modified = True
        
        flash("Profile updated successfully.", "success")
        return redirect(url_for('profile2'))
    
    return render_template('doneeprofile.html')

@app.route('/donee/create_profile')
def create_profile():
    return render_template('doneehome.html')

@app.route('/donee/signout')
def signout2():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)