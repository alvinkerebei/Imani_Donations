from email.mime.text import MIMEText
import smtplib
from flask import Flask, jsonify, request, session, redirect, url_for
from passlib.hash import pbkdf2_sha256
import pyotp
from app import db, app, generate_verification_token, send_mail
import uuid
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Message  
class Donor:
  
    def start_session(self, donor):
        del donor['password']
        session['logged_in'] = True
        session['donor'] = donor
        return jsonify(donor), 200

    def signup(self):
        print(request.form)

    # Create the user object
        donor = {
        "_id": uuid.uuid4().hex,
        "name": request.form.get('name'),
        "email": request.form.get('email'),
        "password": request.form.get('password')
        }

    # Encrypt the password
        donor['password'] = pbkdf2_sha256.encrypt(donor['password'])

    # Check for existing email address
        if db.donor.find_one({ "email": donor['email'] }):
            return jsonify({ "error": "Email address already in use" }), 400
        
        token, secret = generate_verification_token(donor['email'])
        donor['verification_token'] = token
        donor['totp_secret'] = secret

        send_mail(donor['email'], 'App Verification', f'Find your link here:{token}')

        if db.donor.insert_one(donor):
            return self.start_session(donor)
        
        return jsonify({ "error": "Signup failed" }), 400
    
    def signout(self):
        session.clear()
        return redirect('/')
    
    def login(self):

        donor = db.donor.find_one({"email": request.form.get('email') })

        if donor and pbkdf2_sha256.verify(request.form.get('password'), donor['password']):
            if donor['verified']:
                return self.start_session(donor)
        else:
            return jsonify({ "error": "Email not verified. Please check your email." })
        return jsonify({ "error": "Invalid login credentials" }), 401

    # def create_token(self, expires_in=5000):
    #     token = secrets.token_urlsafe(26)
    
    # def verify_token(token):
    #     s=Serializer(app.config['SECRET_KEY'])
    #     try:
    #         donor_id = s.loads(token)['donor_id']
    #     except:
    #         return None
    #     return Donor.query.get('donor_id')
    

    def reset_pass(self):

        email = request.form.get('email')        
        donor = db.donor.find_one({"email": email})  # Adjust collection name if necessary

        if not email:
            return jsonify({"error": "Invalid Email"})
        else:
            totp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(totp_secret)
            otp=totp.now()
            send_mail(donor['email'], 'Password Reset OTP', f'Your OTP is:{otp}' )
            session['reset_pass'] = email
            session['totp_secret'] = totp_secret

            return redirect(url_for('resettoken'))


        
        
        


        