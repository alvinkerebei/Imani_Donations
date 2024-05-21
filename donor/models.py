from flask import Flask, jsonify, request, session, redirect
from passlib.hash import pbkdf2_sha256
from app import db
import uuid

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

        if db.donor.insert_one(donor):
            return self.start_session(donor)
        
        return jsonify({ "error": "Signup failed" }), 400
    
    def signout(self):
        session.clear()
        return redirect('/')
    
    def login(self):

        donor = db.donor.find_one({"email": request.form.get('email') })

        if donor and pbkdf2_sha256.verify(request.form.get('password'), donor['password']):
            return self.start_session(donor)
    
        return jsonify({ "error": "Invalid login credentials" }), 401
