from flask import Flask, jsonify, request
import uuid
from passlib.hash import pbkdf2_sha256
from app import db

class Donor:

    def signup(self):
        print(request.form)

#the 'name' is gotten from name attribute in the form line 15
#create user object
        donor = {
            "_id":uuid.uuid4().hex,
            "name": request.form.get('name'), 
            "email":request.form.get('email'), 
            "password":request.form.get('password'),
        }

#encrypt password
        donor['password'] = pbkdf2_sha256.hash(donor['password'])

        #check email if exists already
        if db.donor.find_one({ "email": donor['email'] }):
            return jsonify({"error":"Email already in use"}), 400
        
#donor is collection to be saved into
        if db.donor.insert_one(donor): 
            return jsonify(donor), 200

        return jsonify({"error": "Signup failed"}), 400