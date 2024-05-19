from flask import Flask
from app import app #from app.py you import app(the instance)
from donor.models import Donor #from user dir, import models.py then import class User

@app.route('/donor/signup',methods=['POST', 'GET'])
def signup():
    return Donor().signup() #creates a new class instance