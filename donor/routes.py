from flask import Flask
from app import app
from donor.models import Donor

@app.route('/donor/signup', methods=['POST'])
def signup():
  return Donor().signup()

@app.route('/donor/signout')
def signout():
  return Donor().signout()

@app.route('/donor/login', methods=['POST'])
def login():
  return Donor().login()
