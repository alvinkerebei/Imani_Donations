from flask import Flask, flash, render_template
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

@app.route('/donor/reset_pass', methods=['POST', 'GET'])
def reset_pass():
  return Donor().reset_pass()

@app.route('/donor/reset_token')
def resettoken():
  return render_template('reset_token.html')