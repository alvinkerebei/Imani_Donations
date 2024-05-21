from flask import Flask, render_template, session, redirect
from functools import wraps
import pymongo

app = Flask(__name__)
app.secret_key = "imtheone"

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