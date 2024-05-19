from flask import Flask, render_template
import pymongo

app=Flask(__name__) #app here is an instance of flask

#database
client = pymongo.MongoClient('localhost',27017)
db = client.imanidonationdb

#the routes
from donor import routes

@app.route('/') #route of the file
def home(): #name of function
    return render_template('home.html')

@app.route('/org-registration/') #route of the file
def registrationorrg(): #name of function
    return render_template('home.html')