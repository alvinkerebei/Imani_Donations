import mysql.connector

mydb = mysql.connector.connect(
    host = "localhost",
    user = "root",
    password = "12345",
    database = "imanidonationdb"
)

mycursor = mydb.cursor()

sql = "insert into donororg_user (username, email, password) values(%s, %s, %s)"
#val = ("user1", "user1@gmail.com", "54321")
mycursor.execute(sql)

mydb.commit()

print(mycursor.rowcount, "inserted!")