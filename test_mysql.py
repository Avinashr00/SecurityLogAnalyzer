import mysql.connector

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="avi_root@1234",
    database="security_analyzer"
)

mycursor = mydb.cursor()

sql = """
INSERT INTO security_logs
(timestamp, event, username, ip_address)
VALUES (%s, %s, %s, %s)
"""

values = (
    "2026-09-06 10:15:21",
    "LOGIN_SUCCESS",
    "arun",
    "192.168.1.10"
)

mycursor.execute(sql, values)

mydb.commit()

print("Log inserted successfully!")

mydb.close()