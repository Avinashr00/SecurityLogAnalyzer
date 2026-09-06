from datetime import datetime
import mysql.connector
from dotenv import load_dotenv
import os

load_dotenv()

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd=os.getenv("DB_PASSWORD"),
    database="security_analyzer"
)

mycursor = mydb.cursor()

file = open("security.log", "r")

print("Starting log analysis...")

failed_attempts = {}
targeted_users = {}
successful_logins = {}
user_ips = {}

for line in file:
    parts = line.split()
    
    date = parts[0]
    time = parts[1]
    event = parts[2]
    
    timestamp = datetime.strptime(date + " " + time, "%Y-%m-%d %H:%M:%S")
        
    user = parts[3].split("=")[1]
    ip = parts[4].split("=")[1]
    
    sql = """
    INSERT INTO security_logs
    (timestamp, event, username, ip_address)
    VALUES (%s, %s, %s, %s)
    """

    values = (timestamp, event, user, ip)

    mycursor.execute(sql + " ON DUPLICATE KEY UPDATE id=id", values)
    
    if event == "LOGIN_FAILED":
        if ip not in failed_attempts:
            failed_attempts[ip] = []
            
        failed_attempts[ip].append(timestamp)

        if ip not in targeted_users:
            targeted_users[ip] = []
            
        targeted_users[ip].append(user)
    
    
    elif event == "LOGIN_SUCCESS":
        if ip not in successful_logins:
            successful_logins[ip] = []
            
        successful_logins[ip].append({
            "time": timestamp,
            "user": user
        })
        
        if user not in user_ips:
            user_ips[user] = set()
        
        user_ips[user].add(ip)
        
    
    print("Date:", date)
    print("Time:", time)
    print("Event:", event)
    print("User:", user)
    print("IP:", ip)
    print("----------------------")
    
print("failed login attempts:", failed_attempts)
print("targeted users:", targeted_users)
print("successful logins:", successful_logins)
print("user IPs:", user_ips)


def detect_brute_force(failed_attempts, threshold):
    for ip, count in failed_attempts.items():
       
        first_attempt = count[0]
        last_attempt = count[-1]
        
        difference = last_attempt - first_attempt
        
        print("IP:", ip)
        print("Time difference:", difference.total_seconds(), "seconds")
        
        if len(count) >= threshold and difference.total_seconds() <= 60:
            print("ALERT: Possible brute-force attack detected!")
            print("IP:", ip)
            print("Failed attempts:", len(count))

detect_brute_force(failed_attempts, 3)

def detect_multiple_users(targeted_users, threshold):
    for ip, users in targeted_users.items():

        unique_users = set(users)

        print("IP:", ip)
        print("Users targeted:", unique_users)

        if len(unique_users) >= threshold:
            print("ALERT: Possible account-targeting attack detected!")
            print("IP:", ip)
            print("Different usernames:", len(unique_users))


detect_multiple_users(targeted_users, 3)

def detect_success_after_failures(failed_attempts, successful_logins, threshold):
    for ip, successes in successful_logins.items():

        if ip in failed_attempts:
            failed_count = len(failed_attempts[ip])

            last_failed = failed_attempts[ip][-1]

            for login in successes:
                print("Successful login:", login["user"])
                print("Login time:", login["time"])

                difference = login["time"] - last_failed

                print("Time after last failure:", difference.total_seconds(), "seconds")

                if failed_count >= threshold and difference.total_seconds() <= 60:
                    print("ALERT: Suspicious successful login after multiple failures!")


detect_success_after_failures(failed_attempts, successful_logins, 3)

def detect_multiple_ips(user_ips, threshold):
    for user, ips in user_ips.items():

        print("User:", user)
        print("IP addresses:", ips)

        if len(ips) >= threshold:
            print("ALERT: User logged in from multiple IP addresses!")
            print("User:", user)
            print("Different IPs:", len(ips))

detect_multiple_ips(user_ips, 2)

mydb.commit()
    
file.close()

