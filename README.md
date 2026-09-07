# Security Log Analyzer

## Overview

Security Log Analyzer is a Python and MySQL-based cybersecurity project that analyzes authentication logs and identifies suspicious login activity.

The application reads security events from a log file, extracts information such as timestamp, event type, username, and IP address, stores the structured data in a MySQL database, and applies rule-based detection techniques to identify potentially suspicious behavior.

## Features

- Parses authentication logs using Python
- Converts log timestamps into Python datetime objects
- Stores structured security events in MySQL
- Detects possible brute-force attacks
- Detects attempts targeting multiple usernames
- Detects successful logins after repeated failures
- Detects successful logins from multiple IP addresses
- Prevents duplicate log entries in the database
- Uses configurable detection thresholds

## Detection Rules

The analyzer uses rule-based detection to identify suspicious authentication patterns.

### 1. Brute-Force Detection

If an IP address generates multiple failed login attempts within a defined time window, the system raises a possible brute-force alert.

**Default threshold:** 3 failed attempts within 60 seconds.

### 2. Multiple Username Targeting

If a single IP address attempts to log in using multiple different usernames, the system flags the activity as possible account-targeting behavior.

**Default threshold:** 3 different usernames.

### 3. Successful Login After Failed Attempts

If a successful login occurs shortly after multiple failed login attempts from the same IP address, the system generates a suspicious-login alert.

**Default threshold:** 3 failed attempts followed by a successful login within 60 seconds.

### 4. Multiple IP Addresses for One User

If the same username successfully logs in from multiple IP addresses, the system flags the activity for further investigation.

**Default threshold:** 2 different IP addresses.

## Technologies Used

- Python — Log parsing, data processing, timestamp handling, and security-rule detection
- MySQL — Storage and SQL-based analysis of security events
- MySQL Connector/Python — Communication between Python and MySQL
- VS Code — Development environment

## Project Structure

SecurityLogAnalyzer/
- main.py
- security.log
- database.sql
- requirements.txt
- test_mysql.py
- README.md
- .gitignore
- .env

## How to Run

1. Clone the repository:

   git clone https://github.com/Avinashr00/SecurityLogAnalyzer.git

2. Open the project folder:

   cd SecurityLogAnalyzer

3. Install the required Python packages:

   pip install -r requirements.txt

4. Set up the MySQL database using database.sql.

5. Create a .env file and add your own MySQL password:

   DB_PASSWORD=your_mysql_password

6. Run the analyzer:

   python main.py

## Example Detection

The analyzer can identify suspicious patterns such as:

- Multiple failed login attempts from the same IP address
- Attempts against multiple usernames
- Successful login immediately after repeated failures
- Successful logins from multiple IP addresses

## Security Considerations

Database credentials are stored in a .env file and are excluded from Git using .gitignore.

The .env file must never be committed to the repository.

## Future Improvements

- Real-time log monitoring
- More advanced detection rules
- Alert severity levels
- Log filtering and reporting
- Web-based security dashboard
- Machine learning-based anomaly detection