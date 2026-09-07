CREATE DATABASE IF NOT EXISTS security_analyzer;

USE security_analyzer;

CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME,
    event VARCHAR(50),
    username VARCHAR(50),
    ip_address VARCHAR(45),
    UNIQUE (timestamp, event, username, ip_address)
);
