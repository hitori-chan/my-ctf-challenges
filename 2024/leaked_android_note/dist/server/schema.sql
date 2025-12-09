CREATE DATABASE IF NOT EXISTS android_note;

USE android_note;

CREATE TABLE IF NOT EXISTS users (
	username VARCHAR(255),
	password VARCHAR(255) NOT NULL,
	note_id VARCHAR(255) NOT NULL,
	PRIMARY KEY (username)
)
