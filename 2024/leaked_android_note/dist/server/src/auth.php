<?php

require_once('./database.php');
require_once('./utils.php');

function check_creddential_fields()
{
	if (!isset($_POST['username'])) {
		error("Missing username");
	}

	if (!isset($_POST['password'])) {
		error("Missing password");
	}

	if (!is_string($_POST['username'])) {
		error("Username must be a string");
	}

	if (!is_string($_POST['password'])) {
		error("Password must be a string");
	}

	if (!preg_match('/^\w{5,20}/', $_POST['username'])) {
		error("Username must be 5-20 characters and include only [a-zA-Z0-9_]");
	}

	if (!preg_match('/^\w{5,20}/', $_POST['password'])) {
		error("Password must be 5-20 characters and include only [a-zA-Z0-9_]");
	}
}

function register()
{
	check_creddential_fields();

	$username = $_POST['username'];
	$password = $_POST['password'];

	if ($username == $password) {
		error("Username and password must not be the same");
	}

	global $conn;

	$hashed_password = password_hash($password, PASSWORD_DEFAULT);
	$note_id = uniqid();

	$stmt = $conn->prepare("INSERT INTO users VALUES (?, ?, ?)");
	$stmt->bind_param("sss", $username, $hashed_password, $note_id);

	if (!$stmt->execute()) {
		error("Username already existed");
	};

	notice("Register successfully");
}

function login()
{
	check_creddential_fields();

	$username = $_POST['username'];
	$password = $_POST['password'];

	global $conn;

	$stmt = $conn->prepare('SELECT password, note_id FROM users WHERE username=?');
	$stmt->bind_param("s", $username);

	if (!$stmt->execute()) {
		error("Failed to login");
	};

	$row = $stmt->get_result()->fetch_assoc();
	if (!$row) {
		error("Wrong username or password");
	}

	$hashed_password = $row['password'];
	$note_id = $row['note_id'];

	if (!password_verify($password, $hashed_password)) {
		error("Wrong username or password");
	}

	session_status() === PHP_SESSION_ACTIVE ?: session_start();
	$_SESSION['username'] = $username;

	response_json(["note_id" => $note_id, "session_id" => session_id()]);
}

function logout()
{
	session_destroy();
	notice("Logged out");
}
