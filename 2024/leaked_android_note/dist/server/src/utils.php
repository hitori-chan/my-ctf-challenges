<?php

require_once('./config.php');

function require_login()
{
	if (isset($_POST['session_id'])) {
		session_id($_POST['session_id']);
		session_start();
	}
	if (!isset($_SESSION['username'])) {
		error("Please login first");
	}
}

function require_android()
{
	if (!isset($_SERVER['HTTP_USER_AGENT']) || !preg_match('/Android/', $_SERVER['HTTP_USER_AGENT'])) {
		die();
	}
}

function notice($msg)
{
	response_json(["msg" => $msg]);
}

function error($msg)
{
	die_json(['error' => $msg]);
}

function response_json($data)
{
	echo json_encode($data);
}

function die_json($data)
{
	die(json_encode($data));
}

function encrypt_response($buffer)
{
	global $CIPHER, $AES_KEY, $IV_LENGTH;

	$iv = openssl_random_pseudo_bytes($IV_LENGTH);
	$ciphertext = openssl_encrypt($buffer, $CIPHER, $AES_KEY, OPENSSL_RAW_DATA, $iv, $tag);

	return base64_encode($iv . $ciphertext . $tag);
}

function decrypt_request($buffer)
{
	global $CIPHER, $AES_KEY, $IV_LENGTH, $TAG_LENGTH;

	$buffer = base64_decode($buffer);
	$buffer_len = strlen($buffer);

	$iv = substr($buffer, 0, $IV_LENGTH);
	$tag = substr($buffer, $buffer_len - $TAG_LENGTH, $TAG_LENGTH);
	$ciphertext = substr($buffer, $IV_LENGTH, $buffer_len - $IV_LENGTH - $TAG_LENGTH);

	return openssl_decrypt($ciphertext, $CIPHER, $AES_KEY, OPENSSL_RAW_DATA, $iv, $tag);
}
