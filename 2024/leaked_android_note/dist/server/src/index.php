<?php

error_reporting(E_ERROR | E_PARSE);
ini_set('session.use_cookies', '0');

require_once('./utils.php');
require_once("./auth.php");
require_once('./note.php');

require_android();

$_POST = json_decode(decrypt_request(file_get_contents("php://input")), true);

ob_start("encrypt_response");

if (!isset($_POST)) {
	error("Invalid JSON");
}

if (!isset($_POST['action'])) {
	error('Missing action');
}

switch ($_POST['action']) {
	case 'login':
		login();
		break;
	case 'logout':
		logout();
		break;
	case 'register':
		register();
		break;
	case 'get':
		get();
		break;
	case 'save':
		save();
		break;
	default:
		error("Invalid action");
}

ob_end_flush();
