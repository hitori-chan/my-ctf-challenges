<?php

require_once('./utils.php');

function get()
{
	require_login();

	if (!isset($_POST['note_id'])) {
		error("Missing note_id");
	}

	$path = sprintf('notes/%s/%s', $_SESSION['username'], $_POST['note_id']);
	response_json(["content" => file_get_contents($path)]);
}

function save()
{
	require_login();

	if (!isset($_POST['note_id'])) {
		error("Missing note_id");
	}

	if (!isset($_POST['content'])) {
		error("Missing content");
	}

	if (strlen($_POST['content']) > 10000) {
		error("Note is too long");
	}

	mkdir('notes/' . $_SESSION['username'], recursive: true);
	$path = sprintf('notes/%s/%s', $_SESSION['username'], $_POST['note_id']);

	file_put_contents($path, $_POST['content']);

	notice("Saved");
}
