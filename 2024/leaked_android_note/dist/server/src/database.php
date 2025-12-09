<?php

mysqli_report(MYSQLI_REPORT_OFF);

$conn = new mysqli("db", "root", "bocchitherock", "android_note");

if ($conn->connect_error) {
	error("Connection failed: " . $conn->connect_error);
}
