<?php

$CIPHER = 'AES-256-GCM';

$AES_KEY = getenv("AES_KEY");
if (!$AES_KEY) {
	$AES_KEY = hex2bin("fc6426c9d841e632267dd44807ace9d6d3aca04dc52ae8a793ec959bd84cb0e6");
}

$IV_LENGTH = openssl_cipher_iv_length($CIPHER);
$TAG_LENGTH = 16;
