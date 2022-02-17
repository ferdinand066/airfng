<?php
$config = require_once("config.php");

$conn = new mysqli($config['server'], $config['username'], $config['password'], $config['database']);
if($conn->connect_error) {
    die("Connection to DB failed");
}

session_start();

require("csrf.php");