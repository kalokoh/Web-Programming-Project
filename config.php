<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* Database config */
$db_host = 'localhost';
$db_user = 'root';
$db_pass = ''; // XAMPP default is empty
$db_name = 'fb';

/* Create mysqli connection */
$mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($mysqli->connect_errno) {
    die("Failed to connect to MySQL: (" . $mysqli->connect_errno . ") " . $mysqli->connect_error);
}

/* Helper: escape output */
function e($string) {
    return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

/* Require login helper */
function require_login() {
    if (empty($_SESSION['user_id'])) {
        header("Location: /football_agent/login.php");
        exit;
    }
}

/* Role check */
function require_role($role) {
    if (empty($_SESSION['role']) || $_SESSION['role'] !== $role) {
        header("Location: /football_agent/login.php");
        exit;
    }
}
?>
