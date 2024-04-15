<?php
session_start();

// Database connection
$servername = "db"; // This is the service name in docker-compose.yml
$username = "root";
$password = ""; // No password set
$dbname = "bonkers_login";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST["email"];
    $password = $_POST["password"];

    // Prepare SQL statement to fetch user from database
    $sql = "SELECT * FROM users WHERE email = ? AND plain_password = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $email, $password);
    $stmt->execute();
    $result = $stmt->get_result();

    // Check if user exists
    if ($result->num_rows == 1) {
        // Login successful, set session variables and redirect to index.html
        $_SESSION["email"] = $email;
        header("Location: index.html");
        exit();
    } else {
        // Invalid credentials, redirect back to login page with error message
        header("Location: login.html?error=InvalidCredentials");
        exit();
    }
}

$conn->close();
?>
