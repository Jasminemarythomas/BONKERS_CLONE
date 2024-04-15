<?php
session_start(); // Start the session

$servername = "db"; // This is the service name in docker-compose.yml
$username = "root";
$password = ""; // No password set
$dbname = "bonkers_login"; // Updated to use the correct database name

// Check if the form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Validate and sanitize user registration inputs
    $name = trim($_POST['name']);
    $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
    $plain_password = $_POST['plain_password'];

    // Validation checks
    $errors = [];
    if (empty($name)) {
        $errors[] = "Name is required.";
    }
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Valid email address is required.";
    }
    if (empty($plain_password)) {
        $errors[] = "Password is required.";
    }

    if (empty($errors)) {
        // Create connection
        $conn = new mysqli($servername, $username, $password, $dbname);

        // Check connection
        if ($conn->connect_error) {
            die("Connection failed: " . $conn->connect_error);
        }

        // Prepare and bind the INSERT statement for user registration
        $stmt_user = $conn->prepare("INSERT INTO users (name, email, password, plain_password) VALUES (?, ?, ?, ?)");

        // Check if the statement is prepared successfully
        if ($stmt_user) {
            // Hash the plain password
            $hashed_password = password_hash($plain_password, PASSWORD_DEFAULT);
            
            // Bind parameters to the prepared statement
            $stmt_user->bind_param("ssss", $name, $email, $hashed_password, $plain_password);

            // Execute the user registration statement
            if ($stmt_user->execute()) {
                // If registration is successful, set a success message in session
                $_SESSION['success_message'] = "User registration successful.";
                // Redirect to login page after successful registration
                header("Location: login.html");
                exit();
            } else {
                // If execution fails, add error message to errors array
                $errors[] = "ERROR: Unable to execute the user registration query.";
            }

            // Close the user registration statement
            $stmt_user->close();
        } else {
            // If preparation fails, add error message to errors array
            $errors[] = "ERROR: Unable to prepare the user registration statement.";
        }

        // Close connection
        $conn->close();
    }

    // If there are errors, display them
    if (!empty($errors)) {
        foreach ($errors as $error) {
            echo $error . "<br>";
        }
    }
} else {
    // If form submission method is not POST, display error message
    echo "ERROR: Form submission method is not POST.";
}
?>
