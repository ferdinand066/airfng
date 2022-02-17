<?php
require "../../database/db.php";
require "../../helpers/function.php";
require "../../helpers/auth.php";

if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['signup'])) {
    //////
    /// QUESTION 5 SECTION 3B OF 3: Cross-Site Request Forgery (CSRF) - Check Token
    /// SECTION STARTS HERE
    //////

    if(!check_valid_token($_POST['_token'])){
        die("419 Session Expired");
        return;
    }
        
    //////
    /// SECTION ENDS HERE
    //////


    $firstName = htmlspecialchars($_POST['first_name']);
    $lastName = htmlspecialchars($_POST['last_name']);
    $password = $_POST['password'];
    $email = htmlspecialchars($_POST['email']);
    $phoneNumber = htmlspecialchars($_POST['phone_number']);
    $gender = htmlspecialchars($_POST['gender']);
    $tnc = $_POST['tnc'];

    if ($firstName === '' 
        || $lastName === '' || $password === '' 
        || $email === '' || $phoneNumber === ''
        || $gender === '' || $tnc === '') {
        $_SESSION['error'] = "All fields must be filled";
        header("location: ../../auth/signup");
    } else if (!in_array($gender, [1, 2])) {
        $_SESSION['error'] = "Gender must between Male and Female";
        header("location: ../../auth/signup");
    } else if ($tnc != 1) {
        $_SESSION['error'] = "You must agree out terms and condition";
        header("location: ../../auth/signup");
    } else if (!preg_match('/^\d{10,13}$/', $phoneNumber)){
        $_SESSION['error'] = "Phone number must between [0-9]";
        header("location: ../../auth/signup");
    } else {
        //////
        /// QUESTION 2 SECTION 2 OF 2: Hashing Password
        /// SECTION STARTS HERE
        //////
            $sql_check_email = "SELECT * from users WHERE email = ? or phone_number = ?";
            $statement = $conn->prepare($sql_check_email);
            $statement->bind_param("ss", $email, $phoneNumber);
            $statement->execute();

            $result = $statement->get_result();
            if ($result->num_rows > 0){
                $_SESSION['error'] = 'Email or Phone Number is already in use';
                header("location: ../../auth/signup");
                exit();
            } else {
                $password = password_hash($password, PASSWORD_BCRYPT);
            
                //////
                /// QUESTION 6 SECTION 2 OF 6: SQL Injection
                /// SECTION STARTS HERE
                //////
    
                $sql = "INSERT INTO users VALUES(uuid(), ?, ?, ?, ?, ?, ?, 'member', null, null, now())";
    
                $statement = $conn->prepare($sql);
                $statement->bind_param("ssssss", $firstName, $lastName, $password, $email, $phoneNumber, $gender);
                $statement->execute();
                //////
                /// SECTION ENDS HERE
                //////
                $_SESSION['success'] = 'Successfully registered new user';
                header("location: ../../auth/login");
                return;
            }


           

        //////
        /// SECTION ENDS HERE
        //////
        

    }

    header("location: ../../auth/signup");
    return;
}

$_SESSION['error'] = 'Invalid Request';
header("location: ../../auth/signup");
exit();