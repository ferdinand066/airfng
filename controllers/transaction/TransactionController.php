<?php
require "../../database/db.php";
require "../../helpers/function.php";
require "../../helpers/auth.php";

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['create'])){
    //////
    /// QUESTION 5 SECTION 3G OF 3: Cross-Site Request Forgery (CSRF) - Check Token
    /// SECTION STARTS HERE
    //////

    if(!check_valid_token($_POST['_token'])){
        die("419 Session Expired");
        return;
    }
        
    //////
    /// SECTION ENDS HERE
    //////

    //////
    /// QUESTION 3 SECTION 8 OF 12: Access Control
    /// Validate that only logged user can access this page
    /// SECTION STARTS HERE
    //////
    if(!isset($_SESSION['id'])){
        header('location: ../auth/login');
    }
    //////
    /// SECTION ENDS HERE
    //////

    $hostId = $_POST['host_id'];
    $checkIn = $_POST['check_in'];
    $checkOut = $_POST['check_out'];
    $guest = $_POST['guest'];

    //////
    /// QUESTION 6 SECTION 6 OF 6: SQL Injection
    /// SECTION STARTS HERE
    //////
    $sql_check_host = "SELECT * from hosts WHERE id = ?";
    $statement = $conn->prepare($sql_check_host);
    $statement->bind_param("s", $hostId);
    $statement->execute();

    $result = $statement->get_result();
    if ($result->num_rows !== 1){
        $_SESSION['error'] = "Invalid Review Request!";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }

    $currentDate = date("Y-m-d");

    if($checkIn === '' || $checkOut === '' 
        || $guest === ''){
        $_SESSION['error'] = "All fields must be filled";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    } else if ($currentDate >= $checkIn || $currentDate >= $checkOut || $checkIn > $checkOut){
        $_SESSION['error'] = "Invalid checkin or checkout date";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    } else if ($guest < 1){
        $_SESSION['error'] = "Guest minimum is 1";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    } else {
        $row = $result->fetch_assoc();
        $sql = "INSERT INTO transactions VALUES(uuid(), ?, ?, ?, ?, ?, ?, now())";
    
        $statement = $conn->prepare($sql);
        $statement->bind_param("ssissi", $row['id'], $_SESSION['id'], $row['price'], 
            date('Y-m-d', strtotime($checkIn)), date('Y-m-d', strtotime($checkOut)), $guest);
        $statement->execute();
        $_SESSION['success'] = 'Successfully add new transaction';
        header("location: ../../index");
        return;
    }
    //////
    /// SECTION ENDS HERE
    //////

    
}