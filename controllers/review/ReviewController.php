<?php
require "../../database/db.php";
require "../../helpers/function.php";
require "../../helpers/auth.php";

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['create'])){
    //////
    /// QUESTION 5 SECTION 3F OF 3: Cross-Site Request Forgery (CSRF) - Check Token
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
    /// QUESTION 3 SECTION 7 OF 12: Access Control
    /// Validate that only logged user can access this page
    /// SECTION STARTS HERE
    //////
    if(!isset($_SESSION['id'])){
        header('location: ../auth/login');
    }
    //////
    /// SECTION ENDS HERE
    //////

    //////
    /// QUESTION 4 SECTION 2 OF 3: Cross-Site Scripting (XSS)
    /// Sanitize input based on requirement
    /// SECTION STARTS HERE
    //////
    $hostId = $_POST['host_id'];
    $review = strip_tags($_POST['review'], "<br><br/><strong><em>");
    //////
    /// SECTION ENDS HERE
    //////
    
    //////
    /// QUESTION 6 SECTION 5 OF 6: SQL Injection
    /// SECTION STARTS HERE
    //////
    $sql_check_transaction = "SELECT * from transactions WHERE host_id = ? and user_id = ?";
    $statement = $conn->prepare($sql_check_transaction);
    $statement->bind_param("ss", $hostId, $_SESSION['id']);
    $statement->execute();

    $result = $statement->get_result();
    if ($result->num_rows < 1){
        $_SESSION['error'] = "Invalid Forum Request!";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }

    if($review === ''){
        $_SESSION['error'] = "All fields must be filled";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    } else {
        $row = $result->fetch_assoc();
        $hostId = $row['host_id'];

        $sql_check_forum = "SELECT * from reviews WHERE host_id = ? and user_id = ?";
        $statement = $conn->prepare($sql_check_forum);
        $statement->bind_param("ss", $hostId, $_SESSION['id']);
        $statement->execute();

        $result = $statement->get_result();

        if ($result->num_rows < 1){
            $sql = "INSERT INTO reviews VALUES(?, ?, ?, now())";
    
            $statement = $conn->prepare($sql);
            $statement->bind_param("sss", $row['host_id'], $_SESSION['id'], $review);
            $statement->execute();
            //////
            /// SECTION ENDS HERE
            //////
            $_SESSION['success'] = 'Successfully add new forum';
            header("location: ../../index");
            return;
        } else {
            $sql = "UPDATE reviews set review = ?, created_at = now() where host_id = ? and user_id = ?";
            $statement = $conn->prepare($sql);
            $statement->bind_param("sss", $review, $row['host_id'], $_SESSION['id']);
            $statement->execute();

            $_SESSION['success'] = 'Successfully update forum';
            header("location: ../../index");
            return;
        }      
    }
    //////
    /// SECTION ENDS HERE
    //////
    
}