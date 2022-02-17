<?php
require "../../database/db.php";
require "../../helpers/function.php";
require "../../helpers/auth.php";

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['create'])){
    //////
    /// QUESTION 5 SECTION 3C OF 3: Cross-Site Request Forgery (CSRF) - Check Token
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
    /// QUESTION 3 SECTION 6 OF 12: Access Control
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
    /// QUESTION 4 SECTION 1 OF 3: Cross-Site Scripting (XSS)
    /// Sanitize input based on requirement
    /// SECTION STARTS HERE
    //////
    $name = htmlspecialchars($_POST['name']);
    $price = htmlspecialchars($_POST['price']);
    $city = htmlspecialchars($_POST['city']);
    $street_address = htmlspecialchars($_POST['street_address']);
    $rules = strip_tags($_POST['rules'], "<br><br/><strong><em>");
    $room = $_POST['room'];
    $room_quantity = $_POST['room_quantity'];
    //////
    /// SECTION ENDS HERE
    //////

    if($name === '' || $price === '' 
        || $city === '' || $street_address === ''
        || $rules === '' || in_array('', $room) || in_array('', $room_quantity)){
        
        $_SESSION['error'] = "All fields must be filled";
        header("location: ../../host/create");
        return;
    } else if (count($room) !== count($room_quantity)){
        $_SESSION['error'] = "Invalid input";
        header("location: ../../host/create");
        return;
    } else if ($_FILES['file_upload']['size'] > 1024 * 1024 * 10){
        $_SESSION['error'] = "File is too big";
        header("location: ../../host/create");
        return;
    } else if (!ctype_digit($price)){
        $_SESSION['error'] = "Price must be in integer format";
        header("location: ../../host/create");
        return;
    }

    foreach($room_quantity as $q){
        if (!ctype_digit($q) || $q < 1){
            $_SESSION['error'] = "Invalid room quantity input";
            header("location: ../../host/create");
            return;
        }
    }
    //////
    /// QUESTION 6 SECTION 3 OF 6: SQL Injection
    /// SECTION STARTS HERE
    //////
    $sql_check_city = "SELECT * from cities WHERE id = ?";
    $statement = $conn->prepare($sql_check_city);
    $statement->bind_param("s", $city);
    $statement->execute();

    $result = $statement->get_result();
    if ($result->num_rows > 0){
        $dir = "../../assets/images/host/";
        $file_name = $_SESSION['id'] . '_' . uniqid("") . '.' . 
            strtolower(pathinfo($_FILES["file_upload"]["name"],PATHINFO_EXTENSION));

        $target_file = $dir . $file_name;

        move_uploaded_file($_FILES["file_upload"]["tmp_name"], $target_file);

        $result = [];
        foreach($room as $key => $value){
            $data['room_name'] = $value;
            $data['quantity'] = $room_quantity[$key];
            array_push($result, $data);
        }

        $sql = "INSERT INTO hosts VALUES(uuid(), ?, ?, ?, ?, ?, ?, ?, ?, now())";
    
        $statement = $conn->prepare($sql);
        $statement->bind_param("ssisssss", $_SESSION['id'] ,$name, $price, $file_name, $city, $street_address, 
            $rules, json_encode($result));
        $statement->execute();

        $_SESSION['success'] = 'Successfully host a new home!';
        header("location: ../../index");
        return;
    } else {
        $_SESSION['error'] = "Invalid city";
        header("location: ../../host/create");
        return;
    }
    //////
    /// SECTION ENDS HERE
    //////

    
}