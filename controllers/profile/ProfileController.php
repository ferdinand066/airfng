<?php
require "../../database/db.php";
require "../../helpers/function.php";
require "../../helpers/auth.php";

if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update'])) {

    //////
    /// QUESTION 5 SECTION 3D OF 3: Cross-Site Request Forgery (CSRF) - Check Token
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
    /// QUESTION 3 SECTION 9A OF 12: Access Control
    /// Validate that only logged user can access this page
    /// SECTION STARTS HERE
    //////
    if (!can_edit_data($_POST['id'])){
        $_SESSION['error'] = "Invalid Request";
        header("location: ../../");
        return;
    }
    //////
    /// SECTION ENDS HERE
    //////

    //////
    /// QUESTION 4 SECTION 2 OF 3: Cross-Site Scripting (XSS)
    /// Sanitize input based on requirement
    /// SECTION STARTS HERE
    //////
    $firstName = htmlspecialchars($_POST['first_name']);
    $lastName = htmlspecialchars($_POST['last_name']);
    $gender = htmlspecialchars($_POST['gender']);
    $about = strip_tags($_POST['about'], "<br><br/><strong><em>");
    $imgStatus = htmlspecialchars($_POST['img_status']);
    //////
    /// SECTION ENDS HERE
    //////

    if (!check_empty_data([$firstName, $lastName, $gender, $imgStatus])){
        $_SESSION['error'] = "All fields must be filled";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }

    if (!in_array($gender, [1, 2])) {
        $_SESSION['error'] = "Gender must between Male and Female";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }

    if (isset($_POST['role']) && !in_array($_POST['role'], ["member", "admin"])) {
        $_SESSION['error'] = "Gender must between Member and Admin";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }

    if (isset($_POST['role']) && $_SESSION['role'] !== 'admin'){
        $_SESSION['error'] = "Invalid Request";
        header("location: ../../");
        return;
    }

    if ($_FILES['file_upload']['size'] > 1024 * 1024 * 10){
        $_SESSION['error'] = "File is too big";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }

    $sql_check_user = "SELECT * from users WHERE id = ?";
    $statement = $conn->prepare($sql_check_user);
    $statement->bind_param("s", $_POST['id']);
    $statement->execute();

    $result = $statement->get_result();
    $row = $result->fetch_assoc();

    $file_name = null;
    $dir = "../../assets/images/profile/";

    if ($imgStatus == 1){
        if ($row['photo'] != null && file_exists($dir . $row['photo'])) {
            unlink($dir . $row['photo']);
        }
        
        $file_name = $row['id'] . '_' . uniqid("") . '.' . 
            strtolower(pathinfo($_FILES["file_upload"]["name"],PATHINFO_EXTENSION));
    
        $target_file = $dir . $file_name;
    
        move_uploaded_file($_FILES["file_upload"]["tmp_name"], $target_file);
    } else if ($imgStatus == 2) {
        if ($row['photo'] != null && file_exists($dir . $row['photo'])) {
            unlink($dir . $row['photo']);
        }
    } else if ($imgStatus != 0){
        $_SESSION['error'] = "Invalid Request";
        header("location: ../../");
        return;
    }

    $sql = "";
    $statement = "";

    if ($imgStatus == 0){
        $sql = "UPDATE users set first_name = ?, last_name = ?, gender = ?, about = ?". ((isset($_POST['role'])) ? ", role = ?" : "") . " where id = ?";
        $statement = $conn->prepare($sql);
        if (isset($_POST['role'])){
            $statement->bind_param("ssisss", $firstName, $lastName, $gender, $about, $_POST['role'], $_POST['id']);
        } else {
            $statement->bind_param("ssiss", $firstName, $lastName, $gender, $about, $_POST['id']);
        }
    } else {
        $sql = "UPDATE users set first_name = ?, last_name = ?, gender = ?, about = ?, photo = ?". ((isset($_POST['role'])) ? ", role = ?" : "") . " where id = ?";
        $statement = $conn->prepare($sql);
        if (isset($_POST['role'])){
            $statement->bind_param("ssissss", $firstName, $lastName, $gender, $about, $file_name, $_POST['role'], $_POST['id']);
        } else {
            $statement->bind_param("ssisss", $firstName, $lastName, $gender, $about, $file_name, $_POST['id']);
        }
    }

    $statement->execute();

    if ($_SESSION['id'] == $_POST['id']){
        $_SESSION['first_name'] = $firstName;
        $_SESSION['last_name'] = $lastName;
        $_SESSION['role'] = isset($_POST['role']) ? $_POST['role'] : "member";
        $_SESSION['photo'] = $file_name;
    }

    $_SESSION['success'] = 'Successfully update user';
    header("location: ../../index");
    return;


}

if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete'])){
    //////
    /// QUESTION 5 SECTION 3E OF 3: Cross-Site Request Forgery (CSRF) - Check Token
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
    /// QUESTION 3 SECTION 9B OF 12: Access Control
    /// Validate that only logged user can access this page
    /// SECTION STARTS HERE
    //////
    if ($_SESSION['role'] != 'admin'){
        $_SESSION['error'] = "Invalid Request";
        header("location: ../../");
        return;
    }

    //////
    /// SECTION ENDS HERE
    //////


    $id = $_POST['id'];
    if (!check_empty_data([$id])){
        $_SESSION['error'] = "All fields must be filled";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }
    //////
    /// QUESTION 6 SECTION 4 OF 6: SQL Injection
    /// SECTION STARTS HERE
    //////
    $sql_check_user = "SELECT u.*, d.id as deleted_id from users u left join deleteditems d on u.id = d.data_id WHERE u.id = ?";
    $statement = $conn->prepare($sql_check_user);
    $statement->bind_param("s", $id);
    $statement->execute();

    $result = $statement->get_result();
    $row = $result->fetch_assoc();

    if ($result->num_rows != 1){
        $_SESSION['error'] = "Invalid user id";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }

    if ($row['deleted_id'] == null){
        $sql = "INSERT INTO deleteditems VALUES(uuid(), ?, ?, now())";
    
        $statement = $conn->prepare($sql);
        $statement->bind_param("ss", $id, $_SESSION['id']);
        $statement->execute();

        $_SESSION['success'] = 'Successfully blacklisted the user';
        header("location: ../../");
        return;
    } 

    $sql = "delete from deleteditems where data_id = ?";
    
    $statement = $conn->prepare($sql);
    $statement->bind_param("s", $id);
    $statement->execute();

    $_SESSION['success'] = 'Successfully removed the blacklist for the user';
    header("location: ../../");
    return;
    //////
    /// SECTION ENDS HERE
    //////
}

header("location: " . $_SERVER['HTTP_REFERER']);
return;