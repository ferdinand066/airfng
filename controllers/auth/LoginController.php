<?php
require "../../database/db.php";
require "../../helpers/function.php";
require "../../helpers/auth.php";

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['login'])){
    //////
    /// QUESTION 5 SECTION 3A OF 3: Cross-Site Request Forgery (CSRF) - Check Token
    /// SECTION STARTS HERE
    //////

    if(!check_valid_token($_POST['_token'])){
        die("419 Session Expired");
        return;
    }
        
    //////
    /// SECTION ENDS HERE
    //////

    $email = $_POST['email'];
    $password = $_POST['password'];

    if ($password === '' || $email === '') {
        $_SESSION['error'] = "All fields must be filled";
        header("location: ../../auth/login");
        return;
    } else {
        //////
        /// QUESTION 2 SECTION 1 OF 2: Hashing Password
        /// SECTION STARTS HERE
        //////

            //////
            /// QUESTION 6 SECTION 1 OF 6: SQL Injection
            /// SECTION STARTS HERE
            //////
            
                $sql = "SELECT u.*, d.id as deleted_id FROM users u left join deleteditems d
                on d.data_id = u.id
                WHERE email = ?";
                $statement = $conn->prepare($sql);
                $statement->bind_param("s", $email);
                $statement->execute();
                $result = $statement->get_result();
            
            //////
            /// SECTION ENDS HERE
            //////

        if($result->num_rows > 0) {
            //////
            /// QUESTION 1 SECTION 1 OF 2: Generate New Session
            /// SECTION STARTS HERE
            //////
                session_regenerate_id(true);
            //////
            /// SECTION ENDS HERE
            //////

            $row = $result->fetch_assoc();

            if ($row['deleted_id'] !== null){
                $_SESSION['error'] = 'This account has been blocked from this site by admin!';

                header("location: ../../");
                return;
            }

            if (password_verify($password, $row['password'])){
                $_SESSION['id'] = $row['id'];
                $_SESSION['email'] = $row['email'];
                $_SESSION['first_name'] = $row['first_name'];
                $_SESSION['last_name'] = $row['last_name'];
                $_SESSION['role'] = $row['role'];
                $_SESSION['photo'] = $row['photo'];
        
                if($_POST['remember']) {
                    //////
                    /// QUESTION 8 SECTION 1 OF 1: HTTP Header
                    /// SECTION STARTS HERE
                    //////
        
                    setcookie("email", $email, time() + (3 * 3600 * 24), "/", null, false, true);
                    setcookie("password", $password, time() + (3 * 3600 * 24), "/", null, false, true);
        
                    //////
                    /// SECTION ENDS HERE
                    //////
                }

                header("location: ../../");
                return;
            }

            else {
                $_SESSION['error'] = 'Wrong password';

                header("location: ../../auth/login");
                return;
            }
            
            
        } 

        //////
        /// SECTION ENDS HERE
        //////
        $_SESSION['error'] = 'Invalid email';
        header("location: ../../auth/login");
        return;

    }
    //////
    /// SECTION ENDS HERE
    //////
}

header("location: ../auth/login");
return;