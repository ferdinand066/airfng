<?php
//////
/// QUESTION 5 Cross-Site Request Forgery (CSRF) - SECTION 1 OF 3
/// Set Token Session
/// SECTION STARTS HERE
//////
function csrf_token(){
    $token = '';

    if (!isset($_SESSION['_token'])){
        $_SESSION['_token'] = bin2hex(random_bytes(32));
    }

    $token = $_SESSION['_token'];
    return $token;
}

function csrf_field(){
    $token = csrf_token();
    echo "<input type='hidden' name='_token' value='$token'>";
}

//////
/// SECTION ENDS HERE
//////