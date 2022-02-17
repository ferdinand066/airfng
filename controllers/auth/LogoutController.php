<?php
session_start();
session_unset();
session_destroy();

//////
/// QUESTION 1 SECTION 2 OF 2: Generate New Session
/// SECTION STARTS HERE
//////
    session_regenerate_id(true);
//////
/// SECTION ENDS HERE
//////

setcookie("email", "", time() - 10, "/", null);
setcookie("password", "", time() - 10, "/", null);
header('location: ../../index');