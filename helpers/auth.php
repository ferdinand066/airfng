<?php

if (!function_exists('check_valid_token')) {
	function check_valid_token($token){
        if (!isset($_SESSION['_token'])) return false;
        if ($_SESSION['_token'] !== $token) return false;
        return true;
	}
}

if (!function_exists('login_user')){
    function login_user(){
        return isset($_SESSION['id']);
    }
}

if (!function_exists('can_edit_data')){
    function can_edit_data($id){
        if (!isset($_SESSION['id'])) return false;
        return $_SESSION['id'] === $id || $_SESSION['role'] === 'admin';
    }
}

