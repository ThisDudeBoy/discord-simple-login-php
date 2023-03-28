<?php

session_start();

// Configuration
$config = [
    "tokenURL" => "https://discord.com/api/oauth2/token",
    "apiURLBase" => "https://discord.com/api/users/@me",
    "clientID" => "YOUR_CLIENT_ID",
    "clientSecret" => "YOUR_CLIENT_SECRET",
    "redirectURI" => "https://example.com/login.php",
    "scopes" => ["identify", "email"]
];

// Login
if (isset($_GET["login"])) {
    $_SESSION["state"] = bin2hex(random_bytes(32));

    $params = [
        "client_id" => $config["clientID"],
        "redirect_uri" => $config["redirectURI"],
        "response_type" => "code",
        "scope" => implode(" ", $config["scopes"]),
        "state" => $_SESSION["state"]
    ];

    header("Location: https://discord.com/api/oauth2/authorize?" . http_build_query($params));
    die();
}

// Check if state is set
if (!isset($_GET["state"]) || empty($_SESSION["state"]) || $_SESSION["state"] !== $_GET["state"]) {
    header("Location: ?login");
    die();
}

// Unset state
unset($_SESSION["state"]);

// Get access token
$token = getToken($_GET["code"]);
if (!$token) {
    header("Location: ?login");
    die();
}

// Get user information
$user = getUser($token);
if (!$user) {
    header("Location: ?login");
    die();
}

// Display user information
foreach ($user as $key => $value) {
    echo sprintf("<p><b>%s</b>: %s</p>", $key, htmlspecialchars($value));
}

function getToken($code) {
    global $config;

    $params = [
        "grant_type" => "authorization_code",
        "client_id" => $config["clientID"],
        "client_secret" => $config["clientSecret"],
        "redirect_uri" => $config["redirectURI"],
        "code" => $code
    ];

    $response = httpPost($config["tokenURL"], $params);
    if (!$response) {
        return false;
    }

    $json = json_decode($response, true);
    if (!isset($json["access_token"])) {
        return false;
    }

    return $json["access_token"];
}

function getUser($token) {
    global $config;

    $response = httpPost($config["apiURLBase"], null, [
        "Authorization: Bearer {$token}",
        "Accept: application/json"
    ]);
    if (!$response) {
        return false;
    }

    $json = json_decode($response, true);
    if (!$json) {
        return false;
    }

    return $json;
}

function httpPost($url, $params = null, $headers = null) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    if ($params) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    }

    if ($headers) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }

    $response = curl_exec($ch);
    curl_close($ch);

    return $response;
}
