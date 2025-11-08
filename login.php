<?php
session_start();

define('DEV_MODE', true); // ⚙️ Passe à false en production !

$configuration = [
    "tokenURL" => "https://discord.com/api/oauth2/token",
    "apiURLBase" => "https://discord.com/api/users/@me",
    "OAUTH2_CLIENT_ID" => "XXXXXXXXXXXXXXXX",
    "OAUTH2_CLIENT_SECRET" => "XXXXXXXXXXXXXXXX",
    "RETURN_URL" => "https://example.com/login.php",
    "scope" => ["identify", "email"]
];


ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');

header("Content-Security-Policy: default-src 'self' https://discord.com");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");


if (DEV_MODE) {
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
    define('LOG_FILE', __DIR__ . '/debug.log');
} else {
    ini_set('display_errors', 0);
    error_reporting(0);
    define('LOG_FILE', __DIR__ . '/error.log');
}

function log_message($message) {
    if (!is_string($message)) $message = print_r($message, true);
    $timestamp = date("[Y-m-d H:i:s]");
    file_put_contents(LOG_FILE, "$timestamp $message\n", FILE_APPEND);
}

// -------------------
// Démarrage du processus OAuth2
// -------------------
if (isset($_GET["login"])) {
    $_SESSION["state"] = bin2hex(random_bytes(32));
    $_SESSION["state_expire"] = time() + 300;

    $params = [
        "client_id" => $configuration["OAUTH2_CLIENT_ID"],
        "redirect_uri" => $configuration["RETURN_URL"],
        "response_type" => "code",
        "scope" => implode(" ", $configuration["scope"]),
        "state" => $_SESSION["state"]
    ];

    log_message("Starting OAuth2 login. Generated state=" . $_SESSION["state"]);

    header("Location: https://discord.com/api/oauth2/authorize?" . http_build_query($params));
    exit;
}

if (isset($_GET["code"], $_GET["state"])) {
    log_message("Received OAuth2 callback with code and state.");

    if (
        empty($_SESSION["state"]) ||
        $_SESSION["state"] !== $_GET["state"] ||
        time() > ($_SESSION["state_expire"] ?? 0)
    ) {
        log_message("Invalid state detected. Possible CSRF or expired session.");
        session_unset();
        header("Location: ?login");
        exit;
    }

    unset($_SESSION["state"], $_SESSION["state_expire"]);

    // Échange code → token
    $tokenResponse = HTTP_POST($configuration["tokenURL"], [
        "grant_type" => "authorization_code",
        "client_id" => $configuration["OAUTH2_CLIENT_ID"],
        "client_secret" => $configuration["OAUTH2_CLIENT_SECRET"],
        "redirect_uri" => $configuration["RETURN_URL"],
        "code" => $_GET["code"]
    ]);

    log_message("Token response: " . $tokenResponse);

    $tokenData = json_decode($tokenResponse, true);
    if (!isset($tokenData["access_token"])) {
        log_message("Error: no access_token in token response.");
        die("Erreur lors de la récupération du token Discord.");
    }

    $accessToken = $tokenData["access_token"];

    // Récupération de l’utilisateur
    $userResponse = HTTP_POST($configuration["apiURLBase"], null, $accessToken);
    log_message("User response: " . $userResponse);

    $userData = json_decode($userResponse, true);
    if (!isset($userData["id"])) {
        log_message("Erreur: réponse utilisateur invalide.");
        die("Impossible de récupérer les informations utilisateur Discord.");
    }

    echo "<h3>Bienvenue, " . htmlspecialchars($userData["username"]) . "!</h3>";
    echo "<p>ID Discord : " . htmlspecialchars($userData["id"]) . "</p>";
    echo "<p>Email : " . htmlspecialchars($userData["email"] ?? "Non disponible") . "</p>";

    $_SESSION["discord_user"] = $userData;
    log_message("Connexion réussie pour l’utilisateur : " . $userData["username"]);
    exit;
}

header("Location: ?login");
exit;

function HTTP_POST($url, $post = null, $token = null)
{
    $ch = curl_init($url);

    if (!empty($post)) {
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    }

    $headers = ["Accept: application/json"];
    if (!empty($token)) {
        $headers[] = "Authorization: Bearer $token";
    }

    curl_setopt_array($ch, [
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_TIMEOUT => 10,
    ]);

    $response = curl_exec($ch);

    if (curl_errno($ch)) {
        log_message("cURL error: " . curl_error($ch));
        curl_close($ch);
        return json_encode(["error" => "Request failed"]);
    }

    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($status < 200 || $status >= 300) {
        log_message("HTTP $status returned for $url");
        return json_encode(["error" => "Invalid HTTP response"]);
    }

    return $response;
}
?>
