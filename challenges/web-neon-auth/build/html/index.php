<?php

$db = new mysqli(
    getenv("DB_HOST") ?: "127.0.0.1",
    getenv("DB_USER") ?: "ctfuser",
    getenv("DB_PASS") ?: "ctfpass",
    getenv("DB_NAME") ?: "ctfdb"
);

if ($db->connect_error) {
    die("Database connection failed");
}

$message = "";
$success = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $username = $_POST["username"] ?? "";
    $password = $_POST["password"] ?? "";

    /*
     * INTENTIONAL SQL INJECTION
     * CTF challenge vulnerability.
     */
    $sql = "
        SELECT id, username
        FROM users
        WHERE username = '$username'
        AND password = '$password'
        LIMIT 1
    ";

    $result = $db->query($sql);

    if ($result && $result->num_rows > 0) {

        $user = $result->fetch_assoc();

        $success = true;

        $message =
            "ACCESS GRANTED // WELCOME "
            . htmlspecialchars($user["username"]);

    } else {

        $message = "ACCESS DENIED // INVALID CREDENTIALS";

    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>NEON CORE // AUTH</title>

<style>

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {

    min-height: 100vh;

    display: flex;

    align-items: center;
    justify-content: center;

    background:
        radial-gradient(
            circle at 50% 50%,
            rgba(255, 0, 170, .08),
            transparent 35%
        ),
        linear-gradient(
            135deg,
            #050014,
            #09001f,
            #020008
        );

    color: #f5f5f5;

    font-family:
        "Courier New",
        monospace;

    overflow: hidden;

}


/* GRID */

body::before {

    content: "";

    position: fixed;

    inset: 0;

    pointer-events: none;

    opacity: .18;

    background-image:

        linear-gradient(
            rgba(255, 0, 170, .15) 1px,
            transparent 1px
        ),

        linear-gradient(
            90deg,
            rgba(0, 255, 255, .12) 1px,
            transparent 1px
        );

    background-size:
        45px 45px;

}


/* CARD */

.card {

    position: relative;

    width: 430px;

    padding: 45px;

    background:
        rgba(7, 3, 20, .94);

    border:
        1px solid #ff00aa;

    box-shadow:

        0 0 20px
        rgba(255, 0, 170, .35),

        inset 0 0 30px
        rgba(255, 0, 170, .04);

}


/* TOP LINE */

.card::before {

    content: "";

    position: absolute;

    top: -1px;
    left: 25px;
    right: 25px;

    height: 2px;

    background: #00ffff;

    box-shadow:
        0 0 15px #00ffff;

}


/* HEADER */

.logo {

    color: #00ffff;

    font-size: 13px;

    letter-spacing: 6px;

    margin-bottom: 12px;

    text-shadow:
        0 0 12px #00ffff;

}

h1 {

    color: #ff00aa;

    font-size: 34px;

    letter-spacing: 3px;

    text-shadow:
        0 0 15px #ff00aa;

    margin-bottom: 10px;

}

.subtitle {

    color: #777;

    font-size: 11px;

    line-height: 1.7;

    margin-bottom: 32px;

}


/* FORM */

label {

    display: block;

    color: #00ffff;

    font-size: 11px;

    letter-spacing: 2px;

    margin-bottom: 8px;

}

input {

    width: 100%;

    padding: 14px;

    margin-bottom: 22px;

    background: #03000b;

    color: #fff;

    border:
        1px solid #442044;

    outline: none;

    font-family:
        "Courier New",
        monospace;

    transition: .2s;

}

input:focus {

    border-color: #00ffff;

    box-shadow:
        0 0 12px
        rgba(0, 255, 255, .3);

}


button {

    width: 100%;

    padding: 15px;

    background: transparent;

    color: #00ffff;

    border:
        1px solid #00ffff;

    font-family:
        "Courier New",
        monospace;

    font-weight: bold;

    letter-spacing: 3px;

    cursor: pointer;

    transition: .2s;

}

button:hover {

    color: #050014;

    background: #00ffff;

    box-shadow:
        0 0 25px
        rgba(0, 255, 255, .6);

}


/* MESSAGE */

.message {

    margin-top: 25px;

    padding: 13px;

    font-size: 11px;

    line-height: 1.5;

    border: 1px solid #442044;

}

.success {

    color: #00ff88;

    border-color: #00ff88;

    box-shadow:
        0 0 12px
        rgba(0, 255, 136, .15);

}

.error {

    color: #ff3366;

    border-color: #ff3366;

}


/* FOOTER */

.footer {

    margin-top: 28px;

    display: flex;

    justify-content: space-between;

    color: #444;

    font-size: 9px;

    letter-spacing: 1px;

}

.online {

    color: #00ff88;

}

</style>

</head>


<body>


<div class="card">

    <div class="logo">
        NEON//CORE
    </div>

    <h1>
        ACCESS TERMINAL
    </h1>

    <div class="subtitle">
        SECURE CYBERNETIC AUTHENTICATION NODE<br>
        AUTHORIZED PERSONNEL ONLY
    </div>


    <form method="POST">

        <label>
            USERNAME
        </label>

        <input
            type="text"
            name="username"
            autocomplete="off"
            placeholder="ENTER USERNAME"
            required
        >


        <label>
            PASSWORD
        </label>

        <input
            type="password"
            name="password"
            placeholder="ENTER PASSWORD"
            required
        >


        <button type="submit">
            [ AUTHENTICATE ]
        </button>

    </form>


    <?php if ($message): ?>

        <div
            class="message <?= $success
                ? 'success'
                : 'error' ?>"
        >
            <?= $message ?>
        </div>

    <?php endif; ?>


    <div class="footer">

        <span>
            NODE::NC-01
        </span>

        <span class="online">
            ● SYSTEM ONLINE
        </span>

    </div>

</div>


</body>

</html>
