<?php

// DB creds come from db.env. envv() keeps an intentionally-EMPTY password
// (getenv returns "" which `?:` would wrongly discard).
function envv($k, $d) { $v = getenv($k); return $v !== false ? $v : $d; }

$message = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = $_POST["username"] ?? "";
    $password = $_POST["password"] ?? "";

    // WAF: UNION SELECT bloklangan
    if (preg_match('/union\s+select/i', $username . $password)) {
        $message = "<span class='err'>Kiritilgan ma'lumot xavfli so'zlar o'z ichiga oladi!</span>";
    } else {
        $db = new mysqli(
            envv("DB_HOST", "127.0.0.1"),
            envv("DB_USER", "root"),
            envv("DB_PASS", ""),
            envv("DB_NAME", "ctf_db")
        );

        if (!$db->connect_error) {
            $sql = "SELECT id, username, secret FROM users
                    WHERE username = '$username' AND password = '$password'
                    LIMIT 1";

            $result = $db->query($sql);

            if ($result && $result->num_rows > 0) {
                $row = $result->fetch_assoc();
                $message = "<span class='ok'>Xush kelibsiz, <b>"
                         . htmlspecialchars($row["username"])
                         . "</b>!</span>";
            } elseif ($result === false) {
                $message = "<span class='err'>SQL xatolik: "
                         . htmlspecialchars($db->error)
                         . "</span>";
            } else {
                $message = "<span class='err'>Login yoki parol noto'g'ri!</span>";
            }
            $db->close();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="uz">
<head>
<meta charset="UTF-8">
<title>Login</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0d1117;
    font-family: 'Courier New', monospace;
    color: #c9d1d9;
}
.card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 40px;
    width: 360px;
}
h2 { color: #58a6ff; margin-bottom: 24px; font-size: 20px; }
label { display: block; font-size: 12px; color: #8b949e; margin-bottom: 6px; }
input {
    width: 100%;
    padding: 10px 12px;
    margin-bottom: 18px;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-family: inherit;
    font-size: 14px;
    outline: none;
}
input:focus { border-color: #58a6ff; }
button {
    width: 100%;
    padding: 11px;
    background: #238636;
    border: none;
    border-radius: 6px;
    color: #fff;
    font-size: 14px;
    font-weight: bold;
    cursor: pointer;
}
button:hover { background: #2ea043; }
.msg { margin-top: 18px; font-size: 13px; line-height: 1.6; word-break: break-all; }
.ok  { color: #3fb950; }
.err { color: #f85149; }
</style>
</head>
<body>
<div class="card">
    <h2>// SYSTEM LOGIN</h2>
    <form method="POST">
        <label>USERNAME</label>
        <input type="text" name="username" autocomplete="off" placeholder="username">
        <label>PASSWORD</label>
        <input type="password" name="password" placeholder="••••••••">
        <button type="submit">AUTHENTICATE</button>
    </form>
    <?php if ($message): ?>
        <div class="msg"><?= $message ?></div>
    <?php endif; ?>
</div>
</body>
</html>
