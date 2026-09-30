<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
session_start();

// DB name from db.env; connection host is the in-container MariaDB over TCP.
function envv($k, $d) { $v = getenv($k); return $v !== false ? $v : $d; }
$DB_NAME = envv("DB_NAME", "ctf_db");

$error = "";
$result_output = "";
$query_executed = "";

// 1. Chiqish (logout)
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// 2. Login formasi yuborilganda
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['login_action'])) {
    $db_user = $_POST['db_user'];
    $db_pass = $_POST['db_pass'];
    $db_name = $DB_NAME;

    $test_conn = @new mysqli("127.0.0.1", $db_user, $db_pass, $db_name);

    if ($test_conn->connect_error) {
        $error = "MySQL xatoligi: Noto'g'ri login yoki parol!";
    } else {
        $_SESSION['db_user'] = $db_user;
        $_SESSION['db_pass'] = $db_pass;
        $test_conn->close();
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}

// 3. SQL buyruq yuborilganda
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['sql_action'])) {
    $user_query = trim($_POST['sql_query']);
    $query_executed = $user_query;

    $conn = @new mysqli("127.0.0.1", $_SESSION['db_user'], $_SESSION['db_pass'], $DB_NAME);

    if ($conn->connect_error) {
        $result_output = "<p style='color:red;'>Ulanish uzildi: " . $conn->connect_error . "</p>";
    } else {
        $query_result = $conn->query($user_query);

        if ($query_result === TRUE) {
            $result_output = "<p style='color:green;'>So'rov muvaffaqiyatli bajarildi!</p>";
        } elseif ($query_result) {
            if ($query_result->num_rows > 0) {
                $result_output = "<table border='1' cellpadding='8' cellspacing='0' style='border-collapse:collapse; width:100%; background:#fff;'>";
                $is_header = true;

                while ($row = $query_result->fetch_assoc()) {
                    if ($is_header) {
                        $result_output .= "<tr style='background:#f2f2f2;'>";
                        foreach (array_keys($row) as $col) {
                            $result_output .= "<th>" . htmlspecialchars($col) . "</th>";
                        }
                        $result_output .= "</tr>";
                        $is_header = false;
                    }
                    $result_output .= "<tr>";
                    foreach ($row as $val) {
                        $result_output .= "<td>" . htmlspecialchars($val) . "</td>";
                    }
                    $result_output .= "</tr>";
                }
                $result_output .= "</table>";
            } else {
                $result_output = "<p style='color:orange;'>So'rov natijasi bo'sh (0 ta qator topildi).</p>";
            }
        } else {
            $result_output = "<p style='color:red;'>SQL Xatolik: " . htmlspecialchars($conn->error) . "</p>";
        }
        $conn->close();
    }
}
?>

<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <title>CTF - MySQL SQL Console</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 30px; background: #f4f7f6; }
        .box { background: white; padding: 25px; border-radius: 8px; box-shadow: 0px 0px 10px rgba(0,0,0,0.1); max-width: 700px; margin: auto; }
        input, textarea { width: 100%; padding: 10px; margin: 8px 0 15px 0; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; font-family: monospace; }
        button { background: #007bff; color: white; padding: 10px 15px; border: none; cursor: pointer; border-radius: 4px; font-weight: bold; }
        button:hover { background: #0056b3; }
        .logout-btn { background: #dc3545; float: right; }
        .logout-btn:hover { background: #c82333; }
        .output-box { margin-top: 20px; overflow-x: auto; }
    </style>
</head>
<body>

<div class="box">
    <?php if (!isset($_SESSION['db_user'])): ?>
        <h2>MySQL Tizimiga Kirish</h2>
        <p>CTF topshirig'ini bajarish uchun MySQL foydalanuvchi ma'lumotlarini kiriting.</p>

        <?php if (!empty($error)): ?>
            <p style="color: red;"><?php echo $error; ?></p>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="hidden" name="login_action" value="1">

            <label><b>MySQL Username:</b></label>
            <input type="text" name="db_user" placeholder="Masalan: root" required>

            <label><b>MySQL Password:</b></label>
            <input type="password" name="db_pass" placeholder="Parol (bo'sh bo'lishi ham mumkin)">

            <button type="submit">Ulanish va Konsolni Ochish</button>
        </form>

    <?php else: ?>
        <a href="?logout=1"><button class="logout-btn">Chiqish</button></a>
        <h2>MySQL SQL Console</h2>
        <p>Xush kelibsiz, <b><?php echo htmlspecialchars($_SESSION['db_user']); ?></b>! Istalgan MySQL buyrug'ini kiriting:</p>

        <form method="POST" action="">
            <input type="hidden" name="sql_action" value="1">

            <label><b>SQL Query:</b></label>
            <textarea name="sql_query" rows="4" ><?php echo htmlspecialchars($query_executed); ?></textarea>

            <button type="submit">Buyruqni Bajarish</button>
        </form>

        <div class="output-box">
            <?php if (!empty($result_output)): ?>
                <h3>Natija:</h3>
                <?php echo $result_output; ?>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>

</body>
</html>
