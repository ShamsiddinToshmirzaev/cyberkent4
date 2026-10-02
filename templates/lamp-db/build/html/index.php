<?php
// PLACEHOLDER. Flag comes from a non-web-served file the entrypoint wrote.
$flag = trim(@file_get_contents('/var/www/flag.txt'));
// Example DB connection for your challenge to build on (creds from db.env):
//   $db = new mysqli(getenv('DB_HOST') ?: '127.0.0.1', getenv('DB_USER') ?: 'ctfuser',
//                    getenv('DB_PASS') ?: 'ctfpass', getenv('DB_NAME') ?: 'ctfdb');
?>
<!doctype html>
<title>__SLUG__</title>
<h1>Replace me</h1>
<p>Scaffold with an in-container MariaDB. Build your vuln; the intended solve must reveal the flag.</p>
<!-- PLACEHOLDER disclosure so the scaffold is solvable out of the box. DELETE this line.
FLAG: <?= htmlspecialchars($flag) ?> -->
