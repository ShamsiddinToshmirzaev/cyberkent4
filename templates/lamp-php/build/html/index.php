<?php
// PLACEHOLDER challenge. The flag is read from a non-web-served file the entrypoint wrote.
$flag = trim(@file_get_contents('/var/www/flag.txt'));
?>
<!doctype html>
<title>__SLUG__</title>
<h1>Replace me</h1>
<p>This is a scaffold. Build your PHP/Apache vulnerability; the intended solve must reveal the flag.</p>
<!-- PLACEHOLDER disclosure so the scaffold is solvable out of the box. DELETE this line.
FLAG: <?= htmlspecialchars($flag) ?> -->
