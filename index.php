<?php
/*
 * Whois in PHP
 * By Flashwave <http://flash.moe>
 * Released under the MIT-License
 */

// Set error reporting: -1 for debugging, 0 for production
error_reporting(0);

// Set character encoding
mb_internal_encoding('UTF-8');

// Include Whois library
require_once 'whois.php';

// Set servers file
Whois::setServers('servers.json');

// If the domain request is set execute the whois query
if(isset($_REQUEST['domain']))
    $response = Whois::query($_REQUEST['domain']);
else
    $response = 'Awaiting Input';

// Get the template file
$template = file_get_contents('whois.html');

// Replace the {{ RESPONSE }} tag with either the awaiting input message or the whois results
$template = str_replace('{{ RESPONSE }}', $response, $template);

// Print the template
print $template;
