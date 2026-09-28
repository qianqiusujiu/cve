<?php
/*
 * GITSCRUM-01 PoC payload — HARMLESS MARKER ONLY.
 *
 * Uploaded via the unauthenticated POST /attachments/store endpoint.
 * Stored as public/attachments/<unix_timestamp>.php (client extension preserved
 * by AttachmentService::upload) and executed by requesting the stored URL.
 *
 * It only echoes a fixed marker plus md5("poc"); it contains no system(),
 * exec() or any other command/IO functionality.
 *
 * Expected output when executed:
 *   GITSCRUM-01-TEST-302fac1d6d73cf4fdf2c9919195df864
 */
echo "GITSCRUM-01-TEST-".md5("poc");
