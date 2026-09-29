<?php
/**
 * TU-01 verification harness (stage 3, ThinkUp expandurls plugin).
 *
 * Includes the REAL, unmodified ThinkUp files from the audited repo:
 *   - webapp/_lib/class.Utils.php                                  (Utils::getURLContents executed verbatim)
 *   - webapp/_lib/model/class.PostIterator.php                     (POP gadget: __destruct at line 124)
 *   - webapp/plugins/expandurls/model/class.FlickrAPIAccessor.php  (vulnerable unserialize at line 60)
 *
 * Only Logger is stubbed (a log sink; the real Logger only writes log files).
 * The HTTP fetch uses the OS resolver: api.flickr.com is pinned to 127.0.0.1 via
 * the Windows hosts file, simulating the on-path attacker's DNS/MITM position.
 *
 * Usage: php harness.php <flickr_api_key> <flickr_short_link>
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

$REPO = '</path/to/checked-out>/ThinkUp/webapp'; // point this at your git checkout of commit ac41d11 (see TARGET-SOURCE.txt)

class Logger {
    public static function getInstance() { return new self(); }
    public function __call($method, $args) {
        file_put_contents(__DIR__ . '/harness.log',
            date('H:i:s') . " [$method] " . (isset($args[0]) ? $args[0] : '') . "\n", FILE_APPEND);
    }
}

require $REPO . '/_lib/class.Utils.php';
require $REPO . '/_lib/model/class.PostIterator.php';
require $REPO . '/plugins/expandurls/model/class.FlickrAPIAccessor.php';

$key  = isset($argv[1]) ? $argv[1] : 'TU01TESTKEY';
$link = isset($argv[2]) ? $argv[2] : 'http://flic.kr/p/2m4yAbC';

$accessor = new FlickrAPIAccessor($key);
$p = new ReflectionProperty('FlickrAPIAccessor', 'api_url');
echo "[harness] real class.FlickrAPIAccessor.php loaded, unmodified\n";
echo "[harness] \$api_url value (line 29): " . var_export($p->getValue($accessor), true) . "\n";
echo "[harness] calling getFlickrPhotoSource('$link')\n";
$result = $accessor->getFlickrPhotoSource($link);
echo "[harness] returned: ";
var_export($result);
echo "\n[harness] end of script; destructors run at shutdown\n";
