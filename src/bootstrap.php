<?php
declare(strict_types=1);

// Zero-dependency bootstrap: the runner needs nothing beyond a PHP
// 8.1+ CLI, so a clone runs with no install step at all. (composer.json
// ships for package consumers; nothing here requires it.)
require __DIR__ . '/Json.php';
require __DIR__ . '/Aer1.php';
