<?php
declare(strict_types=1);

/**
 * Verify one AER-1 artifact offline.
 *
 * Usage:
 *   php bin/verify.php <receipt-or-workflow.json> [--expected-id <uuid>]
 *
 * Receipts get the full offline report: core check, version and
 * provenance binding, id binding state, and the per-anchor outcome
 * report. Workflow receipts get the Section 8.2 steps 3-4 check
 * (the network steps 1-2 stay the caller's job, as the draft
 * assigns them). Exit 0 when the artifact verifies, 1 otherwise.
 */

require __DIR__ . '/../src/bootstrap.php';

use Aer1Php\Aer1;
use Aer1Php\JObject;
use Aer1Php\JsonParser;

$file = null;
$expectedId = null;
for ($i = 1; $i < $argc; $i++) {
    if ($argv[$i] === '--expected-id' && $i + 1 < $argc) {
        $expectedId = $argv[++$i];
    } elseif ($file === null) {
        $file = $argv[$i];
    }
}
if ($file === null) {
    fwrite(STDERR, "usage: php bin/verify.php <file.json> [--expected-id <uuid>]\n");
    exit(2);
}
$text = file_get_contents($file);
if ($text === false) {
    fwrite(STDERR, "cannot read $file\n");
    exit(2);
}
$parser = new JsonParser();
try {
    $value = $parser->parse($text);
} catch (RuntimeException $e) {
    echo "verification failed: not JSON ({$e->getMessage()})\n";
    exit(1);
}

if ($value instanceof JObject
    && ($value->get('type') === 'verifiable-workflow-receipt'
        || $value->has('steps'))) {
    $fails = Aer1::verifyWorkflow($value);
    if ($fails) {
        echo "workflow verification failed:\n";
        foreach ($fails as $f) {
            echo " - $f\n";
        }
        exit(1);
    }
    echo "workflow verified (offline steps 3-4: shape, sequence, "
        . "no duplicate receipt_id, Merkle root recomputed)\n";
    exit(0);
}

if ($parser->firstDuplicate !== null) {
    echo "verification failed: duplicate member name: {$parser->firstDuplicate}\n";
    exit(1);
}
$report = Aer1::verifyReceipt($value, $expectedId);
if (!$report['verified']) {
    echo "verification failed:\n";
    foreach (array_merge($report['core_failures'], $report['binding_failures']) as $f) {
        echo " - $f\n";
    }
    exit(1);
}
echo 'verified' . ($report['legacy'] ? ' (legacy notice)' : '') . "\n";
echo "id: {$report['id_state']} ({$report['id_verdict']})\n";
$anchor = $report['anchor'];
echo 'anchor: ' . ($anchor['present'] ? $anchor['outcome'] : 'absent') . "\n";
exit(0);
