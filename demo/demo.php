<?php
declare(strict_types=1);

/**
 * Ninety-second demo, in terminal form.
 *
 * An agent says a job is done. Before anyone believes it, the
 * job's AER-1 receipt gets checked:
 *
 *   1. the receipt from the corpus verifies;
 *   2. the same receipt with one changed hex digit in its output
 *      hash does not (the saved result no longer matches what the
 *      receipt commits to);
 *   3. a workflow receipt over three steps verifies, and the
 *      same workflow with a step's receipt_id repeated does not
 *      (the MM-1 rule: one receipt cannot stand for two steps).
 *
 * Run: php demo/demo.php
 */

require __DIR__ . '/../src/bootstrap.php';

use Aer1Php\Aer1;
use Aer1Php\JObject;
use Aer1Php\JsonParser;

$corpus = __DIR__ . '/../corpus/base/test-vectors';
$receipt = (new JsonParser())->parse(
    file_get_contents($corpus . '/valid/receipt-01.json')
);

echo "1. The receipt as saved\n";
$report = Aer1::verifyReceipt($receipt);
echo '   verdict: ' . ($report['verified'] ? 'verified' : 'verification failed') . "\n";
echo "   id: {$report['id_state']} ({$report['id_verdict']})\n";
echo '   anchor: ' . ($report['anchor']['present']
    ? $report['anchor']['outcome'] : 'absent') . "\n\n";

// One hex digit changed in the committed output hash.
$tampered = new JObject();
foreach ($receipt->pairs as [$k, $v]) {
    if ($k === 'output_hash') {
        $v = 'sha256:' . str_repeat('0', 63) . '1';
        if ($v === $receipt->get('output_hash')) {
            $v = 'sha256:' . str_repeat('0', 63) . '2';
        }
    }
    $tampered->set($k, $v);
}
echo "2. The same receipt, one hex digit of the output hash changed\n";
$report2 = Aer1::verifyReceipt($tampered);
echo '   verdict: ' . ($report2['verified'] ? 'verified' : 'verification failed') . "\n";
foreach (array_merge($report2['core_failures'], $report2['binding_failures']) as $f) {
    echo "   - $f\n";
}
echo "\n";

// A three-step workflow receipt, then the MM-1 violation.
$ids = [
    'b6c63ac5-f324-4fa7-ad58-c4bf83faa86a',
    '7d3f9a1e-2b4c-4e5f-9a8b-1c2d3e4f5a6b',
    'a1b2c3d4-e5f6-4a5b-8c7d-9e0f1a2b3c4d',
];
$build = static function (array $stepIds): JObject {
    $wf = new JObject();
    $wf->set('type', 'verifiable-workflow-receipt');
    $wf->set('version', '1');
    $wf->set('workflow_id', '11111111-1111-4111-8111-111111111111');
    $wf->set('receipt_id', '22222222-2222-4222-8222-222222222222');
    $wf->set('session_id', 'demo-session');
    $wf->set('goal', 'show a checked workflow');
    $wf->set('status', 'ok');
    $steps = [];
    foreach ($stepIds as $i => $rid) {
        $step = new JObject();
        $step->set('seq', $i + 1);
        $step->set('tool', 'demo-tool');
        $step->set('receipt_id', $rid);
        $step->set('receipt_hash', str_repeat('a', 64));
        $step->set('started_at', '2026-01-01T00:00:00Z');
        $step->set('ended_at', '2026-01-01T00:00:01Z');
        $step->set('status', 'ok');
        $steps[] = $step;
    }
    $wf->set('steps', $steps);
    $wf->set('merkle_root', Aer1::merkleRootCanonical($stepIds));
    $wf->set('output_hash', str_repeat('b', 64));
    $wf->set('verify_url', 'https://example.com/workflow/demo');
    return $wf;
};
echo "3. A workflow receipt over three steps\n";
$fails = Aer1::verifyWorkflow($build($ids));
echo '   verdict: ' . ($fails ? 'verification failed' : 'verified') . "\n\n";

echo "4. The same workflow with step 1's receipt_id repeated at step 3\n";
$fails2 = Aer1::verifyWorkflow($build([$ids[0], $ids[1], $ids[0]]));
echo '   verdict: ' . ($fails2 ? 'verification failed' : 'verified') . "\n";
foreach ($fails2 as $f) {
    echo "   - $f\n";
}
echo "\nFull corpus: php bin/conformance.php\n";
