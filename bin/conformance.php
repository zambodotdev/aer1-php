<?php
declare(strict_types=1);

/**
 * AER-1 conformance runner, PHP port of the reference runner pair
 * (conformance.py --base-only plus the full-corpus driver).
 *
 * Usage: php bin/conformance.php [corpus-dir]
 *
 * The corpus directory holds corpus.json (the published corpus
 * record), the base/ tree it names, and the workflow vector file.
 * Every evaluated file is hash-checked against the record before
 * anything runs, and the run ends by printing the exact set of
 * vectors it evaluated plus the evaluated-set digest, so a claimed
 * pass can be checked as a set difference against the full corpus.
 *
 * Exit 0 when all expectations hold, 1 otherwise.
 */

require __DIR__ . '/../src/bootstrap.php';

use Aer1Php\Aer1;
use Aer1Php\CanonicalJson;
use Aer1Php\JObject;
use Aer1Php\JsonParser;

$corpusDir = $argv[1] ?? (__DIR__ . '/../corpus');
$corpusDir = rtrim($corpusDir, '/');
$baseDir = $corpusDir . '/base';

/** @var array<int, array{0: string, 1: string}> evaluated set registry */
$evaluated = [];

function noteEvaluatedFile(string $id, string $bytes): void
{
    global $evaluated;
    $evaluated[] = [$id, hash('sha256', $bytes)];
}

function noteEvaluatedObject(string $id, mixed $value): void
{
    global $evaluated;
    $evaluated[] = [$id, hash('sha256', CanonicalJson::encode($value, true))];
}

/** @return array{0: mixed, 1: ?string} receipt and duplicate name */
function loadFixture(string $path): array
{
    $text = file_get_contents($path);
    $parser = new JsonParser();
    $receipt = $parser->parse($text);
    return [$receipt, $parser->firstDuplicate];
}

function loadSuite(string $path): mixed
{
    return (new JsonParser())->parse(file_get_contents($path));
}

$problems = [];

// ----------------------------------------------------------------------
// Receipt fixtures: valid / invalid / invalid-profile / anchored
// ----------------------------------------------------------------------

$validPaths = glob($baseDir . '/test-vectors/valid/*.json') ?: [];
$invalidPaths = glob($baseDir . '/test-vectors/invalid/*.json') ?: [];
$profilePaths = glob($baseDir . '/test-vectors/invalid-profile/*.json') ?: [];
$anchoredPaths = glob($baseDir . '/test-vectors/anchored/*.json') ?: [];
sort($validPaths, SORT_STRING);
sort($invalidPaths, SORT_STRING);
sort($profilePaths, SORT_STRING);
sort($anchoredPaths, SORT_STRING);
if (!$validPaths) {
    $problems[] = 'no fixtures in test-vectors/valid (empty glob)';
}
if (!$invalidPaths) {
    $problems[] = 'no fixtures in test-vectors/invalid (empty glob)';
}
if (!$profilePaths) {
    $problems[] = 'no fixtures in test-vectors/invalid-profile (empty glob)';
}
if (!$anchoredPaths) {
    $problems[] = 'no fixtures in test-vectors/anchored (empty glob)';
}

foreach ($validPaths as $path) {
    $name = basename($path);
    noteEvaluatedFile("valid/$name", file_get_contents($path));
    [$receipt, $duplicate] = loadFixture($path);
    $fails = Aer1::check($receipt);
    if ($duplicate !== null) {
        $fails[] = "duplicate member name: $duplicate";
    }
    [$isLegacy, $bindFails] = Aer1::checkVersionAndBinding($receipt);
    $fails = array_merge($fails, $bindFails);
    $status = $fails ? 'FAIL' : 'PASS';
    $legacyNote = ($isLegacy && !$fails) ? ' (legacy notice)' : '';
    echo "[valid]   $name: $status$legacyNote"
        . ($fails ? ' (' . implode('; ', $fails) . ')' : '') . "\n";
    if ($fails) {
        $problems[] = "$name should conform but does not";
    }
}

foreach ($invalidPaths as $path) {
    $name = basename($path);
    noteEvaluatedFile("invalid/$name", file_get_contents($path));
    [$receipt, $duplicate] = loadFixture($path);
    $fails = Aer1::check($receipt);
    if ($duplicate !== null) {
        $fails[] = "duplicate member name: $duplicate";
    }
    [, $bindFails] = Aer1::checkVersionAndBinding($receipt);
    $rejected = (bool) $fails || (bool) $bindFails;
    $allReasons = array_merge($fails, $bindFails);
    $status = $rejected ? 'PASS' : 'FAIL';
    echo "[invalid] $name: $status"
        . ($rejected ? " (rejected: {$allReasons[0]})" : ' (accepted!)') . "\n";
    if (!$rejected) {
        $problems[] = "$name should be rejected but was accepted";
    }
}

foreach ($profilePaths as $path) {
    $name = basename($path);
    noteEvaluatedFile("invalid-profile/$name", file_get_contents($path));
    [$receipt, $duplicate] = loadFixture($path);
    $coreFails = Aer1::check($receipt);
    if ($duplicate !== null) {
        $coreFails[] = "duplicate member name: $duplicate";
    }
    $profFails = Aer1::checkReferenceProfile($receipt);
    if ($coreFails) {
        $problems[] = "$name should be core-valid but fails core: {$coreFails[0]}";
        echo "[profile-invalid] $name: FAIL (unexpected core failure: {$coreFails[0]})\n";
    } elseif (!$profFails) {
        $problems[] = "$name should be profile-rejected but was accepted";
        echo "[profile-invalid] $name: FAIL (profile accepted!)\n";
    } else {
        echo "[profile-invalid] $name: PASS (core accepted, profile rejected: {$profFails[0]})\n";
    }
}

foreach ($anchoredPaths as $path) {
    $name = basename($path);
    noteEvaluatedFile("anchored/$name", file_get_contents($path));
    [$receipt, $duplicate] = loadFixture($path);
    $coreFails = Aer1::check($receipt);
    if ($duplicate !== null) {
        $coreFails[] = "duplicate member name: $duplicate";
    }
    $tierFails = Aer1::checkDisinterestedTier($receipt);
    $outcome = Aer1::anchorOutcome($receipt, $tierFails);
    $expectedOutcome = match ($name) {
        'anchored-valid.json' => 'verified',
        'anchored-unresolvable-anchor.json' => 'rejected: unresolvable record',
        default => 'verification failed',
    };
    $passed = !$coreFails && $outcome === $expectedOutcome;
    $status = $passed ? 'PASS' : 'FAIL';
    $detail = $tierFails ? " (tier: {$tierFails[0]})" : '';
    echo "[anchored] $name: $status (outcome: $outcome)$detail\n";
    if ($coreFails) {
        $problems[] = "$name should be core-valid but fails core";
    }
    if ($outcome !== $expectedOutcome) {
        $problems[] = "$name anchor outcome is $outcome, expected $expectedOutcome";
    }
}

// ----------------------------------------------------------------------
// Merkle vectors (Section 8.1) + workflow-verdict extension
// ----------------------------------------------------------------------

function checkMerkleVectors(string $baseDir): array
{
    $problems = [];
    $path = $baseDir . '/merkle-vectors.json';
    if (!file_exists($path)) {
        return ['merkle-vectors.json is missing (no silent pass)'];
    }
    $corpus = loadSuite($path);
    $vectors = $corpus instanceof JObject ? $corpus->get('vectors') : null;
    if (!is_array($vectors) || !$vectors) {
        return ['merkle-vectors.json contains no vectors (no silent pass)'];
    }
    foreach ($vectors as $v) {
        $name = $v instanceof JObject ? $v->get('name') : '?';
        noteEvaluatedObject("merkle/$name", $v);
        if ($v instanceof JObject && $v->has('receipt_ids')) {
            $got = Aer1::merkleRootCanonical($v->get('receipt_ids'));
            $ok = $got === $v->get('expected_root');
            echo "[merkle]  $name: " . ($ok ? 'PASS' : 'FAIL')
                . ($ok ? '' : " (got $got)") . "\n";
            if (!$ok) {
                $problems[] = "merkle vector $name: expected {$v->get('expected_root')}, got $got";
            }
        } elseif ($v instanceof JObject && $v->has('leaves')) {
            $leaves = $v->get('leaves');
            usort($leaves, static fn ($a, $b) => $a->get('seq') <=> $b->get('seq'));
            $level = [];
            foreach ($leaves as $l) {
                $level[] = hash('sha256', (string) $l->get('preimage'), true);
            }
            while (count($level) > 1) {
                if (count($level) % 2 === 1) {
                    $level[] = $level[count($level) - 1];
                }
                $next = [];
                for ($i = 0; $i < count($level); $i += 2) {
                    $next[] = hash('sha256', $level[$i] . $level[$i + 1], true);
                }
                $level = $next;
            }
            $got = $level ? bin2hex($level[0]) : hash('sha256', '');
            $ok = $got === $v->get('expected_root')
                && $got !== $v->get('must_not_equal');
            echo "[merkle]  $name: " . ($ok ? 'PASS' : 'FAIL')
                . ($ok ? '' : " (got $got)") . "\n";
            if (!$ok) {
                $problems[] = "merkle vector $name: legacy root mismatch (got $got)";
            }
        }
        if ($v instanceof JObject && $v->get('must_not_equal') !== null
            && $v->has('receipt_ids')) {
            if ($v->get('expected_root') === $v->get('must_not_equal')) {
                $problems[] = "merkle vector $name: root must differ from the canonical/legacy counterpart";
            }
        }
        $verdictField = $v instanceof JObject
            ? $v->get('expected_workflow_verdict') : null;
        if ($verdictField !== null) {
            if (!$v->has('receipt_ids')) {
                $problems[] = "merkle vector $name: expected_workflow_verdict needs receipt_ids (no silent pass)";
                echo "[merkle-workflow] $name: FAIL (no receipt_ids)\n";
                continue;
            }
            $wf = new JObject();
            $wf->set('type', 'verifiable-workflow-receipt');
            $wf->set('version', '1');
            $wf->set('workflow_id', '11111111-1111-1111-1111-111111111111');
            $wf->set('receipt_id', '22222222-2222-2222-2222-222222222222');
            $wf->set('session_id', 'test-session');
            $wf->set('goal', 'test workflow');
            $wf->set('status', 'ok');
            $steps = [];
            foreach ($v->get('receipt_ids') as $i => $rid) {
                $step = new JObject();
                $step->set('seq', $i + 1);
                $step->set('tool', 'test-tool');
                $step->set('receipt_id', $rid);
                $step->set('receipt_hash', str_repeat('a', 64));
                $step->set('started_at', '2026-01-01T00:00:00Z');
                $step->set('ended_at', '2026-01-01T00:00:01Z');
                $step->set('status', 'ok');
                $steps[] = $step;
            }
            $wf->set('steps', $steps);
            $wf->set('merkle_root', $v->get('expected_root'));
            $wf->set('output_hash', str_repeat('b', 64));
            $wf->set('verify_url', 'https://example.com/workflow/test');
            $wfFails = Aer1::verifyWorkflow($wf);
            $verdict = $wfFails ? 'invalid' : 'valid';
            $ok = $verdict === $verdictField;
            if ($ok && $verdict === 'invalid') {
                $rb = $v->get('rejected_by');
                $ok = is_string($rb)
                    && (bool) array_filter(
                        $wfFails,
                        static fn ($f) => str_contains($f, $rb)
                    );
            }
            echo "[merkle-workflow] $name: " . ($ok ? 'PASS' : 'FAIL')
                . ($ok ? '' : " (verdict $verdict)") . "\n";
            if (!$ok) {
                $problems[] = "merkle vector $name: expected workflow verdict $verdictField, got $verdict";
            }
        }
    }
    return $problems;
}

// ----------------------------------------------------------------------
// Chain / commitment vector gates
// ----------------------------------------------------------------------

function checkChainLikeVectors(
    string $baseDir,
    string $file,
    string $tag,
    string $label,
    callable $verify,
    int $pad = 1
): array {
    $problems = [];
    $path = $baseDir . '/' . $file;
    if (!file_exists($path)) {
        return ["$file is missing (no silent pass)"];
    }
    $corpus = loadSuite($path);
    $vectors = $corpus instanceof JObject ? $corpus->get('vectors') : null;
    if (!is_array($vectors) || !$vectors) {
        return ["$file contains no vectors (no silent pass)"];
    }
    foreach ($vectors as $v) {
        $name = $v instanceof JObject ? $v->get('name') : '?';
        noteEvaluatedObject("$tag/$name", $v);
        $expected = $v instanceof JObject ? $v->get('expected_verdict') : null;
        $spaces = str_repeat(' ', $pad);
        if ($expected !== 'valid' && $expected !== 'invalid') {
            $problems[] = "$tag vector $name: unknown expected_verdict (no silent pass)";
            echo "[$label]$spaces$name: FAIL (unknown expected_verdict)\n";
            continue;
        }
        $fails = $verify($v);
        $ok = (!$fails) === ($expected === 'valid');
        echo "[$label]$spaces$name: " . ($ok ? 'PASS' : 'FAIL')
            . ($ok ? '' : ' (' . implode('; ', $fails) . ')') . "\n";
        if (!$ok) {
            $problems[] = "$tag vector $name: expected $expected, got "
                . ($fails ? 'invalid' : 'valid');
        }
    }
    return $problems;
}

$problems = array_merge($problems, checkMerkleVectors($baseDir));
$problems = array_merge($problems, checkChainLikeVectors(
    $baseDir,
    'chain-vectors.json',
    'chain',
    'chain',
    static function (JObject $v): array {
        $tl = $v->get('timeline');
        if ($tl === null) {
            $tl = $v->get('entries');
        }
        return Aer1::verifyChain($tl);
    },
    2
));
$problems = array_merge($problems, checkChainLikeVectors(
    $baseDir,
    'chain-vectors-v07.json',
    'chain-v07',
    'chain-v07',
    static function (JObject $v): array {
        $tl = $v->get('timeline');
        if ($tl === null) {
            $tl = $v->get('entries');
        }
        return Aer1::verifyChainV07($tl);
    }
));
$problems = array_merge($problems, checkChainLikeVectors(
    $baseDir,
    'commitment-vectors.json',
    'commitment',
    'commitment',
    static fn (JObject $v): array => Aer1::verifyChainCommitment(
        $v->get('timeline'),
        $v->get('commitment')
    )
));

// ----------------------------------------------------------------------
// Unicode vectors (Section 4: no normalization, ever)
// ----------------------------------------------------------------------

function checkUnicodeVectors(string $baseDir): array
{
    $problems = [];
    $path = $baseDir . '/unicode-vectors.json';
    if (!file_exists($path)) {
        return ['unicode-vectors.json is missing (no silent pass)'];
    }
    $corpus = loadSuite($path);
    $vectors = $corpus instanceof JObject ? $corpus->get('vectors') : null;
    if (!is_array($vectors) || !$vectors) {
        return ['unicode-vectors.json contains no vectors (no silent pass)'];
    }
    foreach ($vectors as $v) {
        $name = $v instanceof JObject ? $v->get('name') : '?';
        noteEvaluatedObject("unicode/$name", $v);
        $expected = $v instanceof JObject ? $v->get('expected') : null;
        if ($expected !== 'match' && $expected !== 'mismatch') {
            $problems[] = "unicode vector $name: unknown expected (no silent pass)";
            echo "[unicode] $name: FAIL (unknown expected)\n";
            continue;
        }
        $fails = [];
        $b64 = $v->get('payload_base64');
        $raw = is_string($b64) ? Aer1::strictB64Decode($b64) : false;
        if ($raw === false) {
            $raw = null;
            $fails[] = 'payload_base64 is not valid base64';
        }
        if ($raw !== null) {
            if (bin2hex($raw) !== $v->get('payload_utf8_hex')) {
                $fails[] = 'decoded payload bytes do not match payload_utf8_hex';
            }
            $digest = hash('sha256', $raw);
            if ($expected === 'match' && $digest !== $v->get('sha256')) {
                $fails[] = 'sha256(payload) does not match the stated commitment';
            }
            if ($expected === 'mismatch' && $digest === $v->get('sha256')) {
                $fails[] = 'sha256(payload) matches a commitment it MUST NOT match (normalization would be required to report agreement)';
            }
        }
        $ok = !$fails;
        echo "[unicode] $name: " . ($ok ? 'PASS' : 'FAIL')
            . ($ok ? '' : ' (' . implode('; ', $fails) . ')') . "\n";
        if (!$ok) {
            $problems[] = "unicode vector $name: " . implode('; ', $fails);
        }
    }
    return $problems;
}

$problems = array_merge($problems, checkUnicodeVectors($baseDir));

// ----------------------------------------------------------------------
// Id-binding vectors
// ----------------------------------------------------------------------

function checkIdBindingVectors(string $baseDir): array
{
    $problems = [];
    $path = $baseDir . '/id-binding-vectors.json';
    if (!file_exists($path)) {
        return ['id-binding-vectors.json is missing (no silent pass)'];
    }
    $corpus = loadSuite($path);
    $vectors = $corpus instanceof JObject ? $corpus->get('vectors') : null;
    if (!is_array($vectors) || !$vectors) {
        return ['id-binding-vectors.json contains no vectors (no silent pass)'];
    }
    foreach ($vectors as $v) {
        $name = $v instanceof JObject ? $v->get('name') : '?';
        noteEvaluatedObject("id-binding/$name", $v);
        $expDigest = $v->get('expected_digest');
        $expState = $v->get('expected_id_state');
        $expIdVerdict = $v->get('expected_id_verdict');
        $expVerdict = $v->get('expected_verdict');
        if (!in_array($expDigest, ['pass', 'fail'], true)
            || !in_array($expState, ['unverified', 'verified-expected', 'verified-resolved', 'mismatch'], true)
            || !in_array($expIdVerdict, ['absent', 'unverified', 'matched', 'resolved', 'mismatched'], true)
            || !in_array($expVerdict, ['pass', 'fail'], true)) {
            $problems[] = "id-binding vector $name: unknown expectation (no silent pass)";
            echo "[id-binding] $name: FAIL (unknown expectation)\n";
            continue;
        }
        $receipt = $v->get('receipt');
        $coreFails = Aer1::check($receipt);
        [, $bindFails] = Aer1::checkVersionAndBinding($receipt);
        $digestOk = !$coreFails && !$bindFails;
        [$idState, $idFails] = Aer1::evaluateIdBinding(
            $receipt,
            $v->get('expected_id'),
            $v->get('resolved_record')
        );
        $idVerdict = Aer1::deriveIdVerdict($receipt, $idState);
        $verdictOk = $digestOk && !$idFails;
        $ok = $digestOk === ($expDigest === 'pass')
            && $idState === $expState
            && $idVerdict === $expIdVerdict
            && $verdictOk === ($expVerdict === 'pass');
        $detail = "id_state=$idState, id_verdict=$idVerdict";
        if (!$ok) {
            $detail .= ' (digest ' . ($digestOk ? 'pass' : 'fail')
                . ', verdict ' . ($verdictOk ? 'pass' : 'fail')
                . "; expected digest=$expDigest id_state=$expState id_verdict=$expIdVerdict verdict=$expVerdict)";
        }
        echo "[id-binding] $name: " . ($ok ? 'PASS' : 'FAIL') . " ($detail)\n";
        if (!$ok) {
            $problems[] = "id-binding vector $name: expectation mismatch";
        }
    }
    return $problems;
}

$problems = array_merge($problems, checkIdBindingVectors($baseDir));

// ----------------------------------------------------------------------
// Anchor vectors (per-anchor outcome report)
// ----------------------------------------------------------------------

function checkAnchorVectors(string $baseDir): array
{
    $problems = [];
    $path = $baseDir . '/anchor-vectors.json';
    if (!file_exists($path)) {
        return ['anchor-vectors.json is missing (no silent pass)'];
    }
    $corpus = loadSuite($path);
    $vectors = $corpus instanceof JObject ? $corpus->get('vectors') : null;
    if (!is_array($vectors) || !$vectors) {
        return ['anchor-vectors.json contains no vectors (no silent pass)'];
    }
    $outcomes = ['verified', 'verification failed',
        'rejected: unresolvable record', 'not checked', 'absent'];
    foreach ($vectors as $v) {
        $name = $v instanceof JObject ? $v->get('name') : '?';
        noteEvaluatedObject("anchor/$name", $v);
        $expPresent = $v->get('expected_present');
        $expEvaluated = $v->get('expected_evaluated');
        $expOutcome = $v->get('expected_anchor_outcome');
        $evaluate = $v->has('evaluate') ? $v->get('evaluate') : true;
        $hasSource = is_string($v->get('file')) || $v->get('receipt') instanceof JObject;
        if (!is_bool($expPresent) || !is_bool($expEvaluated)
            || !is_bool($evaluate) || !in_array($expOutcome, $outcomes, true)
            || !$hasSource) {
            $problems[] = "anchor vector $name: unknown expectation (no silent pass)";
            echo "[anchor] $name: FAIL (unknown expectation)\n";
            continue;
        }
        if ($v->get('receipt') instanceof JObject) {
            $receipt = $v->get('receipt');
        } else {
            [$receipt] = loadFixture($baseDir . '/' . $v->get('file'));
        }
        $tierFails = Aer1::checkDisinterestedTier($receipt);
        $report = Aer1::anchorReport($receipt, $tierFails, $evaluate);
        $ok = $report['present'] === $expPresent
            && $report['evaluated'] === $expEvaluated
            && $report['outcome'] === $expOutcome;
        $bool = static fn (bool $b) => $b ? 'true' : 'false';
        $detail = 'present=' . $bool($report['present'])
            . ', evaluated=' . $bool($report['evaluated'])
            . ", outcome={$report['outcome']}";
        if (!$ok) {
            $detail .= ' (expected present=' . $bool($expPresent)
                . ' evaluated=' . $bool($expEvaluated)
                . " outcome=$expOutcome)";
        }
        echo "[anchor] $name: " . ($ok ? 'PASS' : 'FAIL') . " ($detail)\n";
        if (!$ok) {
            $problems[] = "anchor vector $name: expected present "
                . var_export($expPresent, true) . ', evaluated '
                . var_export($expEvaluated, true) . ", outcome $expOutcome";
        }
    }
    return $problems;
}

$problems = array_merge($problems, checkAnchorVectors($baseDir));

// ----------------------------------------------------------------------
// Evaluated set: print exactly what this run covered
// ----------------------------------------------------------------------

usort($evaluated, static function ($a, $b) {
    $c = strcmp($a[0], $b[0]);
    return $c !== 0 ? $c : strcmp($a[1], $b[1]);
});
$blob = '';
foreach ($evaluated as [$vid, $digest]) {
    echo "[evaluated] $vid: sha256:$digest\n";
    $blob .= "$vid:$digest\n";
}
$setDigest = hash('sha256', $blob);
echo 'EVALUATED SET: ' . count($evaluated)
    . " vectors evaluated, corpus digest sha256:$setDigest\n";
echo "\n";

if ($problems) {
    echo "CONFORMANCE FAILED:\n";
    foreach ($problems as $p) {
        echo " - $p\n";
    }
    exit(1);
}

// ----------------------------------------------------------------------
// Full corpus section: manifest verification + workflow-root vectors
// ----------------------------------------------------------------------

echo "Base expectations passed.\n";

$manifest = (new JsonParser())->parse(
    file_get_contents($corpusDir . '/corpus.json')
);
$entries = [];
$totalVectors = 0;
$totalChecks = 0;
$fullProblems = [];
foreach ($manifest->get('files') as $f) {
    $name = $f->get('path');
    $raw = file_get_contents($corpusDir . '/' . $name);
    $value = (new JsonParser())->parse($raw);
    $n = ($value instanceof JObject && is_array($value->get('vectors')))
        ? count($value->get('vectors')) : 1;
    $c = $n;
    if ($name === 'base/merkle-vectors.json') {
        foreach ($value->get('vectors') as $v) {
            if ($v instanceof JObject && $v->has('expected_workflow_verdict')) {
                $c++;
            }
        }
    }
    $entries[] = [$name, hash('sha256', $raw), $n, $c];
    $totalVectors += $n;
    $totalChecks += $c;
}
$manifestFiles = $manifest->get('files');
if (count($entries) !== count($manifestFiles)) {
    $fullProblems[] = 'evaluated files differ from corpus.json (bytes or counts)';
} else {
    foreach ($manifestFiles as $i => $f) {
        [$name, $sha, $n, $c] = $entries[$i];
        if ($f->get('path') !== $name || $f->get('sha256') !== $sha
            || $f->get('vectors') !== $n || $f->get('checks') !== $c) {
            $fullProblems[] = 'evaluated files differ from corpus.json (bytes or counts)';
            break;
        }
    }
}
$digestBlob = '';
foreach ($entries as [$name, $sha]) {
    $digestBlob .= $name . "\0" . $sha . "\n";
}
$setDigestFull = hash('sha256', $digestBlob);
if ($totalVectors !== $manifest->get('vector_count')
    || $totalChecks !== $manifest->get('check_count')
    || 'sha256:' . $setDigestFull !== $manifest->get('evaluated_set_digest')) {
    $fullProblems[] = 'evaluated-set totals differ from corpus.json';
}

if (!$fullProblems) {
    $wfCorpus = (new JsonParser())->parse(
        file_get_contents($corpusDir . '/workflow-merkle-seq-output-v1.json')
    );
    foreach ($wfCorpus->get('vectors') as $v) {
        $name = $v->get('name');
        $level = [];
        $ok = true;
        $steps = $v->get('steps');
        foreach ($steps as $idx => $step) {
            $i = $idx + 1;
            $seq = $step instanceof JObject ? $step->get('seq') : null;
            if (!is_int($seq) && !(is_float($seq) && floor($seq) === $seq)) {
                $fullProblems[] = "$name: noncontiguous sequence";
                $ok = false;
                break;
            }
            if ((int) $seq !== $i) {
                $fullProblems[] = "$name: noncontiguous sequence";
                $ok = false;
                break;
            }
            $version = $v->get('merkle_version');
            if ($version === 'receipt-id-v0') {
                $leaf = (string) $step->get('receipt_id');
            } elseif ($version === 'seq-output-v1') {
                $outputHash = strtolower((string) $step->get('output_hash'));
                if (str_starts_with($outputHash, 'sha256:')) {
                    $outputHash = substr($outputHash, 7);
                }
                if (!preg_match('/^[0-9a-f]{64}$/', $outputHash)) {
                    $fullProblems[] = "$name: invalid output hash";
                    $ok = false;
                    break;
                }
                $leaf = "$i:$outputHash";
            } else {
                $fullProblems[] = "$name: unsupported merkle_version $version";
                $ok = false;
                break;
            }
            $level[] = hash('sha256', $leaf, true);
        }
        if (!$ok) {
            continue;
        }
        while (count($level) > 1) {
            if (count($level) % 2 === 1) {
                $level[] = $level[count($level) - 1];
            }
            $next = [];
            for ($j = 0; $j < count($level); $j += 2) {
                $next[] = hash('sha256', $level[$j] . $level[$j + 1], true);
            }
            $level = $next;
        }
        if (!$level || $v->get('expected_verdict') !== 'valid'
            || bin2hex($level[0]) !== $v->get('merkle_root')) {
            $fullProblems[] = "$name: root mismatch";
            continue;
        }
        echo "[workflow-root] $name: PASS\n";
    }
}

if ($fullProblems) {
    echo "CONFORMANCE FAILED:\n";
    foreach ($fullProblems as $p) {
        echo " - $p\n";
    }
    exit(1);
}
echo "CONFORMANCE OK: $totalVectors vectors, $totalChecks checks, sha256:$setDigestFull\n";
exit(0);
