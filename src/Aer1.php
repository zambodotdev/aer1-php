<?php
declare(strict_types=1);

namespace Aer1Php;

/**
 * AER-1 verifier library (draft-zambo-aer1-26, kit v1.5.7 semantics).
 *
 * A function-for-function port of the reference Python conformance
 * runner (conformance.py), so the PHP runner's verdicts, failure
 * strings and per-anchor reports agree with the reference runners
 * vector for vector. Every function returns a list of failure
 * reasons; an empty list means the check passed.
 *
 * A receipt proves the saved result was not changed since it was
 * saved. Verification says nothing about whether the answer the
 * receipt records was right.
 */
final class Aer1
{
    public const CORE = ['id', 'receipt_schema_version', 'created_at', 'tool',
        'provenance_class', 'canonical_bytes', 'output_hash',
        'verification_status'];

    private const UUID_RE = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';
    private const STRICT_UUID_RE = '/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/';
    private const RFC3339_RE = '/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})\z/';
    private const HASH_RE = '/\Asha256:[0-9a-f]{64}\z/';
    private const PROV_RE = '/\A(EXECUTED BY [A-Z0-9][A-Z0-9 ._-]*|OBSERVED VIA GATEWAY|LOGGED BY AGENT)\z/';
    private const B64_RE = '/\A[A-Za-z0-9+\/]*={0,2}\z/';
    private const HEX64_RE = '/\A[0-9a-f]{64}\z/';
    private const NIL_UUID = '00000000-0000-0000-0000-000000000000';

    // ------------------------------------------------------------------
    // Primitives
    // ------------------------------------------------------------------

    /** Strict base64 decode (Python b64decode with validate=True). */
    public static function strictB64Decode(string $s): string|false
    {
        if (strlen($s) % 4 !== 0) {
            return false;
        }
        if (!preg_match(self::B64_RE, $s)) {
            return false;
        }
        $raw = base64_decode($s, true);
        return $raw === false ? false : $raw;
    }

    public static function isValidUtf8(string $s): bool
    {
        return preg_match('//u', $s) === 1;
    }

    public static function sha256Hex(string $raw): string
    {
        return hash('sha256', $raw);
    }

    /** Python str() for the scalar values the binding check compares. */
    private static function pyStr(mixed $v): string
    {
        if (is_string($v)) {
            return $v;
        }
        if (is_int($v)) {
            return (string) $v;
        }
        if (is_float($v)) {
            $s = CanonicalJson::floatString($v);
            return $s;
        }
        if (is_bool($v)) {
            return $v ? 'True' : 'False';
        }
        if ($v === null) {
            return 'None';
        }
        return CanonicalJson::encode($v, false);
    }

    /** Python repr() approximation for the id-binding detail strings. */
    private static function pyRepr(mixed $v): string
    {
        if ($v === null) {
            return 'None';
        }
        if (is_bool($v)) {
            return $v ? 'True' : 'False';
        }
        if (is_int($v)) {
            return (string) $v;
        }
        if (is_float($v)) {
            return CanonicalJson::floatString($v);
        }
        if (is_string($v)) {
            $quote = "'";
            if (str_contains($v, "'") && !str_contains($v, '"')) {
                $quote = '"';
            }
            $out = '';
            foreach (JsonParser::codePoints($v) as $cp) {
                if ($cp === 0x5C) {
                    $out .= '\\\\';
                } elseif (chr(min($cp, 0x7F)) === $quote && $cp < 0x80) {
                    $out .= '\\' . $quote;
                } elseif ($cp === 0x0A) {
                    $out .= '\\n';
                } elseif ($cp === 0x0D) {
                    $out .= '\\r';
                } elseif ($cp === 0x09) {
                    $out .= '\\t';
                } elseif ($cp < 0x20 || $cp === 0x7F) {
                    $out .= sprintf('\\x%02x', $cp);
                } elseif ($cp < 0x7F) {
                    $out .= chr($cp);
                } else {
                    $out .= JsonParser::encodeUtf8($cp);
                }
            }
            return $quote . $out . $quote;
        }
        return CanonicalJson::encode($v, false);
    }

    /**
     * Strict RFC 3339 validation: shape, in-range timezone offset,
     * real calendar date, no leap seconds. Fail closed.
     */
    public static function strictRfc3339(mixed $s): bool
    {
        if (!is_string($s) || !preg_match(self::RFC3339_RE, $s)) {
            return false;
        }
        if (!str_ends_with($s, 'Z')) {
            $off = substr($s, -6);
            $oh = (int) substr($off, 1, 2);
            $om = (int) substr($off, 4, 2);
            if (!($oh >= 0 && $oh <= 23 && $om >= 0 && $om <= 59)) {
                return false;
            }
        }
        $year = (int) substr($s, 0, 4);
        $month = (int) substr($s, 5, 2);
        $day = (int) substr($s, 8, 2);
        $hour = (int) substr($s, 11, 2);
        $minute = (int) substr($s, 14, 2);
        $second = (int) substr($s, 17, 2);
        if (!($month >= 1 && $month <= 12)) {
            return false;
        }
        // second=60 is a leap second; leap-second validity cannot be
        // checked offline, so the draft requires rejection.
        if (!($hour >= 0 && $hour <= 23 && $minute >= 0 && $minute <= 59
            && $second >= 0 && $second <= 59)) {
            return false;
        }
        if (in_array($month, [1, 3, 5, 7, 8, 10, 12], true)) {
            $maxDay = 31;
        } elseif (in_array($month, [4, 6, 9, 11], true)) {
            $maxDay = 30;
        } else {
            $isLeap = ($year % 4 === 0 && ($year % 100 !== 0 || $year % 400 === 0));
            $maxDay = $isLeap ? 29 : 28;
        }
        return $day >= 1 && $day <= $maxDay;
    }

    // ------------------------------------------------------------------
    // Core receipt check (draft Sections 3-6)
    // ------------------------------------------------------------------

    private static function isLegacyProductionShape(mixed $receipt): bool
    {
        if (!$receipt instanceof JObject) {
            return false;
        }
        if ($receipt->has('created_at')) {
            return false;
        }
        $version = $receipt->get('receipt_schema_version');
        if ($version !== '0.2' && $version !== '0.3') {
            return false;
        }
        $ts = $receipt->get('timestamp');
        if (!is_string($ts) || $ts === '') {
            return false;
        }
        $tool = $receipt->get('tool');
        $ctx = $receipt->get('tool_context');
        if (!is_string($tool) || $tool === '') {
            return false;
        }
        if (!$ctx instanceof JObject) {
            return false;
        }
        foreach (['name', 'version', 'scope'] as $k) {
            $v = $ctx->get($k);
            if (!is_string($v) || $v === '') {
                return false;
            }
        }
        return $ctx->get('name') === $tool;
    }

    /** Core check. Returns failure reasons; empty means conformant. */
    public static function check(mixed $receipt): array
    {
        $failures = [];
        if (!$receipt instanceof JObject) {
            return ['receipt is not a JSON object'];
        }
        $legacyProd = self::isLegacyProductionShape($receipt);
        $required = self::CORE;
        if ($legacyProd) {
            $required = array_values(array_filter(
                self::CORE,
                static fn ($f) => $f !== 'created_at'
            ));
            $required[] = 'timestamp';
            $required[] = 'tool_context';
        }
        foreach ($required as $field) {
            if (!$receipt->has($field)) {
                $failures[] = "missing required member: $field";
            }
        }
        if ($failures) {
            return $failures;
        }
        $id = $receipt->get('id');
        if (!is_string($id) || !preg_match(self::UUID_RE, $id)) {
            $failures[] = 'id is not a lowercase UUID';
        } elseif ($id === self::NIL_UUID) {
            $failures[] = 'id is the nil UUID';
        }
        $rsv = $receipt->get('receipt_schema_version');
        if (!is_string($rsv) || $rsv === '') {
            $failures[] = 'receipt_schema_version is not a non-empty string';
        }
        $createdValue = $legacyProd ? $receipt->get('timestamp')
            : $receipt->get('created_at');
        if (!is_string($createdValue)) {
            $failures[] = 'created_at is not a string';
        } elseif (!preg_match(self::RFC3339_RE, $createdValue)) {
            $failures[] = 'created_at is not RFC 3339';
        } elseif (!self::strictRfc3339($createdValue)) {
            $failures[] = 'created_at is not a valid calendar date/time';
        }
        $tool = $legacyProd ? $receipt->get('tool_context')
            : $receipt->get('tool');
        $toolOk = $tool instanceof JObject;
        if ($toolOk) {
            foreach (['name', 'version', 'scope'] as $k) {
                $v = $tool->get($k);
                if (!is_string($v) || $v === '') {
                    $toolOk = false;
                    break;
                }
            }
        }
        if (!$toolOk) {
            $failures[] = 'tool is not an object with name/version/scope strings';
        }
        $pc = $receipt->get('provenance_class');
        if (!is_string($pc) || !preg_match(self::PROV_RE, $pc)) {
            $failures[] = 'provenance_class is not a known class';
        }
        $cb = $receipt->get('canonical_bytes');
        $raw = null;
        if (!is_string($cb) || !preg_match(self::B64_RE, $cb)) {
            $failures[] = 'canonical_bytes is not valid base64';
        } else {
            $decoded = self::strictB64Decode($cb);
            if ($decoded === false) {
                $failures[] = 'canonical_bytes is not valid base64';
            } else {
                $raw = $decoded;
                // Canonical spelling, not just decodability.
                if (base64_encode($raw) !== $cb) {
                    $failures[] = 'canonical_bytes is not the canonical base64 spelling';
                }
                if (!self::isValidUtf8($raw)) {
                    $failures[] = 'canonical_bytes is not valid UTF-8';
                    $raw = null;
                }
            }
        }
        $oh = $receipt->get('output_hash');
        if (!is_string($oh) || !preg_match(self::HASH_RE, $oh)) {
            $failures[] = 'output_hash is not sha256: + lowercase hex digest';
        } elseif ($raw !== null) {
            $want = 'sha256:' . self::sha256Hex($raw);
            if ($oh !== $want) {
                $failures[] = 'output_hash does not match sha256(canonical_bytes)';
            }
        }
        // Optional input commitment (Section 3.3): evaluated only when
        // the canonical payload records an 'inputs' member.
        if ($receipt->has('input_hash') && $receipt->get('input_hash') !== null) {
            $ih = $receipt->get('input_hash');
            if (!is_string($ih) || !preg_match(self::HASH_RE, $ih)) {
                $failures[] = 'input_hash is not sha256: + lowercase hex digest';
            } elseif ($raw !== null) {
                $payload = null;
                try {
                    $payload = (new JsonParser())->parse($raw);
                } catch (\RuntimeException) {
                    $payload = null;
                }
                if ($payload instanceof JObject && $payload->has('inputs')) {
                    $blob = CanonicalJson::encode($payload->get('inputs'), false);
                    $want = 'sha256:' . self::sha256Hex($blob);
                    if ($ih !== $want) {
                        $failures[] = 'input_hash does not match sha256(canonical JSON of the recorded inputs)';
                    }
                }
            }
        }
        if ($legacyProd) {
            $vs = $receipt->get('verification_status');
            if (!is_string($vs) || $vs === '') {
                $failures[] = 'verification_status is not a non-empty string';
            }
        } elseif ($receipt->get('verification_status') !== 'verified') {
            $failures[] = 'verification_status is not verified';
        }
        return $failures;
    }

    // ------------------------------------------------------------------
    // Version agreement + provenance binding (Section 6)
    // ------------------------------------------------------------------

    /**
     * Returns [isLegacy, failures]. Legacy receipts (outer 0.2/0.3
     * with no inner version commitment) pass with no failures.
     */
    public static function checkVersionAndBinding(mixed $receipt): array
    {
        $innerObj = null;
        $innerVersion = null;
        $cb = $receipt instanceof JObject ? $receipt->get('canonical_bytes') : null;
        if (is_string($cb)) {
            $raw = self::strictB64Decode($cb);
            if ($raw !== false && self::isValidUtf8($raw)) {
                try {
                    $parsed = (new JsonParser())->parse($raw);
                    if ($parsed instanceof JObject) {
                        $innerObj = $parsed;
                    }
                } catch (\RuntimeException) {
                    $innerObj = null;
                }
            }
        }
        if ($innerObj instanceof JObject) {
            $innerVersion = $innerObj->get('receipt_schema_version');
        }
        $outerVersion = $receipt instanceof JObject
            ? $receipt->get('receipt_schema_version') : null;
        $legacyVersion = $innerVersion !== null ? $innerVersion : $outerVersion;
        $isLegacy = $legacyVersion !== null
            && in_array(self::pyStr($legacyVersion), ['0.2', '0.3'], true);
        if ($isLegacy) {
            return [true, []];
        }
        $failures = [];
        if ($innerVersion !== null && $outerVersion !== null) {
            if (self::pyStr($innerVersion) !== self::pyStr($outerVersion)) {
                $failures[] = 'receipt_schema_version: outer '
                    . CanonicalJson::jsonQuote($outerVersion)
                    . ' does not match committed '
                    . CanonicalJson::jsonQuote($innerVersion);
            }
        } else {
            $failures[] = 'receipt_schema_version: one side missing (outer='
                . CanonicalJson::jsonQuote($outerVersion) . ' committed='
                . CanonicalJson::jsonQuote($innerVersion) . ')';
        }
        if ($innerObj instanceof JObject) {
            $issuerClaims = $innerObj->get('issuer_claims');
            $committed = $issuerClaims instanceof JObject
                ? $issuerClaims->get('provenance_class') : null;
            $outerPc = $receipt instanceof JObject
                ? $receipt->get('provenance_class') : null;
            if ($committed !== null && $outerPc !== null) {
                if ($committed !== $outerPc) {
                    $failures[] = 'provenance binding: outer '
                        . CanonicalJson::jsonQuote($outerPc)
                        . ' does not match committed '
                        . CanonicalJson::jsonQuote($committed);
                }
            } else {
                $failures[] = 'provenance binding: one side missing (outer='
                    . CanonicalJson::jsonQuote($outerPc) . ' committed='
                    . CanonicalJson::jsonQuote($committed) . ')';
            }
        } else {
            $failures[] = 'provenance binding: canonical payload did not decode to an object';
        }
        return [false, $failures];
    }

    // ------------------------------------------------------------------
    // Reference-producer profile
    // ------------------------------------------------------------------

    public static function checkReferenceProfile(mixed $receipt): array
    {
        if (!$receipt instanceof JObject) {
            return ['receipt is not a JSON object'];
        }
        $cb = $receipt->get('canonical_bytes');
        if (!is_string($cb)) {
            return ['canonical_bytes is not a string'];
        }
        $raw = self::strictB64Decode($cb);
        if ($raw === false) {
            return ['canonical_bytes is not valid base64'];
        }
        if (!self::isValidUtf8($raw)) {
            return ['canonical_bytes is not valid UTF-8'];
        }
        try {
            $payload = (new JsonParser())->parse($raw);
        } catch (\RuntimeException) {
            return ['canonical payload is not JSON'];
        }
        if (!$payload instanceof JObject) {
            return ['canonical payload is not a JSON object'];
        }
        if (!$payload->has('inputs')) {
            return ["reference-producer payload omits the 'inputs' member"];
        }
        return [];
    }

    // ------------------------------------------------------------------
    // Anchor profile (disinterested tier) + anchor outcome report
    // ------------------------------------------------------------------

    public static function checkDisinterestedTier(mixed $receipt): array
    {
        $failures = [];
        $rid = $receipt instanceof JObject ? $receipt->get('id') : null;
        if (!is_string($rid) || !preg_match(self::STRICT_UUID_RE, $rid)) {
            $failures[] = 'id is not a UUID v4 (strict profile)';
        }
        $anchor = $receipt instanceof JObject ? $receipt->get('anchor') : null;
        if (!$anchor instanceof JObject) {
            return ['anchor is not an object'];
        }
        $keys = $anchor->keys();
        sort($keys, SORT_STRING);
        $keys = array_values(array_unique($keys));
        if ($keys !== ['anchored_at', 'leaf_hash', 'log', 'proof']) {
            $failures[] = 'anchor has members other than log/leaf_hash/anchored_at/proof';
        }
        $log = $anchor->get('log');
        if (!is_string($log) || $log === '') {
            $failures[] = 'anchor.log is not a non-empty string';
        }
        $leaf = $anchor->get('leaf_hash');
        if (!is_string($leaf) || !preg_match(self::HASH_RE, $leaf)) {
            $failures[] = 'anchor.leaf_hash is not sha256: + lowercase hex digest';
        } else {
            $cb = $receipt instanceof JObject ? $receipt->get('canonical_bytes') : null;
            $raw = null;
            if (!is_string($cb) || !preg_match(self::B64_RE, $cb)) {
                $failures[] = 'canonical_bytes is not valid base64';
            } else {
                $decoded = self::strictB64Decode($cb);
                if ($decoded === false || !self::isValidUtf8($decoded)) {
                    $failures[] = 'canonical_bytes is not valid UTF-8 base64';
                } else {
                    $raw = $decoded;
                }
            }
            if ($raw !== null) {
                $want = 'sha256:' . self::sha256Hex($raw);
                if ($leaf !== $want) {
                    $failures[] = 'anchor.leaf_hash does not match canonical_bytes';
                }
            }
        }
        $anchoredAt = $anchor->get('anchored_at');
        if (!is_string($anchoredAt) || !preg_match(self::RFC3339_RE, $anchoredAt)) {
            $failures[] = 'anchor.anchored_at is not RFC 3339';
        } elseif (!self::strictRfc3339($anchoredAt)) {
            $failures[] = 'anchor.anchored_at is not a valid calendar date/time';
        }
        if (!$anchor->get('proof') instanceof JObject) {
            $failures[] = 'anchor.proof is not an object';
        }
        return $failures;
    }

    private static function uriHost(string $uri): ?string
    {
        if (!preg_match('/^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^\/\?#]+)/', $uri, $m)) {
            return null;
        }
        $rest = $m[1];
        $at = strrpos($rest, '@');
        if ($at !== false) {
            $rest = substr($rest, $at + 1);
        }
        $host = strtolower(explode(':', $rest)[0]);
        return $host === '' ? null : $host;
    }

    public static function anchorResolvable(mixed $receipt): bool
    {
        $anchor = $receipt instanceof JObject ? $receipt->get('anchor') : null;
        if (!$anchor instanceof JObject) {
            return true;
        }
        $log = $anchor->get('log');
        if (!is_string($log) || $log === '') {
            return true;
        }
        $host = self::uriHost($log);
        if ($host === null) {
            return true;
        }
        return !str_ends_with($host, '.invalid');
    }

    /** Section 6 step 5 outcome classification. */
    public static function anchorOutcome(mixed $receipt, array $tierFails): string
    {
        if (!self::anchorResolvable($receipt)) {
            return 'rejected: unresolvable record';
        }
        if ($tierFails) {
            return 'verification failed';
        }
        return 'verified';
    }

    private const ANCHOR_PROFILE_MEMBERS = ['log', 'leaf_hash', 'anchored_at', 'proof'];

    public static function anchorProfilePresent(mixed $receipt): bool
    {
        if (!$receipt instanceof JObject) {
            return false;
        }
        $anchor = $receipt->get('anchor');
        if (!$anchor instanceof JObject) {
            return false;
        }
        foreach ($anchor->keys() as $k) {
            if (in_array($k, self::ANCHOR_PROFILE_MEMBERS, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Machine-visible per-anchor report: absent / not checked /
     * evaluated Section 6 step 5 outcome.
     *
     * @return array{present: bool, evaluated: bool, outcome: string}
     */
    public static function anchorReport(mixed $receipt, array $tierFails, bool $evaluate = true): array
    {
        if (!self::anchorProfilePresent($receipt)) {
            return ['present' => false, 'evaluated' => false, 'outcome' => 'absent'];
        }
        if (!$evaluate) {
            return ['present' => true, 'evaluated' => false, 'outcome' => 'not checked'];
        }
        return ['present' => true, 'evaluated' => true,
            'outcome' => self::anchorOutcome($receipt, $tierFails)];
    }

    // ------------------------------------------------------------------
    // Workflow verification (Section 8) + Merkle root (Section 8.1)
    // ------------------------------------------------------------------

    /** Section 8.1 root over receipt_id strings (receipt-id-v0 rule). */
    public static function merkleRootCanonical(array $receiptIds): string
    {
        if (!$receiptIds) {
            return self::sha256Hex('');
        }
        $level = [];
        foreach ($receiptIds as $rid) {
            $level[] = hash('sha256', (string) $rid, true);
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
        return bin2hex($level[0]);
    }

    /**
     * Versioned workflow root used by the v1.5.7 workflow vectors:
     * leaf preimage is the receipt_id under receipt-id-v0, or
     * "{seq}:{output_hash}" under seq-output-v1. Returns the hex root.
     *
     * @param array<int, array{receipt_id?: string, output_hash?: string}> $steps
     */
    public static function workflowRoot(array $steps, string $merkleVersion): string
    {
        $level = [];
        $i = 0;
        foreach ($steps as $step) {
            $i++;
            if ($merkleVersion === 'receipt-id-v0') {
                $leaf = (string) ($step['receipt_id'] ?? '');
            } elseif ($merkleVersion === 'seq-output-v1') {
                $outputHash = strtolower((string) ($step['output_hash'] ?? ''));
                if (str_starts_with($outputHash, 'sha256:')) {
                    $outputHash = substr($outputHash, 7);
                }
                if (!preg_match(self::HEX64_RE, $outputHash)) {
                    throw new \RuntimeException('invalid output hash');
                }
                $leaf = $i . ':' . $outputHash;
            } else {
                throw new \RuntimeException('unsupported merkle_version ' . $merkleVersion);
            }
            $level[] = hash('sha256', $leaf, true);
        }
        if (!$level) {
            return self::sha256Hex('');
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
        return bin2hex($level[0]);
    }

    private static function isIntegerValued(mixed $v): bool
    {
        return is_int($v) || (is_float($v) && floor($v) === $v);
    }

    /** Section 8.2 steps 3-4: offline workflow verification. */
    public static function verifyWorkflow(mixed $workflow): array
    {
        if (!$workflow instanceof JObject) {
            return ['workflow is not a JSON object'];
        }
        $failures = [];
        if ($workflow->get('type') !== 'verifiable-workflow-receipt') {
            $failures[] = 'workflow type is not "verifiable-workflow-receipt"';
        }
        $version = $workflow->get('version');
        if (!is_string($version) || $version === '') {
            $failures[] = 'workflow version is not a non-empty string';
        }
        $wid = $workflow->get('workflow_id');
        if (!is_string($wid) || !preg_match(self::UUID_RE, $wid)) {
            $failures[] = 'workflow workflow_id is not a lowercase UUID';
        }
        $wrid = $workflow->get('receipt_id');
        if (!is_string($wrid) || !preg_match(self::UUID_RE, $wrid)) {
            $failures[] = 'workflow receipt_id is not a lowercase UUID';
        }
        foreach (['session_id', 'goal', 'status'] as $field) {
            $v = $workflow->get($field);
            if (!is_string($v) || $v === '') {
                $failures[] = "workflow $field is not a non-empty string";
            }
        }
        $oh = $workflow->get('output_hash');
        if (!is_string($oh) || !preg_match(self::HEX64_RE, $oh)) {
            $failures[] = 'workflow output_hash is not a 64-char lowercase hex SHA-256 digest';
        }
        $vu = $workflow->get('verify_url');
        if (!is_string($vu)
            || !(str_starts_with($vu, 'http://') || str_starts_with($vu, 'https://'))) {
            $failures[] = 'workflow verify_url is not an http(s) URL string';
        }
        $steps = $workflow->get('steps');
        // JSON arrays parse to PHP lists; a JObject here is not a list.
        if (!is_array($steps) || !$steps) {
            $failures[] = 'workflow steps is not a non-empty list';
            return $failures;
        }
        foreach ($steps as $idx => $step) {
            $n = $idx + 1;
            if (!$step instanceof JObject) {
                $failures[] = "step $n is not an object";
                continue;
            }
            $seq = $step->get('seq');
            if (is_bool($seq) || !self::isIntegerValued($seq)) {
                $failures[] = "step $n seq is not an integer";
            }
            if (!is_string($step->get('receipt_id'))) {
                $failures[] = "step $n receipt_id is not a string";
            }
            $tool = $step->get('tool');
            if (!is_string($tool) || $tool === '') {
                $failures[] = "step $n tool is not a non-empty string";
            }
            $rh = $step->get('receipt_hash');
            if (!is_string($rh) || !preg_match(self::HEX64_RE, $rh)) {
                $failures[] = "step $n receipt_hash is not a 64-char lowercase hex SHA-256 digest";
            }
            if (!self::strictRfc3339($step->get('started_at'))) {
                $failures[] = "step $n started_at is not a valid RFC 3339 timestamp";
            }
            if (!self::strictRfc3339($step->get('ended_at'))) {
                $failures[] = "step $n ended_at is not a valid RFC 3339 timestamp";
            }
            $status = $step->get('status');
            if (!is_string($status) || $status === '') {
                $failures[] = "step $n status is not a non-empty string";
            }
        }
        if ($failures) {
            return $failures;
        }
        $count = count($steps);
        foreach ($steps as $idx => $step) {
            $seq = $step->get('seq');
            $seqInt = is_int($seq) ? $seq : (int) $seq;
            if ($seqInt !== $idx + 1) {
                $shown = is_int($seq) ? (string) $seq
                    : CanonicalJson::floatString((float) $seq);
                $failures[] = "step seq values are not 1..$count in order (index $idx carries seq $shown)";
                break;
            }
        }
        $seen = [];
        foreach ($steps as $step) {
            $rid = $step->get('receipt_id');
            if (isset($seen[$rid])) {
                $failures[] = "duplicate receipt_id: $rid";
                break;
            }
            $seen[$rid] = true;
        }
        $ids = array_map(static fn ($s) => $s->get('receipt_id'), $steps);
        $root = self::merkleRootCanonical($ids);
        $mr = $workflow->get('merkle_root');
        if (!is_string($mr) || $mr !== $root) {
            $failures[] = 'merkle_root does not match the recomputed Section 8.1 root';
        }
        return $failures;
    }

    // ------------------------------------------------------------------
    // Chains (Section 7): -06 construction, -07 construction, commitment
    // ------------------------------------------------------------------

    public static function verifyChain(mixed $timeline): array
    {
        if (!is_array($timeline) || !$timeline) {
            return ['timeline is not a non-empty list'];
        }
        $failures = [];
        $prev = null;
        foreach ($timeline as $i => $entry) {
            if (!$entry instanceof JObject) {
                $failures[] = "entry $i is not an object";
                break;
            }
            $cb = $entry->get('canonical_bytes');
            if (!is_string($cb) || !preg_match(self::B64_RE, $cb)) {
                $failures[] = "entry $i canonical_bytes is not valid base64";
                break;
            }
            $raw = self::strictB64Decode($cb);
            if ($raw === false) {
                $failures[] = "entry $i canonical_bytes is not valid base64";
                break;
            }
            $digest = self::sha256Hex($raw);
            $pd = $entry->get('prev_digest');
            if ($i === 0) {
                if (!is_string($pd) || $pd !== str_repeat('0', 64)) {
                    $failures[] = 'entry 0 prev_digest is not 64 zero characters';
                }
            } elseif (!is_string($pd) || $pd !== $prev) {
                $failures[] = "entry $i prev_digest does not match the digest of entry "
                    . ($i - 1);
            }
            $prev = $digest;
        }
        $last = $timeline[count($timeline) - 1];
        if ($last instanceof JObject && $last->get('close') !== true) {
            $failures[] = 'last entry does not carry close: true';
        }
        return $failures;
    }

    /** Section 7 (-07) entry digest. Throws on bad base64 or shape. */
    public static function chainEntryDigestV07(JObject $entry): string
    {
        $cb = $entry->get('canonical_bytes');
        if (!is_string($cb)) {
            throw new \RuntimeException('canonical_bytes missing');
        }
        $raw = self::strictB64Decode($cb);
        if ($raw === false) {
            throw new \RuntimeException('canonical_bytes is not valid base64');
        }
        $outputHash = self::sha256Hex($raw);
        $seq = $entry->get('seq');
        if (is_float($seq) && floor($seq) === $seq) {
            $seq = (int) $seq;
        }
        $payload = new JObject();
        $payload->set('prev_digest', $entry->get('prev_digest'));
        $payload->set('seq', $seq);
        $payload->set('job_id', $entry->get('job_id'));
        $payload->set('close', $entry->has('close') ? $entry->get('close') : false);
        $payload->set('id', $entry->get('id'));
        $payload->set('tool', $entry->get('tool'));
        $payload->set('provenance_class', $entry->get('provenance_class'));
        $payload->set('output_hash', $outputHash);
        return self::sha256Hex(CanonicalJson::encode($payload, false));
    }

    public static function verifyChainV07(mixed $timeline): array
    {
        if (!is_array($timeline) || !$timeline) {
            return ['timeline is not a non-empty list'];
        }
        $failures = [];
        $job = null;
        $prev = null;
        $count = count($timeline);
        foreach ($timeline as $i => $entry) {
            if (!$entry instanceof JObject) {
                return ["entry $i is not an object"];
            }
            $cb = $entry->get('canonical_bytes');
            if (!is_string($cb) || !preg_match(self::B64_RE, $cb)) {
                return ["entry $i canonical_bytes is not valid base64"];
            }
            if (self::strictB64Decode($cb) === false) {
                return ["entry $i canonical_bytes is not valid base64"];
            }
            foreach (['id', 'tool', 'provenance_class', 'job_id', 'prev_digest'] as $m) {
                $v = $entry->get($m);
                if (!is_string($v) || $v === '') {
                    return ["entry $i missing $m"];
                }
            }
            $seq = $entry->get('seq');
            if (is_bool($seq) || !self::isIntegerValued($seq)) {
                return ["entry $i seq is not an integer"];
            }
            $seqInt = is_int($seq) ? $seq : (int) $seq;
            if ($seqInt !== $i + 1) {
                $failures[] = "entry $i seq $seqInt breaks contiguity (expected "
                    . ($i + 1) . ')';
            }
            if ($job === null) {
                $job = $entry->get('job_id');
            } elseif ($entry->get('job_id') !== $job) {
                $failures[] = "entry $i job_id mixes jobs";
            }
            $pd = $entry->get('prev_digest');
            if ($i === 0) {
                if ($pd !== str_repeat('0', 64)) {
                    $failures[] = 'entry 0 prev_digest is not 64 zero characters';
                }
            } elseif ($pd !== $prev) {
                $failures[] = "entry $i prev_digest does not match the digest of entry "
                    . ($i - 1);
            }
            if ($entry->has('close') && !is_bool($entry->get('close'))) {
                $failures[] = "entry $i close is not a boolean";
            } elseif ($i < $count - 1 && $entry->get('close') === true) {
                $failures[] = "entry $i carries close:true before the last entry";
            }
            $prev = self::chainEntryDigestV07($entry);
        }
        $last = $timeline[$count - 1];
        if (!$last instanceof JObject || $last->get('close') !== true) {
            $failures[] = 'last entry does not carry close: true';
        }
        return $failures;
    }

    public static function verifyChainCommitment(mixed $timeline, mixed $commitment): array
    {
        if (!is_array($timeline) || !$timeline) {
            return ['timeline is not a non-empty list'];
        }
        if (!$commitment instanceof JObject) {
            return ['commitment is not a JSON object'];
        }
        $failures = [];
        $jobId = $commitment->get('job_id');
        if (!is_string($jobId) || $jobId === '') {
            $failures[] = 'commitment job_id is not a non-empty string';
        }
        $digest = $commitment->get('final_entry_digest');
        if (!is_string($digest) || !preg_match(self::HEX64_RE, $digest)) {
            $failures[] = 'commitment final_entry_digest is not 64 lowercase hex characters';
        }
        $count = $commitment->get('entry_count');
        if (is_bool($count) || !is_int($count)) {
            $failures[] = 'commitment entry_count is not an integer';
        }
        $published = $commitment->get('published_at');
        if (!is_string($published) || !preg_match(self::RFC3339_RE, $published)) {
            $failures[] = 'commitment published_at is not RFC 3339';
        } elseif (!self::strictRfc3339($published)) {
            $failures[] = 'commitment published_at is not a valid calendar date/time';
        }
        if ($failures) {
            return $failures;
        }
        if ($count !== count($timeline)) {
            $failures[] = "commitment entry_count $count does not match the timeline length "
                . count($timeline);
        }
        foreach ($timeline as $i => $entry) {
            $ej = $entry instanceof JObject ? $entry->get('job_id') : null;
            if (!is_string($ej) || $ej === '') {
                $failures[] = "entry $i has no usable job_id";
            } elseif ($ej !== $jobId) {
                $failures[] = "entry $i job_id does not match the commitment job_id";
            }
        }
        try {
            $last = $timeline[count($timeline) - 1];
            if (!$last instanceof JObject) {
                throw new \RuntimeException('last entry is not an object');
            }
            $want = self::chainEntryDigestV07($last);
            if ($digest !== $want) {
                $failures[] = 'commitment final_entry_digest does not match the recomputed digest of the last entry';
            }
        } catch (\RuntimeException $e) {
            $failures[] = 'final entry digest could not be recomputed: ' . $e->getMessage();
        }
        return $failures;
    }

    // ------------------------------------------------------------------
    // Id binding (Sections 6 and 13) + enumerated id verdict
    // ------------------------------------------------------------------

    /**
     * Returns [idState, failures].
     */
    public static function evaluateIdBinding(
        mixed $receipt,
        mixed $expectedId,
        mixed $resolvedRecord
    ): array {
        $rid = $receipt instanceof JObject ? $receipt->get('id') : null;
        if ($expectedId === null && $resolvedRecord === null) {
            return ['unverified', []];
        }
        $failures = [];
        $state = null;
        if ($expectedId !== null) {
            if ($rid !== $expectedId) {
                $failures[] = 'id mismatch: artifact id ' . self::pyRepr($rid)
                    . ' does not match the externally supplied expected id '
                    . self::pyRepr($expectedId);
                $state = 'mismatch';
            } else {
                $state = 'verified-expected';
            }
        }
        if ($resolvedRecord !== null) {
            $rrec = $resolvedRecord;
            if ($rrec instanceof JObject && $rrec->get('receipt') instanceof JObject) {
                $rrec = $rrec->get('receipt');
            }
            if (!$rrec instanceof JObject) {
                $failures[] = 'resolved record is not a JSON object';
                $state = 'mismatch';
            } else {
                $rDigest = $rrec->get('output_hash');
                $rId = $rrec->get('id');
                $artifactDigest = $receipt instanceof JObject
                    ? $receipt->get('output_hash') : null;
                if ($rDigest !== $artifactDigest) {
                    $failures[] = 'id mismatch: resolved record digest '
                        . self::pyRepr($rDigest)
                        . " disagrees with the artifact's committed digest "
                        . self::pyRepr($artifactDigest);
                    $state = 'mismatch';
                } elseif ($rId !== null && $rId !== $rid) {
                    $failures[] = 'id mismatch: resolved record carries id '
                        . self::pyRepr($rId) . ", not the artifact's id "
                        . self::pyRepr($rid);
                    $state = 'mismatch';
                } elseif (!$failures) {
                    $state = 'verified-resolved';
                }
            }
        }
        return [$state ?? 'unverified', $failures];
    }

    public static function deriveIdVerdict(mixed $receipt, string $idState): string
    {
        if (!$receipt instanceof JObject || $receipt->get('id') === null) {
            return 'absent';
        }
        return [
            'unverified' => 'unverified',
            'verified-expected' => 'matched',
            'verified-resolved' => 'resolved',
            'mismatch' => 'mismatched',
        ][$idState] ?? 'unverified';
    }

    // ------------------------------------------------------------------
    // Full offline receipt report (what bin/verify.php and the MCP tool print)
    // ------------------------------------------------------------------

    /**
     * @return array{
     *     core_failures: string[], binding_failures: string[],
     *     legacy: bool, id_state: string, id_verdict: string,
     *     anchor: array{present: bool, evaluated: bool, outcome: string},
     *     verified: bool
     * }
     */
    public static function verifyReceipt(
        mixed $receipt,
        mixed $expectedId = null,
        mixed $resolvedRecord = null
    ): array {
        $core = self::check($receipt);
        [$isLegacy, $binding] = self::checkVersionAndBinding($receipt);
        [$idState, $idFailures] = self::evaluateIdBinding(
            $receipt,
            $expectedId,
            $resolvedRecord
        );
        $tier = self::checkDisinterestedTier($receipt);
        $report = self::anchorReport($receipt, $tier, true);
        $verified = !$core && !$binding && !$idFailures;
        return [
            'core_failures' => $core,
            'binding_failures' => $binding,
            'legacy' => $isLegacy,
            'id_state' => $idState,
            'id_verdict' => self::deriveIdVerdict($receipt, $idState),
            'anchor' => $report,
            'verified' => $verified,
        ];
    }
}
