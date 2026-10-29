# AER-1 for PHP

A PHP verifier for AER-1 receipts and workflow receipts, built for the
Symfony AI and MCP Hackathon. It is the missing language runner for
AER-1: the reference kit ships conformant runners in several
languages, and until now none of them was PHP.

Zambo is the verifiable work layer for AI. When an agent finishes a
job, Zambo issues an AER-1 receipt for it: a small JSON record that
commits to the exact bytes of the saved result. Anyone holding the
receipt can check, offline, that the saved result was not changed
since it was saved. That is all a receipt proves, and it is the thing
worth proving: "done" becomes something you can check, not something
you have to trust.

The standard is AER-1, published as the IETF Internet-Draft
draft-zambo-aer1-26. The public conformance corpus (126 vectors,
129 checks, kit v1.5.7) is the test that decides whether a verifier
is conformant. Earlier third-party PHP attempts were checked against
it and were not conformant. This one is, and the corpus is bundled
here so you can re-run the test yourself.

## Five-minute start

You need a PHP 8.1+ CLI and nothing else. No Composer install, no
dependencies.

```bash
git clone <this repo> aer1-php
cd aer1-php

# The full conformance corpus:
php bin/conformance.php

# The ninety-second demo:
php demo/demo.php

# Verify one receipt or workflow receipt:
php bin/verify.php path/to/receipt.json
```

A green corpus run ends with:

```
CONFORMANCE OK: 126 vectors, 129 checks, sha256:ccaff18aba8f4e70aacf8a469403e9a6f12f025ad39df88079398bbe13100ce8
```

That digest is the published evaluated-set digest of the corpus.
The runner hash-checks every corpus file against the published
record (corpus/corpus.json) before evaluating it, and prints the
exact set of vectors it evaluated, so a pass here is a pass over the
same bytes everyone else tests against.

## Measured results

Measured on 2026-10-29 with PHP 8.4.13 (CLI) on Linux:

- 126 vectors, 129 checks: all pass.
- The evaluated-set digest computed by this runner equals the
  published digest, sha256:ccaff18aba8f4e70aacf8a469403e9a6f12f025ad39df88079398bbe13100ce8.
- The runner's full output is byte-identical to the reference
  Python runner's output over the same corpus: same verdicts, same
  rejection reasons, same per-vector evaluated-set lines.

## The MCP server: check the job before you believe it

bin/mcp-server.php exposes verification as two MCP tools over
stdio, so an agent (or the person reviewing its work) can check a
receipt inside the session where the work happened:

- aer1_verify_receipt: the full offline receipt report.
- aer1_verify_workflow: the workflow receipt check.

Point any MCP client at the command `php bin/mcp-server.php` and
the tools appear in its tool list. The server is a small
dependency-free JSON-RPC implementation of the MCP stdio shape so
the demo runs anywhere PHP runs. In a Symfony application, the same
two handlers sit behind the official PHP MCP SDK (mcp/sdk) tool
attributes unchanged: verification itself is two static calls on
the Aer1 class, with no transport code inside it.

The demo (demo/demo.php) shows the shape of the idea: a receipt
verifies; the same receipt with one hex digit of its output hash
changed does not; a three-step workflow verifies; the same workflow
with one step's receipt_id repeated does not, because one receipt
cannot stand for two steps.

## What the verifier checks

Receipts (draft Sections 3 to 6):

- member shape and required members, with the legacy production
  shapes of schema 0.2 and 0.3 accepted under the legacy rules;
- id shape (the nil UUID is rejected), RFC 3339 creation time with
  real calendar validation and leap-second rejection;
- the output commitment: SHA-256 over the exact canonical bytes,
  with canonical base64 spelling required and invalid UTF-8
  rejected;
- the optional input commitment, evaluated when the payload records
  its inputs, against the Section 7.1 canonical JSON of those
  inputs;
- version agreement and provenance binding between the envelope and
  the committed payload;
- duplicate member names anywhere in the receipt JSON, rejected at
  parse time;
- the reference-producer profile boundary: receipts that omit the
  inputs member stay core-conformant and fail only the profile.

Anchors (Section 6, step 5): the disinterested-tier anchor profile,
plus the per-anchor outcome report that keeps three states apart:
absent, not checked, and the evaluated outcomes (verified,
verification failed, rejected: unresolvable record).

Chains (Section 7): the original chain construction, the hardened
-07 construction that binds sequence, job, and metadata into each
entry digest, and the external chain commitment that binds a
timeline's length and final entry digest.

Workflows (Section 8): member shape for the workflow receipt and
its steps, step sequence with no gaps, the MM-1 rule (no two steps
share a receipt_id), and the Merkle root, recomputed under both
published rules:

- receipt-id-v0, the legacy rule: leaves are the receipt_id strings;
- seq-output-v1, the current rule: leaves are "seq:output_hash"
  pairs, so the root binds each step's position and output.

Unicode (Section 4): payloads are hashed as the exact bytes they
are. No normalization is applied, ever: the NFC and NFD forms of
the same visible string are different payloads with different
digests, and a verifier that normalizes would report agreement
where there is none.

Id binding (Sections 6 and 13): the receipt id is a label outside
the committed payload, so the verifier reports its state honestly:
unverified with no external expectation, matched against a supplied
expected id, resolved against the record the id resolves to, or
mismatched.

Verification here is the offline part of the draft's procedure.
Fetching each workflow step's receipt over the network (Section
8.2, steps 1 and 2) stays the caller's job, exactly as the draft
assigns it.

## Layout

```
src/Json.php          strict JSON parser (duplicate-name detection)
                      plus the Section 7.1 canonical JSON encoder
src/Aer1.php          the verifier library (all checks above)
src/McpServer.php     the MCP stdio server
bin/conformance.php   the corpus harness
bin/verify.php        one-artifact verification CLI
bin/mcp-server.php    MCP server entry point
demo/demo.php         the ninety-second demo
corpus/               the published corpus, byte for byte:
                      corpus.json (the record), base/ (the base
                      corpus), workflow-merkle-seq-output-v1.json
```

## Links

- The draft: https://datatracker.ietf.org/doc/draft-zambo-aer1/26/
- The corpus record: https://zambo.dev/aer1/corpus.json
- Zambo: https://zambo.dev

## License

MIT. See LICENSE. The corpus under corpus/ is the published AER-1
conformance corpus and ships under the same license file, whose
digest is recorded in the corpus record itself.
