<?php
declare(strict_types=1);

namespace Aer1Php;

/**
 * A small MCP server over stdio that exposes AER-1 verification as
 * two tools, so an agent can check a finished job's receipt before
 * anyone believes the job is done:
 *
 *   aer1_verify_receipt   full offline receipt report
 *   aer1_verify_workflow  workflow receipt check (Section 8.2 steps 3-4)
 *
 * It speaks JSON-RPC 2.0 with newline-delimited messages, the MCP
 * stdio transport shape, and has no dependencies beyond this
 * package. In a Symfony app the same two handlers drop behind the
 * official PHP MCP SDK (mcp/sdk) tool attributes unchanged: the
 * verification calls are plain static methods on Aer1.
 */
final class McpServer
{
    public function run(): void
    {
        while (($line = fgets(STDIN)) !== false) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            try {
                $request = (new JsonParser())->parse($line);
            } catch (\RuntimeException) {
                continue;
            }
            if (!$request instanceof JObject) {
                continue;
            }
            $response = $this->handle($request);
            if ($response !== null) {
                fwrite(STDOUT, json_encode($response, JSON_UNESCAPED_SLASHES) . "\n");
                fflush(STDOUT);
            }
        }
    }

    private function handle(JObject $request): ?array
    {
        $method = $request->get('method');
        $id = $request->get('id');
        $params = $request->get('params');
        switch ($method) {
            case 'initialize':
                return $this->reply($id, [
                    'protocolVersion' => '2024-11-05',
                    'capabilities' => ['tools' => new \stdClass()],
                    'serverInfo' => ['name' => 'aer1-php', 'version' => '1.0.0'],
                ]);
            case 'ping':
                return $this->reply($id, new \stdClass());
            case 'tools/list':
                return $this->reply($id, ['tools' => $this->tools()]);
            case 'tools/call':
                $name = $params instanceof JObject ? $params->get('name') : null;
                $args = $params instanceof JObject ? $params->get('arguments') : null;
                return $this->reply($id, $this->callTool($name, $args));
            default:
                // Notifications (no id) and unknown methods: no reply.
                return null;
        }
    }

    private function reply(mixed $id, mixed $result): ?array
    {
        if ($id === null) {
            return null;
        }
        return ['jsonrpc' => '2.0', 'id' => $id, 'result' => $result];
    }

    private function tools(): array
    {
        return [
            [
                'name' => 'aer1_verify_receipt',
                'description' => 'Verify an AER-1 receipt offline: core '
                    . 'commitment check, version and provenance binding, '
                    . 'id binding state, and the per-anchor outcome '
                    . 'report. A verified receipt proves the saved '
                    . 'result was not changed since it was saved.',
                'inputSchema' => [
                    'type' => 'object',
                    'properties' => [
                        'receipt' => ['type' => 'object'],
                        'expected_id' => ['type' => 'string'],
                    ],
                    'required' => ['receipt'],
                ],
            ],
            [
                'name' => 'aer1_verify_workflow',
                'description' => 'Verify an AER-1 workflow receipt '
                    . 'offline (Section 8.2 steps 3-4): member shape, '
                    . 'step sequence, the no-duplicate-receipt_id rule, '
                    . 'and the recomputed Merkle root over the steps.',
                'inputSchema' => [
                    'type' => 'object',
                    'properties' => [
                        'workflow' => ['type' => 'object'],
                    ],
                    'required' => ['workflow'],
                ],
            ],
        ];
    }

    private function callTool(mixed $name, mixed $args): array
    {
        if (!$args instanceof JObject) {
            $args = new JObject();
        }
        if ($name === 'aer1_verify_receipt') {
            $report = Aer1::verifyReceipt(
                $args->get('receipt'),
                $args->get('expected_id')
            );
            $lines = [];
            $lines[] = $report['verified'] ? 'verified' : 'verification failed';
            foreach (array_merge($report['core_failures'], $report['binding_failures']) as $f) {
                $lines[] = " - $f";
            }
            if ($report['legacy']) {
                $lines[] = 'legacy notice: pre-binding envelope, accepted under the legacy rules';
            }
            $lines[] = "id: {$report['id_state']} ({$report['id_verdict']})";
            $anchor = $report['anchor'];
            $lines[] = 'anchor: ' . ($anchor['present'] ? $anchor['outcome'] : 'absent');
            return $this->toolResult(implode("\n", $lines), !$report['verified']);
        }
        if ($name === 'aer1_verify_workflow') {
            $fails = Aer1::verifyWorkflow($args->get('workflow'));
            $text = $fails
                ? "workflow verification failed:\n - " . implode("\n - ", $fails)
                : 'workflow verified';
            return $this->toolResult($text, (bool) $fails);
        }
        return $this->toolResult("unknown tool: $name", true);
    }

    private function toolResult(string $text, bool $isError): array
    {
        return [
            'content' => [['type' => 'text', 'text' => $text]],
            'isError' => $isError,
        ];
    }
}
