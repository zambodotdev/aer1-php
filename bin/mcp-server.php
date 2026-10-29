<?php
declare(strict_types=1);

/**
 * Entry point for the AER-1 MCP server (stdio transport).
 *
 * Run: php bin/mcp-server.php
 * Point any MCP client at that command and the two verification
 * tools appear in its tool list.
 */

require __DIR__ . '/../src/bootstrap.php';
require __DIR__ . '/../src/McpServer.php';

(new Aer1Php\McpServer())->run();
