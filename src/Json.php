<?php
declare(strict_types=1);

namespace Aer1Php;

/**
 * Minimal JSON support tuned to the AER-1 verifier's needs.
 *
 * PHP's json_decode() cannot report duplicate member names, and draft
 * Section 6 requires a verifier to reject a receipt whose JSON text
 * carries a duplicate member name in any object. This parser therefore
 * decodes JSON itself: objects become JObject (an ordered pair list,
 * last value wins, exactly like the Python reference runner's
 * object_pairs_hook + dict()), and the first duplicate member name
 * found in the document is recorded.
 *
 * The canonical encoder produces the Section 7.1 canonical JSON bytes
 * the Python and JavaScript reference runners produce: member names
 * sorted by Unicode code point, no whitespace, ASCII escaping
 * (json.dumps defaults). Two variants exist because the reference
 * runner itself has two: canonicalJsonBytes() normalizes
 * integer-valued floats to integers; canonicalJsonPlain() does not.
 */
final class JObject
{
    /** @var array<int, array{0: string, 1: mixed}> */
    public array $pairs = [];

    public function has(string $key): bool
    {
        foreach ($this->pairs as $p) {
            if ($p[0] === $key) {
                return true;
            }
        }
        return false;
    }

    public function get(string $key): mixed
    {
        $value = null;
        foreach ($this->pairs as $p) {
            if ($p[0] === $key) {
                $value = $p[1];
            }
        }
        return $value;
    }

    /** @return string[] member names in document order (duplicates kept) */
    public function keys(): array
    {
        return array_map(static fn ($p) => $p[0], $this->pairs);
    }

    public function set(string $key, mixed $value): void
    {
        $this->pairs[] = [$key, $value];
    }
}

final class JsonParser
{
    /** First duplicate member name found in the parsed document. */
    public ?string $firstDuplicate = null;

    private string $text;
    private int $len;
    private int $pos = 0;

    /**
     * Parse JSON text like Python's json.loads (strict). Returns
     * JObject for objects, PHP arrays for arrays, and PHP scalars.
     *
     * @throws \RuntimeException on malformed input.
     */
    public function parse(string $text): mixed
    {
        $this->text = $text;
        $this->len = strlen($text);
        $this->pos = 0;
        $this->firstDuplicate = null;
        $value = $this->parseValue();
        $this->skipWs();
        if ($this->pos !== $this->len) {
            throw new \RuntimeException('trailing data after JSON value');
        }
        return $value;
    }

    private function skipWs(): void
    {
        while ($this->pos < $this->len) {
            $c = $this->text[$this->pos];
            if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") {
                $this->pos++;
            } else {
                break;
            }
        }
    }

    private function parseValue(): mixed
    {
        $this->skipWs();
        if ($this->pos >= $this->len) {
            throw new \RuntimeException('unexpected end of input');
        }
        $c = $this->text[$this->pos];
        return match (true) {
            $c === '{' => $this->parseObject(),
            $c === '[' => $this->parseArray(),
            $c === '"' => $this->parseString(),
            $c === 't' => $this->parseLiteral('true', true),
            $c === 'f' => $this->parseLiteral('false', false),
            $c === 'n' => $this->parseLiteral('null', null),
            default => $this->parseNumber(),
        };
    }

    private function parseLiteral(string $word, mixed $value): mixed
    {
        if (substr($this->text, $this->pos, strlen($word)) !== $word) {
            throw new \RuntimeException('invalid literal');
        }
        $this->pos += strlen($word);
        return $value;
    }

    private function parseObject(): JObject
    {
        $obj = new JObject();
        $this->pos++; // {
        $this->skipWs();
        if ($this->pos < $this->len && $this->text[$this->pos] === '}') {
            $this->pos++;
            return $obj;
        }
        while (true) {
            $this->skipWs();
            if ($this->pos >= $this->len || $this->text[$this->pos] !== '"') {
                throw new \RuntimeException('object key is not a string');
            }
            $key = $this->parseString();
            $this->skipWs();
            if ($this->pos >= $this->len || $this->text[$this->pos] !== ':') {
                throw new \RuntimeException('expected : in object');
            }
            $this->pos++;
            $obj->set($key, $this->parseValue());
            $this->skipWs();
            if ($this->pos >= $this->len) {
                throw new \RuntimeException('unterminated object');
            }
            $c = $this->text[$this->pos];
            if ($c === ',') {
                $this->pos++;
                continue;
            }
            if ($c === '}') {
                $this->pos++;
                break;
            }
            throw new \RuntimeException('expected , or } in object');
        }
        // Duplicate scan at object completion, innermost first, the
        // same order Python's object_pairs_hook observes.
        if ($this->firstDuplicate === null) {
            $seen = [];
            foreach ($obj->pairs as $p) {
                if (isset($seen[$p[0]])) {
                    $this->firstDuplicate = $p[0];
                    break;
                }
                $seen[$p[0]] = true;
            }
        }
        return $obj;
    }

    private function parseArray(): array
    {
        $list = [];
        $this->pos++; // [
        $this->skipWs();
        if ($this->pos < $this->len && $this->text[$this->pos] === ']') {
            $this->pos++;
            return $list;
        }
        while (true) {
            $list[] = $this->parseValue();
            $this->skipWs();
            if ($this->pos >= $this->len) {
                throw new \RuntimeException('unterminated array');
            }
            $c = $this->text[$this->pos];
            if ($c === ',') {
                $this->pos++;
                continue;
            }
            if ($c === ']') {
                $this->pos++;
                break;
            }
            throw new \RuntimeException('expected , or ] in array');
        }
        return $list;
    }

    private function parseString(): string
    {
        $out = '';
        $this->pos++; // opening quote
        while ($this->pos < $this->len) {
            $c = $this->text[$this->pos];
            $ord = ord($c);
            if ($c === '"') {
                $this->pos++;
                return $out;
            }
            if ($c === '\\') {
                $this->pos++;
                if ($this->pos >= $this->len) {
                    break;
                }
                $e = $this->text[$this->pos];
                $this->pos++;
                switch ($e) {
                    case '"': $out .= '"'; break;
                    case '\\': $out .= '\\'; break;
                    case '/': $out .= '/'; break;
                    case 'b': $out .= "\x08"; break;
                    case 'f': $out .= "\x0c"; break;
                    case 'n': $out .= "\n"; break;
                    case 'r': $out .= "\r"; break;
                    case 't': $out .= "\t"; break;
                    case 'u':
                        $cp = $this->parseHex4();
                        if ($cp >= 0xD800 && $cp <= 0xDBFF
                            && $this->pos + 1 < $this->len
                            && $this->text[$this->pos] === '\\'
                            && $this->text[$this->pos + 1] === 'u'
                        ) {
                            $save = $this->pos;
                            $this->pos += 2;
                            $lo = $this->parseHex4();
                            if ($lo >= 0xDC00 && $lo <= 0xDFFF) {
                                $cp = 0x10000 + (($cp - 0xD800) << 10)
                                    + ($lo - 0xDC00);
                            } else {
                                $this->pos = $save;
                            }
                        }
                        $out .= self::encodeUtf8($cp);
                        break;
                    default:
                        throw new \RuntimeException('invalid escape');
                }
                continue;
            }
            if ($ord < 0x20) {
                throw new \RuntimeException('unescaped control character in string');
            }
            $out .= $c;
            $this->pos++;
        }
        throw new \RuntimeException('unterminated string');
    }

    private function parseHex4(): int
    {
        if ($this->pos + 4 > $this->len) {
            throw new \RuntimeException('short \\u escape');
        }
        $hex = substr($this->text, $this->pos, 4);
        if (!ctype_xdigit($hex)) {
            throw new \RuntimeException('invalid \\u escape');
        }
        $this->pos += 4;
        return (int) hexdec($hex);
    }

    private function parseNumber(): mixed
    {
        $start = $this->pos;
        if ($this->pos < $this->len && $this->text[$this->pos] === '-') {
            $this->pos++;
        }
        while ($this->pos < $this->len
            && str_contains('0123456789+-.eE', $this->text[$this->pos])) {
            $this->pos++;
        }
        $token = substr($this->text, $start, $this->pos - $start);
        if (!preg_match('/^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/', $token)) {
            throw new \RuntimeException('invalid number');
        }
        if (!str_contains($token, '.') && !str_contains($token, 'e')
            && !str_contains($token, 'E')) {
            // Integer token: keep as int when it fits, as Python would
            // compare equal either way for the sizes JSON fixtures use.
            $int = filter_var($token, FILTER_VALIDATE_INT);
            if ($int !== false) {
                return $int;
            }
        }
        return (float) $token;
    }

    public static function encodeUtf8(int $cp): string
    {
        if ($cp < 0x80) {
            return chr($cp);
        }
        if ($cp < 0x800) {
            return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp < 0x10000) {
            return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F))
                . chr(0x80 | ($cp & 0x3F));
        }
        return chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F))
            . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
    }

    /** Decode the UTF-8 string into a list of code points. */
    public static function codePoints(string $s): array
    {
        $cps = [];
        $n = strlen($s);
        for ($i = 0; $i < $n;) {
            $b = ord($s[$i]);
            if ($b < 0x80) {
                $cps[] = $b;
                $i += 1;
            } elseif (($b & 0xE0) === 0xC0 && $i + 1 < $n) {
                $cps[] = (($b & 0x1F) << 6) | (ord($s[$i + 1]) & 0x3F);
                $i += 2;
            } elseif (($b & 0xF0) === 0xE0 && $i + 2 < $n) {
                $cps[] = (($b & 0x0F) << 12) | ((ord($s[$i + 1]) & 0x3F) << 6)
                    | (ord($s[$i + 2]) & 0x3F);
                $i += 3;
            } elseif (($b & 0xF8) === 0xF0 && $i + 3 < $n) {
                $cps[] = (($b & 0x07) << 18) | ((ord($s[$i + 1]) & 0x3F) << 12)
                    | ((ord($s[$i + 2]) & 0x3F) << 6) | (ord($s[$i + 3]) & 0x3F);
                $i += 4;
            } else {
                // Invalid byte: pass it through as its own value so
                // escaping stays byte-faithful.
                $cps[] = $b;
                $i += 1;
            }
        }
        return $cps;
    }
}

final class CanonicalJson
{
    /**
     * Section 7.1 canonical JSON: sorted member names, no whitespace,
     * ASCII escaping. With $normalize, integer-valued floats serialize
     * as integers (the _canonical_json_bytes variant in the Python
     * runner); without it they keep their float spelling (the variant
     * used for the input commitment and the chain entry digest).
     */
    public static function encode(mixed $value, bool $normalize): string
    {
        if ($value === null) {
            return 'null';
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_int($value)) {
            return (string) $value;
        }
        if (is_float($value)) {
            if ($normalize && floor($value) === $value
                && abs($value) < 9007199254740992.0) {
                return (string) (int) $value;
            }
            return self::floatString($value);
        }
        if (is_string($value)) {
            return self::quoteAscii($value);
        }
        if (is_array($value)) {
            $parts = [];
            foreach ($value as $item) {
                $parts[] = self::encode($item, $normalize);
            }
            return '[' . implode(',', $parts) . ']';
        }
        if ($value instanceof JObject) {
            // Sort member names by Unicode code point. UTF-8 byte
            // order is code point order, so strcmp is exact. Last
            // value wins for a repeated name, as in a parsed dict.
            $map = [];
            foreach ($value->pairs as $p) {
                $map[$p[0]] = $p[1];
            }
            $keys = array_keys($map);
            usort($keys, static fn ($a, $b) => strcmp((string) $a, (string) $b));
            $parts = [];
            foreach ($keys as $k) {
                $parts[] = self::quoteAscii((string) $k) . ':'
                    . self::encode($map[$k], $normalize);
            }
            return '{' . implode(',', $parts) . '}';
        }
        throw new \RuntimeException('cannot canonicalize value');
    }

    /** json.dumps-style float rendering (shortest round trip). */
    public static function floatString(float $f): string
    {
        if (is_nan($f) || is_infinite($f)) {
            throw new \RuntimeException('non-finite number');
        }
        if (floor($f) === $f && abs($f) < 1e16) {
            // Python renders 1.0 as "1.0" in plain json.dumps.
            return number_format($f, 1, '.', '');
        }
        $s = json_encode($f);
        if ($s === false) {
            throw new \RuntimeException('float encode failed');
        }
        return $s;
    }

    /** JSON string escaping with ensure_ascii semantics. */
    public static function quoteAscii(string $s): string
    {
        $out = '"';
        foreach (JsonParser::codePoints($s) as $cp) {
            $out .= match (true) {
                $cp === 0x22 => '\\"',
                $cp === 0x5C => '\\\\',
                $cp === 0x08 => '\\b',
                $cp === 0x09 => '\\t',
                $cp === 0x0A => '\\n',
                $cp === 0x0C => '\\f',
                $cp === 0x0D => '\\r',
                $cp < 0x20 || $cp > 0x7E => self::unicodeEscape($cp),
                default => chr($cp),
            };
        }
        return $out . '"';
    }

    /**
     * JSON string escaping the way JSON.stringify renders it (the
     * _json_quote variant in the Python runner): double quotes,
     * non-ASCII characters left as raw UTF-8.
     */
    public static function quoteRaw(string $s): string
    {
        $out = '"';
        $n = strlen($s);
        for ($i = 0; $i < $n; $i++) {
            $c = $s[$i];
            $ord = ord($c);
            $out .= match (true) {
                $c === '"' => '\\"',
                $c === '\\' => '\\\\',
                $c === "\x08" => '\\b',
                $c === "\x09" => '\\t',
                $c === "\x0A" => '\\n',
                $c === "\x0C" => '\\f',
                $c === "\x0D" => '\\r',
                $ord < 0x20 => sprintf('\\u%04x', $ord),
                default => $c,
            };
        }
        return $out . '"';
    }

    /** Render a value the way _json_quote does in the Python runner. */
    public static function jsonQuote(mixed $value): string
    {
        if ($value === null) {
            return 'null';
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_int($value)) {
            return (string) $value;
        }
        if (is_float($value)) {
            return self::floatString($value);
        }
        if (is_string($value)) {
            return self::quoteRaw($value);
        }
        return self::encode($value, false);
    }

    private static function unicodeEscape(int $cp): string
    {
        if ($cp < 0x10000) {
            return sprintf('\\u%04x', $cp);
        }
        $v = $cp - 0x10000;
        return sprintf('\\u%04x\\u%04x', 0xD800 + ($v >> 10), 0xDC00 + ($v & 0x3FF));
    }
}
