<?php

declare(strict_types=1);

namespace Dotlock;

use SensitiveParameter;

/**
 * The encrypted file, and the only thing allowed to write it.
 *
 * `.env.secrets` is shaped like a dotenv file on purpose — one `NAME="value"`
 * per line — so it stays greppable and a person can see which secrets exist
 * without a tool. Only the values are unreadable.
 *
 * There are two layers of key. The passphrase derives a key that opens one
 * thing: a random master key kept in the header. The master key encrypts the
 * values. That indirection is worth having for one reason — changing the
 * passphrase then rewrites a single line instead of re-encrypting everything,
 * so `secrets:rekey` cannot half-fail across a dozen values.
 *
 * Every write goes to a temporary file, is opened again from disk with the
 * passphrase and checked byte for byte, and only then replaces the real file.
 * The live vault is therefore never the thing being verified: if anything is
 * wrong, the temporary file is what gets thrown away.
 */
final readonly class Vault
{
    public const string META = 'DOTLOCK_META';

    private const string HEADER = '# Dotlock v1. Values are encrypted; do not edit by hand.';

    private const string VERSION = 'v1';

    /**
     * The cost settings apply to vaults this instance creates or rekeys. Opening
     * an existing vault always uses the settings recorded in its own header, so
     * a file made with one setting stays readable after the default changes.
     */
    public function __construct(
        private string $path,
        private int $ops = Cipher::OPS,
        private int $mem = Cipher::MEM,
    ) {}

    public function path(): string
    {
        return $this->path;
    }

    public function exists(): bool
    {
        return is_file($this->path);
    }

    /**
     * The encrypted values, still encrypted, keyed by name.
     *
     * @return array<string, string>
     */
    public function entries(): array
    {
        $lines = $this->parse();

        unset($lines[self::META]);

        return $lines;
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->entries());
    }

    public function isEmpty(): bool
    {
        return $this->entries() === [];
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->entries());
    }

    /**
     * Every secret in the clear, or null when this passphrase is not the one.
     *
     * Null is the answer to a wrong passphrase, which is an ordinary thing for
     * a person to type. A file that opens but holds a value the master key
     * cannot read is a different matter — that is damage, and it is loud.
     *
     * @return array<string, string>|null
     */
    public function open(#[SensitiveParameter] string $passphrase): ?array
    {
        if (! $this->exists()) {
            return null;
        }

        $master = $this->master($passphrase);

        if ($master === null) {
            return null;
        }

        $values = [];

        foreach ($this->entries() as $name => $sealed) {
            $value = Cipher::open($sealed, $master);

            if ($value === null) {
                throw new DotlockException(
                    "The entry for {$name} in {$this->path} is damaged and cannot be read.",
                );
            }

            $values[$name] = $value;
        }

        sodium_memzero($master);

        return $values;
    }

    /**
     * Add or replace one secret.
     *
     * Creates the vault when there is not one yet; otherwise the passphrase has
     * to be the one already in use, checked before anything is written.
     */
    public function put(
        string $name,
        #[SensitiveParameter] string $value,
        #[SensitiveParameter] string $passphrase,
    ): void {
        $this->assertName($name);

        [$meta, $master] = $this->openOrCreate($passphrase);

        $entries = $this->entries();
        $entries[$name] = Cipher::seal($value, $master);

        sodium_memzero($master);

        $this->commit($meta, $entries, $passphrase, [$name => $value]);
    }

    /**
     * Drop one secret. It does not go back to `.env` — that would put the
     * plaintext on disk again, which is the thing this exists to avoid.
     */
    public function forget(string $name, #[SensitiveParameter] string $passphrase): void
    {
        if (! $this->has($name)) {
            throw new DotlockException("There is no secret called {$name}.");
        }

        [$meta, $master] = $this->openOrCreate($passphrase);

        sodium_memzero($master);

        $entries = $this->entries();
        unset($entries[$name]);

        $this->commit($meta, $entries, $passphrase, []);
    }

    /**
     * Change the passphrase. The master key is untouched, so not one encrypted
     * value is rewritten and there is nothing here that can half-succeed.
     */
    public function rekey(
        #[SensitiveParameter] string $current,
        #[SensitiveParameter] string $replacement,
    ): void {
        $master = $this->master($current);

        if ($master === null) {
            throw new DotlockException('That is not the passphrase this vault was locked with.');
        }

        $meta = $this->wrap($master, $replacement);

        sodium_memzero($master);

        $this->commit($meta, $this->entries(), $replacement, []);
    }

    /**
     * The header, decoded: the salt and settings used to stretch the passphrase,
     * and the master key sealed with the result.
     *
     * @return array{salt: string, ops: int, mem: int, wrapped: string}|null
     */
    private function meta(): ?array
    {
        $raw = $this->parse()[self::META] ?? null;

        if (! is_string($raw)) {
            return null;
        }

        $parts = explode(':', $raw);

        if (count($parts) !== 5 || $parts[0] !== self::VERSION) {
            return null;
        }

        [, $salt, $ops, $mem, $wrapped] = $parts;

        $salt = base64_decode($salt, true);

        if ($salt === false || ! ctype_digit($ops) || ! ctype_digit($mem)) {
            return null;
        }

        return ['salt' => $salt, 'ops' => (int) $ops, 'mem' => (int) $mem, 'wrapped' => $wrapped];
    }

    /**
     * Unwrap the master key, or null when the passphrase is wrong.
     */
    private function master(#[SensitiveParameter] string $passphrase): ?string
    {
        $meta = $this->meta();

        // An empty passphrase is answered rather than argued with: it is never
        // the right one, because nothing can be locked with it in the first place.
        if ($meta === null || $passphrase === '') {
            return null;
        }

        $key = Cipher::deriveKey($passphrase, $meta['salt'], $meta['ops'], $meta['mem']);

        $master = Cipher::open($meta['wrapped'], $key);

        sodium_memzero($key);

        return $master;
    }

    /**
     * The master key for a vault that exists, or a brand new one for a vault
     * that does not.
     *
     * @return array{0: string, 1: string} the header line and the master key
     */
    private function openOrCreate(#[SensitiveParameter] string $passphrase): array
    {
        if (! $this->exists()) {
            $master = Cipher::newKey();

            return [$this->wrap($master, $passphrase), $master];
        }

        if ($this->meta() === null) {
            throw new DotlockException(
                "{$this->path} is not a secrets file, or its header has been damaged.",
            );
        }

        $master = $this->master($passphrase);

        if ($master === null) {
            throw new DotlockException('That is not the passphrase this vault was locked with.');
        }

        // The salt and settings are kept as they are. Re-deriving here would
        // change the header on every `secrets:set` for no reason, and a header
        // that churns is a header nobody notices going wrong.
        $meta = $this->meta();

        return [$this->line($meta['salt'], $meta['ops'], $meta['mem'], $meta['wrapped']), $master];
    }

    private function wrap(#[SensitiveParameter] string $master, #[SensitiveParameter] string $passphrase): string
    {
        $salt = Cipher::salt();

        $key = Cipher::deriveKey($passphrase, $salt, $this->ops, $this->mem);

        $wrapped = Cipher::seal($master, $key);

        sodium_memzero($key);

        return $this->line($salt, $this->ops, $this->mem, $wrapped);
    }

    private function line(string $salt, int $ops, int $mem, string $wrapped): string
    {
        // The settings stay as plain numbers rather than being packed into the
        // blob, so you can look at a vault and see what it costs to open.
        return implode(':', [self::VERSION, base64_encode($salt), $ops, $mem, $wrapped]);
    }

    /**
     * Write, verify what was written, and only then let it become the real file.
     *
     * The check re-opens the temporary file with the passphrase rather than
     * reusing the master key already in hand. That is a second key derivation
     * and it is the point: it proves the whole chain — header, wrapping, every
     * value — works from nothing but the passphrase, which is all the next
     * process will have.
     *
     * @param  array<string, string>  $entries
     * @param  array<string, string>  $expected  plaintext that must survive the round trip
     */
    private function commit(
        string $meta,
        array $entries,
        #[SensitiveParameter] string $passphrase,
        array $expected,
    ): void {
        ksort($entries);

        $content = self::HEADER."\n".self::META.'="'.$meta."\"\n";

        foreach ($entries as $name => $sealed) {
            $content .= $name.'="'.$sealed."\"\n";
        }

        $temporary = $this->path.'.'.bin2hex(random_bytes(6)).'.tmp';

        // Opened exclusively and locked down before a single byte goes in, so
        // there is no moment where the file exists and is world readable.
        $handle = @fopen($temporary, 'x');

        if ($handle === false) {
            throw new DotlockException("Could not write next to {$this->path}.");
        }

        @chmod($temporary, 0600);
        fwrite($handle, $content);
        fclose($handle);

        try {
            $this->verify($temporary, $passphrase, $entries, $expected);
        } catch (DotlockException $failure) {
            @unlink($temporary);

            throw $failure;
        }

        if (! @rename($temporary, $this->path)) {
            @unlink($temporary);

            throw new DotlockException("Could not replace {$this->path}.");
        }

        @chmod($this->path, 0600);
    }

    /**
     * @param  array<string, string>  $entries
     * @param  array<string, string>  $expected
     */
    private function verify(
        string $temporary,
        #[SensitiveParameter] string $passphrase,
        array $entries,
        array $expected,
    ): void {
        $written = new self($temporary, $this->ops, $this->mem)->open($passphrase);

        if ($written === null) {
            throw new DotlockException('The file that was just written cannot be opened again. Nothing was changed.');
        }

        if (array_keys($written) !== array_keys($entries)) {
            throw new DotlockException('The file that was just written lost or gained a secret. Nothing was changed.');
        }

        foreach ($expected as $name => $value) {
            if (! hash_equals($value, $written[$name] ?? '')) {
                throw new DotlockException("{$name} did not survive being written. Nothing was changed.");
            }
        }
    }

    /**
     * @return array<string, string>
     */
    private function parse(): array
    {
        if (! $this->exists()) {
            return [];
        }

        $contents = @file_get_contents($this->path);

        if ($contents === false) {
            throw new DotlockException("{$this->path} exists but could not be read.");
        }

        $values = [];

        foreach (preg_split('/\R/', $contents) ?: [] as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            if (! preg_match('/^([A-Za-z_]\w*)=(.*)$/', $line, $matches)) {
                continue;
            }

            $value = trim($matches[2]);

            if (strlen($value) >= 2 && str_starts_with($value, '"') && str_ends_with($value, '"')) {
                $value = substr($value, 1, -1);
            }

            $values[$matches[1]] = $value;
        }

        return $values;
    }

    private function assertName(string $name): void
    {
        if ($name === self::META) {
            throw new DotlockException(self::META." is the vault's own header and cannot be used as a name.");
        }

        if (! preg_match('/^[A-Za-z_]\w*$/', $name)) {
            throw new DotlockException("{$name} is not a usable environment variable name.");
        }
    }
}
