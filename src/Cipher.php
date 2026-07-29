<?php

declare(strict_types=1);

namespace Dotlock;

use SensitiveParameter;
use SodiumException;

/**
 * The crypto, and nothing else. No files, no environment, no framework.
 *
 * Argon2id turns the passphrase into a key; XSalsa20-Poly1305 (`secretbox`)
 * encrypts with it. Both come from libsodium, so there is nothing here that
 * was invented for this package.
 *
 * Secretbox is authenticated, which is the property the whole design leans on:
 * a wrong passphrase fails the MAC and `open()` returns null. It cannot quietly
 * hand back plausible-looking rubbish, so "is this the right passphrase" and
 * "is this file intact" are the same question and it is answered for free.
 *
 * Every parameter that carries key material is marked `#[SensitiveParameter]`,
 * so a stack trace from anywhere below this class prints `Object(SensitiveParameterValue)`
 * instead of the passphrase. Secrets have a way of ending up in logs otherwise.
 */
final class Cipher
{
    /**
     * Argon2id's interactive parameters: 64MB and one pass, measured at 46ms.
     *
     * This is a deliberate floor rather than the strongest setting available.
     * `.env.secrets` is gitignored and never leaves the machine, so the attack
     * being priced in is a local process reading the file, not somebody running
     * a cracking rig against a leaked copy — and against that, any setting at
     * all is enough. The cost is paid on every unlock, so it buys real time back.
     *
     * The numbers used are written into the file, not read from here, so raising
     * them later is a `secrets:rekey` and not a format change.
     */
    public const int OPS = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;

    public const int MEM = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;

    public const int SALT_BYTES = SODIUM_CRYPTO_PWHASH_SALTBYTES;

    public const int KEY_BYTES = SODIUM_CRYPTO_SECRETBOX_KEYBYTES;

    public const int NONCE_BYTES = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;

    public static function salt(): string
    {
        return random_bytes(self::SALT_BYTES);
    }

    public static function newKey(): string
    {
        return random_bytes(self::KEY_BYTES);
    }

    /**
     * The passphrase, stretched into something a cipher can use.
     */
    public static function deriveKey(
        #[SensitiveParameter] string $passphrase,
        string $salt,
        int $ops,
        int $mem,
    ): string {
        if (strlen($salt) !== self::SALT_BYTES) {
            throw new DotlockException('The secrets file has a salt of the wrong size, so it cannot be opened.');
        }

        if ($ops < 1 || $mem < 8192) {
            throw new DotlockException('The secrets file asks for key settings that are too weak to use.');
        }

        if ($passphrase === '') {
            throw new DotlockException('An empty passphrase is not a passphrase.');
        }

        return sodium_crypto_pwhash(
            self::KEY_BYTES,
            $passphrase,
            $salt,
            $ops,
            $mem,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        );
    }

    /**
     * Encrypt, with a fresh nonce every time.
     *
     * The result is base64, which is what lets an encrypted value sit on one
     * line of a dotenv-shaped file whatever it contains — a newline, a quote,
     * a `#`. Plain `.env` cannot hold a PEM key; this can.
     */
    public static function seal(
        #[SensitiveParameter] string $plaintext,
        #[SensitiveParameter] string $key,
    ): string {
        self::assertKey($key);

        $nonce = random_bytes(self::NONCE_BYTES);

        return base64_encode($nonce.sodium_crypto_secretbox($plaintext, $nonce, $key));
    }

    /**
     * Decrypt, or null if this key does not open this box.
     *
     * Null covers every way it can fail — wrong passphrase, truncated file,
     * something edited by hand — because the caller does the same thing in all
     * of those cases and pretending to tell them apart would be a guess.
     */
    public static function open(string $sealed, #[SensitiveParameter] string $key): ?string
    {
        self::assertKey($key);

        $raw = base64_decode($sealed, true);

        if ($raw === false || strlen($raw) <= self::NONCE_BYTES) {
            return null;
        }

        try {
            $plaintext = sodium_crypto_secretbox_open(
                substr($raw, self::NONCE_BYTES),
                substr($raw, 0, self::NONCE_BYTES),
                $key,
            );
        } catch (SodiumException) {
            return null;
        }

        return $plaintext === false ? null : $plaintext;
    }

    private static function assertKey(#[SensitiveParameter] string $key): void
    {
        if (strlen($key) !== self::KEY_BYTES) {
            throw new DotlockException('A key of the wrong size was handed to the cipher.');
        }
    }
}
