# Dotlock

Encrypted secrets for local Laravel development.

[![CI](https://img.shields.io/github/actions/workflow/status/mnapoli/dotlock/ci.yml?style=flat-square&label=CI)](https://github.com/mnapoli/dotlock/actions)
[![Latest Version](https://img.shields.io/packagist/v/mnapoli/dotlock.svg?style=flat-square)](https://packagist.org/packages/mnapoli/dotlock)
[![Total Downloads](https://img.shields.io/packagist/dt/mnapoli/dotlock.svg?style=flat-square)](https://packagist.org/packages/mnapoli/dotlock)

Your OpenAI key, your Stripe test key, that IMAP password — they sit in `.env` in plain text. Every process on your machine can read them: a stray `cat`, an npm install script, a coding agent grepping the project. Dotlock moves them to `.env.secrets`, a file that still looks like dotenv — the names stay readable, only the values are encrypted:

```dotenv
# Dotlock v1. Values are encrypted; do not edit by hand.
DOTLOCK_META="v1:hz1yIu0…"
OPENAI_API_KEY="mvGOEc0Vf1Xh0…"
STRIPE_SECRET="Tir/AHfuTgKoS…"
```

The secrets load back into the environment at boot, before Laravel builds its config, so `env()`, `config()` and everything downstream work exactly as before. Nothing else in the application changes.

One rule governs everything: **locked means unset**. No passphrase, wrong passphrase, damaged file — the variables are simply absent, exactly as if they were never configured. Nothing prompts at boot, nothing blocks, nothing throws. A cron job can't hang on a question; a missing token fails the way it always failed.

## Install

```sh
composer require --dev mnapoli/dotlock
```

Add one line at the top of `bootstrap/app.php`, before `Application::configure()`:

```php
// Load encrypted secrets into the environment, before config is built.
// Does nothing unless APP_SECRETS_KEY is set and `.env.secrets` exists.
if (class_exists(\Dotlock\Secrets::class)) {
    \Dotlock\Secrets::unlock(dirname(__DIR__));
}
```

It has to live there: `config/services.php` reads `env()` while Laravel boots, and a service provider runs too late to matter. `bootstrap/app.php` is the one file both `public/index.php` and `artisan` pass through in time. The `class_exists` guard is what lets the package stay in `require-dev`.

Then add the file to `.gitignore`:

```
.env.secrets
```

The values are encrypted, but a secrets file in git history is still a file you can never take back.

## Usage

Move a secret out of `.env`:

```sh
php artisan secrets:set
```

It offers the names from `.env` and the names already encrypted, asks which value to take, and asks for a passphrase (created on first use). The vault is written and proven readable *before* the `.env` line is replaced with a note saying where the value went — the worst possible outcome is the secret existing in both places, never in neither.

Start working:

```sh
php artisan dev
```

`dev` asks for the passphrase once, then hands the decrypted values — not the passphrase — to everything it starts: the server, the queue worker, vite. This is the only command that ever prompts.

The rest:

| Command | What it does |
|-|-|
| `secrets:list` | The names, without asking for anything |
| `secrets:get NAME` | One value, masked; `--show` prints it in the clear |
| `secrets:forget NAME` | Removes it for good — it is not written back to `.env` |
| `secrets:rekey` | Changes the passphrase without rewriting a single value |

For non-interactive use — scripts, a shell you trust — export the passphrase and every artisan command and request unlocks silently:

```sh
export APP_SECRETS_KEY="your passphrase"
```

Read it from your password manager rather than typing it into shell history, e.g. with 1Password:

```sh
export APP_SECRETS_KEY="$(op read op://Private/my-app/passphrase)"
```

## What it refuses to do

**`config:cache` and `optimize` fail while a vault exists.** Caching config resolves every `env()` call and writes the answers to `bootstrap/cache/config.php` in plain text. Unlocked, that puts your secrets on disk in the clear — in a file nobody thinks to check. Locked, it freezes them as `null` forever. Neither is allowed to happen by accident. This is a local-development tool; production config caching belongs to real environment variables.

**Tests never unlock.** When `APP_ENV` is `testing`, the vault stays shut even with the right passphrase in the environment. Real credentials have no business in a process whose entire job is to fake things.

## How it works

- The passphrase is stretched with **Argon2id** into a key that opens one thing: a random **master key** kept encrypted in the file's header. The master key encrypts the values with **XSalsa20-Poly1305** (libsodium's `secretbox`). Changing the passphrase rewrites one line, not every value.
- Encryption is authenticated, so a wrong passphrase and a corrupted file are detected outright — the vault can never hand back plausible-looking garbage.
- Every write goes to a temporary file first, is re-opened from disk using only the passphrase, and checked value by value. Only then does it replace the real file. A failed write changes nothing.
- Values are base64 on one line whatever they contain, so the vault holds things `.env` never could — a multi-line PEM key, a value with quotes or `#` in it.
- The file is `chmod 0600`, and the passphrase is never stored anywhere. There is no recovery: a secret whose passphrase is lost is lost with it.

## Why not a password manager?

Keep using one — for the passphrase. The difference is who does the reading: a password manager is where a *person* keeps secrets, the vault is what a *process* reads on every boot. Fetching from 1Password or the Keychain at boot would mean prompts and latency on every request, and covering only the processes you remembered to wrap. Dotlock loads inside PHP at bootstrap, so `artisan tinker`, a test runner started from your IDE, and a queue worker all get the same environment — instantly, offline.

## Requirements

- PHP 8.4+ with the sodium extension (bundled by default)
- Laravel 13

## License

MIT
