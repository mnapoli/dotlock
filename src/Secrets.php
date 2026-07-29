<?php

declare(strict_types=1);

namespace Dotlock;

use SensitiveParameter;
use Throwable;

/**
 * The way in. Called from `bootstrap/app.php` before anything else exists.
 *
 * It has to run there because it has to run early: `LoadEnvironmentVariables`
 * comes before `LoadConfiguration`, and `config/services.php` reads `env()` at
 * that point. By the time a service provider could act, config has been built
 * and the tokens are already missing from it. Both `public/index.php` and
 * `artisan` require the autoloader and then `bootstrap/app.php`, so that file
 * is the one place both paths pass through in time.
 *
 * Which means no container, no facades, no helpers. Plain PHP only.
 *
 * ------------------------------------------------------------------
 * Locked means unset.
 * ------------------------------------------------------------------
 *
 * No passphrase, no file, a damaged file, the wrong passphrase — every one of
 * them ends the same way: the variables are simply not there, exactly as if
 * they had never been configured. Nothing here prompts, blocks or throws.
 *
 * That is the whole design, and it is worth being stubborn about. A boot path
 * that can ask a question hangs forever under cron; one that can throw takes
 * the application down over a file that is, by definition, optional. Something
 * that needed the token fails the way it already failed before any of this
 * existed, which is a failure the app knows how to talk about.
 */
final class Secrets
{
    /**
     * The passphrase, read from the real process environment.
     *
     * Never from `.env` — a passphrase in the file it protects would be a
     * lock with its key taped to the door.
     */
    public const string KEY = 'APP_SECRETS_KEY';

    public const string FILE = '.env.secrets';

    /** @var list<string> */
    private static array $loaded = [];

    /**
     * Put every secret into the environment, or quietly do nothing.
     *
     * This is what `bootstrap/app.php` calls, and it is the guarded form: a
     * test run never opens the vault. See `isTestRun()` for why that is a rule
     * rather than a convenience.
     */
    public static function unlock(string $basePath): void
    {
        if (self::isTestRun()) {
            return;
        }

        self::load($basePath);
    }

    /**
     * The unlocking itself, with no opinion about where it is being run.
     */
    public static function load(string $basePath): void
    {
        try {
            $passphrase = self::environment(self::KEY);

            if ($passphrase === null || $passphrase === '') {
                return;
            }

            // Not wiped afterwards, on purpose. This is a copy of a string that
            // lives in the process environment either way, and `sodium_memzero`
            // works on the buffer rather than the variable — zeroing a copy can
            // reach the original, which would break the next read of it.
            $values = self::vault($basePath)->open($passphrase);

            if ($values !== null) {
                self::inject($values);
            }
        } catch (Throwable) {
            // Deliberately silent, and deliberately catching everything. See
            // the note above: there is no failure here worth more than the
            // variable being absent, and nothing useful to say this early —
            // there is no logger yet, and stderr would print on every command.
        }
    }

    /**
     * Put values into the environment, skipping any name already set.
     *
     * All three of `putenv`, `$_ENV` and `$_SERVER`, because they are not the
     * same thing and Laravel reads more than one of them. `putenv` is also
     * what makes a value survive into a child process, which is how
     * `artisan dev` hands the decrypted secrets to the server and the queue
     * worker without them ever holding a key.
     *
     * Skipping names that are already set is what keeps this safe to call: a
     * real exported variable always wins, and a second call cannot clobber the
     * first.
     *
     * @param  array<string, string>  $values
     */
    public static function inject(#[SensitiveParameter] array $values): void
    {
        foreach ($values as $name => $value) {
            if (self::environment($name) !== null) {
                continue;
            }

            putenv($name.'='.$value);
            $_ENV[$name] = $value;
            $_SERVER[$name] = $value;

            self::$loaded[] = $name;
        }
    }

    public static function isUnlocked(): bool
    {
        return self::$loaded !== [];
    }

    /**
     * Is this name set in the environment at all — by us, by an export, or by
     * a parent process that handed it down?
     */
    public static function has(string $name): bool
    {
        return self::environment($name) !== null;
    }

    /**
     * The names this process decrypted — not the ones it inherited already set.
     *
     * @return list<string>
     */
    public static function loaded(): array
    {
        return array_values(array_unique(self::$loaded));
    }

    public static function vault(string $basePath): Vault
    {
        return new Vault($basePath.DIRECTORY_SEPARATOR.self::FILE);
    }

    public static function envFile(string $basePath): EnvFile
    {
        return new EnvFile($basePath.DIRECTORY_SEPARATOR.'.env');
    }

    /**
     * Only for tests, which run many boots inside one process.
     */
    public static function reset(): void
    {
        self::$loaded = [];
    }

    /**
     * Are we inside a test run?
     *
     * Real credentials have no business in a process whose entire job is to
     * fake things. A suite that decrypts them gets two problems: it behaves
     * differently depending on what the person running it happens to have
     * exported, and a live token sits in memory next to code that is allowed
     * to be careless because none of it is supposed to be real.
     *
     * `APP_ENV` is the signal because every Laravel `phpunit.xml` sets it, so
     * this needs no configuration in the project that adopts it.
     *
     * All three sources are checked, and any one of them saying `testing` is
     * enough. They can disagree — PHPUnit writes `$_ENV` and `putenv` but not
     * `$_SERVER`, so an exported `APP_ENV` shows up in only one of them — and
     * when a signal about whether to touch real secrets is ambiguous, the
     * answer is don't.
     */
    private static function isTestRun(): bool
    {
        return in_array('testing', [$_SERVER['APP_ENV'] ?? null, $_ENV['APP_ENV'] ?? null, getenv('APP_ENV')], true);
    }

    private static function environment(string $name): ?string
    {
        foreach ([$_SERVER[$name] ?? null, $_ENV[$name] ?? null, getenv($name)] as $value) {
            if (is_string($value)) {
                return $value;
            }
        }

        return null;
    }
}
