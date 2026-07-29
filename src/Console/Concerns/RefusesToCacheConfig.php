<?php

declare(strict_types=1);

namespace Dotlock\Console\Concerns;

use Dotlock\Secrets;

/**
 * The one hole big enough to sink the whole package.
 *
 * `config:cache` resolves every `env()` call right now and writes the answers
 * to `bootstrap/cache/config.php` as a plain PHP array. Run it once with the
 * vault open and every secret is sitting unencrypted in a file nobody thinks
 * to look in — not `.env`, so it survives every check you would think to make.
 *
 * Refusing while locked matters just as much, and is less obvious: the cache
 * would freeze the secrets as `null`, and they would stay `null` afterwards no
 * matter how many times you unlock, because config is never consulted again.
 *
 * So: if there is a vault at all, this does not run.
 */
trait RefusesToCacheConfig
{
    protected function refuseWhileThereIsAVault(): bool
    {
        $vault = Secrets::vault($this->laravel->environmentPath());

        if (! $vault->exists() || $vault->isEmpty()) {
            return false;
        }

        $this->components->error('Nothing was cached, because this project has encrypted secrets.');

        $this->components->bulletList([
            'Caching config freezes env() into bootstrap/cache/config.php as plain text.',
            'Unlocked, that writes your secrets there in the clear.',
            'Locked, it writes them as null and they stay null however often you unlock.',
        ]);

        return true;
    }
}
