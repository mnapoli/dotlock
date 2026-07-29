<?php

declare(strict_types=1);

namespace Dotlock\Console\Concerns;

use Dotlock\Secrets;
use Dotlock\Vault;

/**
 * The one silent failure the design leaves open: `composer require` done,
 * every command working, `APP_SECRETS_KEY` exported — and the snippet never
 * added to `bootstrap/app.php`. Locked means unset, so nothing ever says a
 * word; the variables are simply not there.
 *
 * This process is its own evidence. It booted the way every process boots, so
 * a key in the environment plus vault names the boot did not inject can only
 * mean the boot path is broken: the snippet is missing, or the key holds the
 * wrong passphrase.
 */
trait NoticesAMissedUnlock
{
    /**
     * Say so when the boot should have unlocked the vault and did not.
     *
     * Returns whether it spoke, so a caller with something milder to say can
     * stay quiet when this already said the important thing.
     *
     * @param  ?string  $justSet  a name this very command wrote, which no boot
     *                            can have seen yet
     */
    protected function warnAboutAMissedUnlock(Vault $vault, ?string $justSet = null): bool
    {
        if (! Secrets::has(Secrets::KEY)) {
            return false;
        }

        $missing = array_filter(
            $vault->names(),
            fn (string $name): bool => $name !== $justSet && ! Secrets::has($name),
        );

        if ($missing === []) {
            return false;
        }

        $this->components->warn(
            Secrets::KEY.' is set, but the secrets were not loaded when this process started. '
            .('Check that bootstrap/app.php calls '.Secrets::class.'::unlock() — the README has the ')
            .'snippet — and that '.Secrets::KEY.' holds the right passphrase.',
        );

        return true;
    }
}
