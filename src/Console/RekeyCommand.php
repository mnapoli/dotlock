<?php

declare(strict_types=1);

namespace Dotlock\Console;

use Dotlock\Console\Concerns\AsksForThePassphrase;
use Dotlock\DotlockException;
use Dotlock\Secrets;
use Illuminate\Console\Command;

/**
 * Change the passphrase.
 *
 * Not one encrypted value is rewritten. The passphrase only ever guards the
 * master key, so this rewrites a single line — which means there is no state
 * where half the secrets have moved to the new passphrase and half have not.
 */
final class RekeyCommand extends Command
{
    use AsksForThePassphrase;

    protected $signature = 'secrets:rekey';

    protected $description = 'Change the passphrase that opens the vault';

    public function handle(): int
    {
        $vault = Secrets::vault($this->laravel->environmentPath());

        if (! $vault->exists()) {
            $this->components->error('There is no vault yet. `php artisan secrets:set` makes one.');

            return self::FAILURE;
        }

        $current = $this->askForThePassphrase($vault, 'Current passphrase');

        if ($current === null) {
            return self::FAILURE;
        }

        $replacement = $this->askForANewPassphrase();

        if ($replacement === null) {
            return self::FAILURE;
        }

        try {
            $vault->rekey($current, $replacement);
        } catch (DotlockException $failure) {
            $this->components->error($failure->getMessage());

            return self::FAILURE;
        }

        $this->components->info('The vault takes the new passphrase now.');
        $this->components->warn('Anywhere the old one is written down — '.Secrets::KEY.' in a shell, a password manager — is now wrong.');

        return self::SUCCESS;
    }
}
