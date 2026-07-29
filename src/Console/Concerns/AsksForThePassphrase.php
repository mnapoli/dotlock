<?php

declare(strict_types=1);

namespace Dotlock\Console\Concerns;

use Dotlock\DotlockException;
use Dotlock\Vault;

use function Laravel\Prompts\password;
use function Laravel\Prompts\warning;

trait AsksForThePassphrase
{
    /**
     * The passphrase for a vault that exists, checked before it is used.
     *
     * Three tries and then it gives up, rather than looping until somebody
     * closes the terminal. Null means "could not produce it", and every caller
     * treats that as a reason to change nothing at all.
     */
    protected function askForThePassphrase(Vault $vault, string $label = 'Passphrase'): ?string
    {
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $passphrase = password(label: $label, required: true);

            try {
                if ($vault->open($passphrase) !== null) {
                    return $passphrase;
                }
            } catch (DotlockException $damaged) {
                $this->components->error($damaged->getMessage());

                return null;
            }

            $this->components->error('That is not the passphrase this vault was locked with.');
        }

        return null;
    }

    /**
     * A passphrase for a vault that does not exist yet.
     *
     * Typed twice, because there is no way back from a typo here: the vault is
     * the only copy of what goes into it and nothing on this machine can open
     * it without this exact string.
     */
    protected function askForANewPassphrase(): ?string
    {
        warning(
            'This passphrase is the only way into the vault. It is not stored anywhere, '
            .'there is no recovery, and a secret whose passphrase is lost is lost with it. '
            .'Somewhere like 1Password is a good home for it.',
        );

        $passphrase = password(
            label: 'Choose a passphrase',
            required: true,
            validate: fn (string $value): ?string => mb_strlen($value) < 8
                ? 'Use at least 8 characters.'
                : null,
        );

        if (! hash_equals($passphrase, password(label: 'Type it again', required: true))) {
            $this->components->error('Those two do not match. Nothing was changed.');

            return null;
        }

        return $passphrase;
    }
}
