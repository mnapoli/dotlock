<?php

declare(strict_types=1);

namespace Dotlock\Console;

use Dotlock\Console\Concerns\AsksForThePassphrase;
use Dotlock\Console\Concerns\MasksValues;
use Dotlock\DotlockException;
use Dotlock\EnvFile;
use Dotlock\Secrets;
use Illuminate\Console\Command;

use function Laravel\Prompts\confirm;
use function Laravel\Prompts\password;
use function Laravel\Prompts\suggest;

/**
 * Move a value out of `.env` and into the vault, or change one already in it.
 *
 * The order is the whole point and it never varies: the vault is written and
 * proved readable first, and `.env` is only touched afterwards. Until that
 * moment `.env` holds the only copy of the value, so the worst this command can
 * do is finish with the secret stored in both places — never in neither.
 */
final class SetCommand extends Command
{
    use AsksForThePassphrase;
    use MasksValues;

    protected $signature = 'secrets:set';

    protected $description = 'Move a value out of .env into the encrypted vault';

    public function handle(): int
    {
        $vault = Secrets::vault($this->laravel->environmentPath());
        $env = Secrets::envFile($this->laravel->environmentPath());

        try {
            $inEnv = array_keys($env->values());
        } catch (DotlockException $unreadable) {
            $this->components->error($unreadable->getMessage());

            return self::FAILURE;
        }

        // Both kinds of name belong on this list. One still in .env is a value
        // to move; one already encrypted is a value to change, which is what
        // rotating a token looks like.
        //
        // Encrypted names go first because that list is short and every entry
        // on it was deliberately put there, whereas .env is forty-odd lines of
        // LOG_LEVEL and SESSION_PATH with a secret or two among them. Ordered
        // the other way, the names you are most likely to want are the ones
        // you have to scroll past everything else to reach.
        $name = trim(suggest(
            label: 'Which environment variable?',
            options: array_values(array_unique([...$vault->names(), ...$inEnv])),
            placeholder: 'API_TOKEN',
            required: true,
            hint: 'Names in .env and names already encrypted are both offered. A new one is fine too.',
        ));

        $replacing = $vault->has($name);

        // Asked before the value, not after: being told what you are about to
        // overwrite is no use once you have typed the thing to overwrite it
        // with. Nothing keeps a copy of what it holds now.
        if ($replacing && ! confirm(
            label: "{$name} is already encrypted. Replace what it holds?",
            default: true,
            hint: 'The value it holds now is not kept anywhere else.',
        )) {
            return self::SUCCESS;
        }

        $existing = $env->has($name) ? $env->get($name) : null;
        $value = null;

        if ($existing !== null && $existing !== '') {
            $value = confirm(
                label: "Encrypt the value .env already has for {$name}?",
                default: true,
                hint: $this->mask($existing),
            ) ? $existing : null;
        }

        $takenFromEnv = $value !== null;

        $value ??= password(label: "Value for {$name}", required: true);

        $passphrase = $vault->exists()
            ? $this->askForThePassphrase($vault)
            : $this->askForANewPassphrase();

        if ($passphrase === null) {
            return self::FAILURE;
        }

        try {
            $vault->put($name, $value, $passphrase);
        } catch (DotlockException $failure) {
            $this->components->error($failure->getMessage());

            return self::FAILURE;
        }

        $this->components->info($replacing
            ? "{$name} now holds the new value."
            : "{$name} is encrypted in ".Secrets::FILE.'.');

        return $this->tidyEnv($name, $env, $takenFromEnv, $existing !== null);
    }

    /**
     * Clear the plaintext out of `.env`, now that there is a proven copy of it.
     */
    private function tidyEnv(
        string $name,
        EnvFile $env,
        bool $takenFromEnv,
        bool $presentInEnv,
    ): int {
        if (! $presentInEnv) {
            return self::SUCCESS;
        }

        // A value that was typed rather than lifted is a different value from
        // the one sitting in .env, and deleting somebody's only copy of a thing
        // they did not mention is not ours to do quietly.
        if (! $takenFromEnv) {
            $this->components->warn(
                ".env still sets {$name}, and it will be ignored — the encrypted value is loaded first and wins.",
            );

            if (! confirm(label: "Remove the {$name} line from .env?", default: false)) {
                return self::SUCCESS;
            }
        }

        try {
            $env->moveOut($name, "# {$name} -> ".Secrets::FILE);
        } catch (DotlockException $failure) {
            $this->components->error($failure->getMessage());
            $this->components->warn('The secret is safely stored. Only the .env line still needs removing.');

            return self::FAILURE;
        }

        $this->components->info('Removed from .env, with a note left where it was.');

        return self::SUCCESS;
    }
}
