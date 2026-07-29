<?php

declare(strict_types=1);

namespace Dotlock\Console;

use Dotlock\Console\Concerns\AsksForThePassphrase;
use Dotlock\DotlockException;
use Dotlock\Secrets;
use Illuminate\Console\Command;

use function Laravel\Prompts\confirm;

/**
 * Drop one secret.
 *
 * It does not go back to `.env`. Putting the plaintext on disk again would
 * undo the one thing this whole package does, so a secret that leaves the
 * vault leaves for good — copy it out with `secrets:get --show` first if you
 * still need it.
 */
final class ForgetCommand extends Command
{
    use AsksForThePassphrase;

    protected $signature = 'secrets:forget {name : The environment variable}';

    protected $description = 'Remove a secret from the vault for good';

    public function handle(): int
    {
        $vault = Secrets::vault($this->laravel->environmentPath());

        /** @var string $name */
        $name = $this->argument('name');

        if (! $vault->has($name)) {
            $this->components->error("There is no secret called {$name}.");

            return self::FAILURE;
        }

        if (! confirm(
            label: "Forget {$name}?",
            default: false,
            hint: 'It is not written back to .env, and there is no copy of it anywhere else.',
        )) {
            return self::SUCCESS;
        }

        $passphrase = $this->askForThePassphrase($vault);

        if ($passphrase === null) {
            return self::FAILURE;
        }

        try {
            $vault->forget($name, $passphrase);
        } catch (DotlockException $failure) {
            $this->components->error($failure->getMessage());

            return self::FAILURE;
        }

        $this->components->info("{$name} is gone.");

        return self::SUCCESS;
    }
}
