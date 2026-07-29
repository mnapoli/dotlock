<?php

declare(strict_types=1);

namespace Dotlock\Console;

use Dotlock\Console\Concerns\AsksForThePassphrase;
use Dotlock\Console\Concerns\MasksValues;
use Dotlock\DotlockException;
use Dotlock\Secrets;
use Illuminate\Console\Command;

/**
 * Read one secret back.
 *
 * Printing in the clear takes `--show` and is not the default. Terminal output
 * outlives the moment — it sits in scrollback, in a screen share, and in the
 * transcript of any agent that ran the command — so putting a live credential
 * there should be something you asked for rather than something you got.
 */
final class GetCommand extends Command
{
    use AsksForThePassphrase;
    use MasksValues;

    protected $signature = 'secrets:get {name : The environment variable} {--show : Print the value in the clear}';

    protected $description = 'Read one secret out of the vault';

    public function handle(): int
    {
        $vault = Secrets::vault($this->laravel->environmentPath());

        /** @var string $name */
        $name = $this->argument('name');

        if (! $vault->has($name)) {
            $this->components->error("There is no secret called {$name}.");

            return self::FAILURE;
        }

        $value = Secrets::has($name) ? (string) getenv($name) : null;

        if ($value === null) {
            $passphrase = $this->askForThePassphrase($vault);

            if ($passphrase === null) {
                return self::FAILURE;
            }

            try {
                $value = ($vault->open($passphrase) ?? [])[$name] ?? null;
            } catch (DotlockException $failure) {
                $this->components->error($failure->getMessage());

                return self::FAILURE;
            }
        }

        if ($value === null) {
            $this->components->error("{$name} could not be read.");

            return self::FAILURE;
        }

        if (! $this->option('show')) {
            $this->components->twoColumnDetail($name, $this->mask($value));
            $this->components->info('Add --show to print it in the clear.');

            return self::SUCCESS;
        }

        // Written bare, with nothing around it, so it can be piped somewhere
        // without a label coming along for the ride.
        $this->line($value);

        return self::SUCCESS;
    }
}
