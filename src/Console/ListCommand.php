<?php

declare(strict_types=1);

namespace Dotlock\Console;

use Dotlock\Console\Concerns\MasksValues;
use Dotlock\Secrets;
use Illuminate\Console\Command;

/**
 * What is in the vault, without asking for the passphrase.
 *
 * Names are readable straight from the file, which is why it is shaped like a
 * dotenv file at all. Values are only shown when this process happens to be
 * unlocked already — this command will not ask for a passphrase just to print
 * a row of dots.
 */
final class ListCommand extends Command
{
    use MasksValues;

    protected $signature = 'secrets:list';

    protected $description = 'List the secrets in the vault';

    public function handle(): int
    {
        $vault = Secrets::vault($this->laravel->environmentPath());
        $env = Secrets::envFile($this->laravel->environmentPath());

        if (! $vault->exists() || $vault->isEmpty()) {
            $this->components->info('No secrets yet. `php artisan secrets:set` moves one out of .env.');

            return self::SUCCESS;
        }

        // A name in both files is the one genuinely confusing state this can
        // get into: .env looks like it is in charge and is not. It earns a
        // column, but only when there is one to report — a blank column on
        // every healthy vault teaches people to stop reading the table.
        $shadowed = array_values(array_filter($vault->names(), $env->has(...)));

        $rows = array_map(function (string $name) use ($shadowed): array {
            $value = Secrets::has($name) ? (string) getenv($name) : null;

            $row = [$name, $value === null ? 'locked' : $this->mask($value)];

            return $shadowed === [] ? $row : [...$row, in_array($name, $shadowed, true) ? 'also in .env' : ''];
        }, $vault->names());

        $this->newLine();
        $this->table($shadowed === [] ? ['Name', 'Value'] : ['Name', 'Value', ''], $rows);

        if (! Secrets::isUnlocked()) {
            $this->components->info('Locked. Set '.Secrets::KEY.' to see the values.');
        }

        foreach ($shadowed as $name) {
            // Short on purpose: this is the one genuinely confusing state the
            // feature can get into, and a sentence that wraps is a sentence
            // somebody skims.
            $this->components->warn("{$name} is also set in .env. That line does nothing.");
        }

        return self::SUCCESS;
    }
}
