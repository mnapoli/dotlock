<?php

declare(strict_types=1);

namespace Dotlock\Console;

use Dotlock\DotlockException;
use Dotlock\Secrets;
use Illuminate\Foundation\Console\DevCommand as FrameworkDevCommand;
use Illuminate\Support\NodePackageManager;

use function Laravel\Prompts\password;

/**
 * `artisan dev`, with one question in front of it.
 *
 * This is the only place in the whole package that ever asks for anything. It
 * can, because it is the one command a person starts by hand and then watches:
 * a prompt here is expected, whereas a prompt inside `schedule:run` under cron
 * would hang forever.
 *
 * What it hands to the child processes is the decrypted values, not the
 * passphrase. Two reasons, and both matter.
 *
 * `artisan serve` boots PHP again for every HTTP request, so passing the
 * passphrase down would pay the Argon2id derivation on every request instead
 * of once. And a child holding values rather than a key can only use what it
 * was given — it cannot open the vault and read something else.
 *
 * The framework's command ends in `pcntl_exec('/usr/bin/env', ...)` with no
 * environment array, so whatever `putenv` has set here is inherited by
 * `concurrently` and everything under it: the server, the queue worker, pail
 * and vite.
 */
final class DevCommand extends FrameworkDevCommand
{
    protected $name = 'dev';

    public function handle(NodePackageManager $packageManager): int
    {
        $this->unlock();

        return parent::handle($packageManager);
    }

    /**
     * Ask once, and carry on either way.
     *
     * Giving up and starting locked is deliberate. `dev` runs the whole
     * application; refusing to start it because one token is unavailable would
     * be a worse outcome than the token being unavailable, which is a thing
     * the app already knows how to say.
     */
    private function unlock(): void
    {
        $vault = Secrets::vault($this->laravel->environmentPath());

        if (! $vault->exists() || $vault->isEmpty()) {
            return;
        }

        // Already sorted: APP_SECRETS_KEY was set and the boot path used it, or
        // these were exported by hand, or a parent process passed them down.
        $missing = array_filter($vault->names(), fn (string $name): bool => ! Secrets::has($name));

        if ($missing === []) {
            return;
        }

        if (! $this->input->isInteractive()) {
            return;
        }

        $this->components->info(count($missing).' encrypted '.(count($missing) === 1 ? 'secret' : 'secrets').' to unlock.');

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $passphrase = password(label: 'Passphrase', required: true);

            try {
                $values = $vault->open($passphrase);
            } catch (DotlockException $damaged) {
                $this->components->error($damaged->getMessage());

                return;
            }

            if ($values !== null) {
                Secrets::inject($values);

                return;
            }

            $this->components->error('That is not the passphrase this vault was locked with.');
        }

        $this->components->warn('Starting without them. Anything that needs one will behave as if it was never configured.');
    }
}
