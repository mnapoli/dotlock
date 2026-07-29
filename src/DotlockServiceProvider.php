<?php

declare(strict_types=1);

namespace Dotlock;

use Dotlock\Console\ConfigCacheCommand;
use Dotlock\Console\DevCommand;
use Dotlock\Console\ForgetCommand;
use Dotlock\Console\GetCommand;
use Dotlock\Console\ListCommand;
use Dotlock\Console\OptimizeCommand;
use Dotlock\Console\RekeyCommand;
use Dotlock\Console\SetCommand;
use Illuminate\Foundation\Console\DevCommand as FrameworkDevCommand;
use Illuminate\Support\ServiceProvider;

/**
 * Everything here is console-only, and three of the commands replace ones the
 * framework already ships.
 *
 * That works because Symfony keys its commands by name — `$commands[$name] = $command`
 * — so the last registration of a name wins. This provider boots after the
 * framework's own, which is what makes `dev`, `config:cache` and `optimize`
 * ours rather than theirs.
 *
 * Nothing here participates in unlocking. That happens in `bootstrap/app.php`,
 * long before any provider exists, because config has to be built from an
 * environment that already has the secrets in it.
 */
final class DotlockServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->commands([
            SetCommand::class,
            ListCommand::class,
            GetCommand::class,
            ForgetCommand::class,
            RekeyCommand::class,
            ConfigCacheCommand::class,
            OptimizeCommand::class,
        ]);

        // Only in a Laravel new enough to have it. The rest of this works
        // without `artisan dev`; it just means nobody gets asked anything.
        if (class_exists(FrameworkDevCommand::class)) {
            $this->commands([DevCommand::class]);
        }
    }
}
