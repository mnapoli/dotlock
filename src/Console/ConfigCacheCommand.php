<?php

declare(strict_types=1);

namespace Dotlock\Console;

use Dotlock\Console\Concerns\RefusesToCacheConfig;
use Illuminate\Foundation\Console\ConfigCacheCommand as FrameworkConfigCacheCommand;

final class ConfigCacheCommand extends FrameworkConfigCacheCommand
{
    use RefusesToCacheConfig;

    protected $name = 'config:cache';

    public function handle(): int
    {
        if ($this->refuseWhileThereIsAVault()) {
            return self::FAILURE;
        }

        // Returns nothing and throws when it cannot write, so reaching the next
        // line is the success case.
        parent::handle();

        return self::SUCCESS;
    }
}
