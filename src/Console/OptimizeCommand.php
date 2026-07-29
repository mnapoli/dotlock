<?php

declare(strict_types=1);

namespace Dotlock\Console;

use Dotlock\Console\Concerns\RefusesToCacheConfig;
use Illuminate\Foundation\Console\OptimizeCommand as FrameworkOptimizeCommand;

/**
 * `optimize` runs `config:cache` among other things, so the guard on that
 * command would catch this anyway — but it would catch it inside a silenced
 * sub-call, and all you would see is a red FAIL with no reason next to it.
 * Refusing up here means the explanation is the thing you read.
 */
final class OptimizeCommand extends FrameworkOptimizeCommand
{
    use RefusesToCacheConfig;

    protected $name = 'optimize';

    public function handle(): int
    {
        if ($this->refuseWhileThereIsAVault()) {
            return self::FAILURE;
        }

        parent::handle();

        return self::SUCCESS;
    }
}
