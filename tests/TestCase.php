<?php

declare(strict_types=1);

namespace Dotlock\Tests;

use Dotlock\DotlockServiceProvider;
use Orchestra\Testbench\TestCase as Testbench;

abstract class TestCase extends Testbench
{
    /**
     * @param  \Illuminate\Foundation\Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [DotlockServiceProvider::class];
    }
}
