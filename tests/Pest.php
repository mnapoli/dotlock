<?php

declare(strict_types=1);

use Dotlock\EnvFile;
use Dotlock\Tests\TestCase;
use Dotlock\Vault;

pest()->extend(TestCase::class)->in('Feature');

/**
 * A throwaway directory, gone when the process ends.
 */
function scratchDir(): string
{
    $dir = sys_get_temp_dir().'/dotlock-'.bin2hex(random_bytes(6));

    mkdir($dir, 0700, true);

    register_shutdown_function(function () use ($dir): void {
        foreach (glob($dir.'/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($dir);
    });

    return $dir;
}

/**
 * A vault with the cheapest key derivation libsodium accepts. The tests are
 * about behaviour, not about how long Argon2id takes.
 */
function fastVault(string $dir): Vault
{
    return new Vault($dir.'/.env.secrets', ops: 1, mem: 8192);
}

function scratchEnv(string $dir, string $contents): EnvFile
{
    file_put_contents($dir.'/.env', $contents);

    return new EnvFile($dir.'/.env');
}

/**
 * A name no other test can collide with, since injecting one changes this
 * process's environment for the rest of the run.
 */
function uniqueName(): string
{
    return 'DOTLOCK_TEST_'.strtoupper(bin2hex(random_bytes(5)));
}
