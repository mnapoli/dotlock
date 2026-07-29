<?php

declare(strict_types=1);

use Dotlock\Secrets;
use Dotlock\Vault;

/**
 * The commands, driven through Artisan.
 *
 * Every test points the application's environment path at a scratch directory
 * first. Nothing here is allowed within reach of a real `.env`.
 */
beforeEach(function () {
    $this->dir = scratchDir();
    $this->app->useEnvironmentPath($this->dir);

    Secrets::reset();
});

it('moves a value out of .env and proves it can be read back', function () {
    scratchEnv($this->dir, <<<'ENV'
        APP_NAME=Example
        API_TOKEN=the-real-token

        # Something else entirely.
        OTHER_KEY=not-a-secret
        ENV);

    $this->artisan('secrets:set')
        ->expectsQuestion('Which environment variable?', 'API_TOKEN')
        ->expectsConfirmation('Encrypt the value .env already has for API_TOKEN?', 'yes')
        ->expectsQuestion('Choose a passphrase', 'correct horse battery')
        ->expectsQuestion('Type it again', 'correct horse battery')
        ->assertSuccessful();

    $env = file_get_contents($this->dir.'/.env');

    expect($env)
        ->not->toContain('the-real-token')
        ->toContain('# API_TOKEN -> .env.secrets')
        // Everything else is exactly where it was.
        ->toContain('APP_NAME=Example')
        ->toContain('# Something else entirely.')
        ->toContain('OTHER_KEY=not-a-secret');

    expect((new Vault($this->dir.'/.env.secrets'))->open('correct horse battery'))
        ->toBe(['API_TOKEN' => 'the-real-token']);
});

it('offers what is already encrypted, so a token can be rotated', function () {
    fastVault($this->dir)->put('API_TOKEN', 'the-old-one', 'pass');
    scratchEnv($this->dir, "OTHER_KEY=still-in-env\n");

    $this->artisan('secrets:set')
        // Both lists, in one: something to move and something to change.
        ->expectsChoice('Which environment variable?', 'API_TOKEN', ['OTHER_KEY', 'API_TOKEN'])
        ->expectsConfirmation('API_TOKEN is already encrypted. Replace what it holds?', 'yes')
        ->expectsQuestion('Value for API_TOKEN', 'the-new-one')
        ->expectsQuestion('Passphrase', 'pass')
        ->assertSuccessful();

    expect(fastVault($this->dir)->open('pass'))->toBe(['API_TOKEN' => 'the-new-one']);
});

it('keeps the stored value when the replacement is turned down', function () {
    fastVault($this->dir)->put('API_TOKEN', 'the-old-one', 'pass');

    $this->artisan('secrets:set')
        ->expectsQuestion('Which environment variable?', 'API_TOKEN')
        ->expectsConfirmation('API_TOKEN is already encrypted. Replace what it holds?', 'no')
        ->assertSuccessful();

    expect(fastVault($this->dir)->open('pass'))->toBe(['API_TOKEN' => 'the-old-one']);
});

it('leaves .env alone when the passphrase is wrong', function () {
    fastVault($this->dir)->put('EXISTING', 'value', 'the right one');

    $before = "API_TOKEN=the-real-token\n";
    scratchEnv($this->dir, $before);

    $this->artisan('secrets:set')
        ->expectsQuestion('Which environment variable?', 'API_TOKEN')
        ->expectsConfirmation('Encrypt the value .env already has for API_TOKEN?', 'yes')
        ->expectsQuestion('Passphrase', 'wrong')
        ->expectsQuestion('Passphrase', 'still wrong')
        ->expectsQuestion('Passphrase', 'wrong again')
        ->assertFailed();

    // The only copy of the token is the one in .env, and it is still there.
    expect(file_get_contents($this->dir.'/.env'))->toBe($before)
        ->and(fastVault($this->dir)->names())->toBe(['EXISTING']);
});

it('will not delete a .env value it was not asked to encrypt', function () {
    scratchEnv($this->dir, "TOKEN=the-old-one\n");

    $this->artisan('secrets:set')
        ->expectsQuestion('Which environment variable?', 'TOKEN')
        ->expectsConfirmation('Encrypt the value .env already has for TOKEN?', 'no')
        ->expectsQuestion('Value for TOKEN', 'the-new-one')
        ->expectsQuestion('Choose a passphrase', 'a passphrase')
        ->expectsQuestion('Type it again', 'a passphrase')
        ->expectsOutputToContain('.env still sets TOKEN')
        ->expectsConfirmation('Remove the TOKEN line from .env?', 'no')
        ->assertSuccessful();

    expect(file_get_contents($this->dir.'/.env'))->toContain('TOKEN=the-old-one');
});

it('lists what is in the vault and says which names .env is shadowing', function () {
    fastVault($this->dir)->put('SHADOWED', 'value', 'pass');
    fastVault($this->dir)->put('CLEAN', 'value', 'pass');

    scratchEnv($this->dir, "SHADOWED=stale\nUNRELATED=fine\n");

    // Substrings here must not overlap: each line of output is matched against
    // the first expectation that fits it, so a loose one swallows a later line.
    $this->artisan('secrets:list')
        ->expectsOutputToContain('CLEAN')
        ->expectsOutputToContain('SHADOWED is also set in .env')
        ->assertSuccessful();
});

it('will not print a secret without being asked twice', function () {
    fastVault($this->dir)->put('TOKEN', 'the-secret-value', 'pass');

    $this->artisan('secrets:get', ['name' => 'TOKEN'])
        ->expectsQuestion('Passphrase', 'pass')
        ->doesntExpectOutputToContain('the-secret-value')
        ->expectsOutputToContain('--show')
        ->assertSuccessful();

    $this->artisan('secrets:get', ['name' => 'TOKEN', '--show' => true])
        ->expectsQuestion('Passphrase', 'pass')
        ->expectsOutput('the-secret-value')
        ->assertSuccessful();
});

it('forgets a secret without writing it back to .env', function () {
    fastVault($this->dir)->put('KEEP', 'kept', 'pass');
    fastVault($this->dir)->put('DROP', 'dropped', 'pass');

    scratchEnv($this->dir, "UNRELATED=fine\n");

    $this->artisan('secrets:forget', ['name' => 'DROP'])
        ->expectsConfirmation('Forget DROP?', 'yes')
        ->expectsQuestion('Passphrase', 'pass')
        ->assertSuccessful();

    expect(fastVault($this->dir)->names())->toBe(['KEEP'])
        ->and(file_get_contents($this->dir.'/.env'))->not->toContain('DROP');
});

it('changes the passphrase without disturbing a single value', function () {
    fastVault($this->dir)->put('ONE', 'first', 'old passphrase');
    fastVault($this->dir)->put('TWO', 'second', 'old passphrase');

    $this->artisan('secrets:rekey')
        ->expectsQuestion('Current passphrase', 'old passphrase')
        ->expectsQuestion('Choose a passphrase', 'new passphrase')
        ->expectsQuestion('Type it again', 'new passphrase')
        ->assertSuccessful();

    $vault = fastVault($this->dir);

    expect($vault->open('old passphrase'))->toBeNull()
        ->and($vault->open('new passphrase'))->toBe(['ONE' => 'first', 'TWO' => 'second']);
});

it('gives up rather than looping when the passphrase never comes', function () {
    fastVault($this->dir)->put('TOKEN', 'value', 'pass');

    $this->artisan('secrets:rekey')
        ->expectsQuestion('Current passphrase', 'no')
        ->expectsQuestion('Current passphrase', 'nope')
        ->expectsQuestion('Current passphrase', 'still no')
        ->assertFailed();
});

describe('caching config would undo the whole thing', function () {
    /**
     * Locked or unlocked, `config:cache` is the one command that can write
     * these values to disk in plain text — or freeze them as null for good.
     * Neither is allowed to happen by accident.
     */
    it('refuses config:cache while a vault exists', function () {
        fastVault($this->dir)->put('TOKEN', 'value', 'pass');

        $this->artisan('config:cache')
            ->expectsOutputToContain('encrypted secrets')
            ->assertFailed();

        expect(file_exists($this->app->getCachedConfigPath()))->toBeFalse();
    });

    it('refuses optimize as well, so the reason is the thing you read', function () {
        fastVault($this->dir)->put('TOKEN', 'value', 'pass');

        $this->artisan('optimize')
            ->expectsOutputToContain('encrypted secrets')
            ->assertFailed();

        expect(file_exists($this->app->getCachedConfigPath()))->toBeFalse();
    });
});
