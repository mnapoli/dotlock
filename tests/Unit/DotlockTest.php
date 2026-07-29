<?php

declare(strict_types=1);

use Dotlock\Cipher;
use Dotlock\DotlockException;
use Dotlock\Secrets;
use Dotlock\Vault;

it('gives back exactly what it was given, whatever that is', function (string $value) {
    $vault = fastVault(scratchDir());

    $vault->put('SECRET', $value, 'correct horse battery staple');

    expect($vault->open('correct horse battery staple')['SECRET'])->toBe($value);
})->with([
    'ordinary' => 'fmu1-0123456789abcdef',
    'multi-line' => "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----",
    'dotenv would choke on this' => 'a"b\'c#d=e$f`g \\ h',
    'unicode' => 'clé-privée-🔐',
    'one character' => 'x',
    'empty' => '',
]);

it('gets nothing at all from the wrong passphrase', function () {
    $vault = fastVault(scratchDir());
    $vault->put('SECRET', 'value', 'right');

    expect($vault->open('wrong'))->toBeNull()
        ->and($vault->open(''))->toBeNull()
        ->and($vault->open('Right'))->toBeNull();
});

it('says so when a value has been damaged rather than handing back rubbish', function () {
    $dir = scratchDir();
    $vault = fastVault($dir);
    $vault->put('SECRET', 'value', 'right');

    // One byte of the ciphertext, changed to something it definitely was not.
    // The MAC is what catches this; a cipher without one would decrypt it to
    // noise and nobody would know.
    $contents = file_get_contents($dir.'/.env.secrets');
    file_put_contents($dir.'/.env.secrets', preg_replace_callback(
        '/^SECRET="(.)/m',
        fn (array $m) => 'SECRET="'.($m[1] === 'A' ? 'B' : 'A'),
        $contents,
    ));

    expect(fn () => $vault->open('right'))->toThrow(DotlockException::class, 'damaged');
});

it('refuses a wrong passphrase without touching the file', function () {
    $dir = scratchDir();
    $vault = fastVault($dir);
    $vault->put('SECRET', 'value', 'right');

    $before = file_get_contents($dir.'/.env.secrets');

    expect(fn () => $vault->put('OTHER', 'value', 'wrong'))
        ->toThrow(DotlockException::class, 'not the passphrase');

    expect(file_get_contents($dir.'/.env.secrets'))->toBe($before)
        ->and(glob($dir.'/*.tmp'))->toBe([]);
});

it('leaves the file readable only by its owner', function () {
    $dir = scratchDir();
    fastVault($dir)->put('SECRET', 'value', 'right');

    expect(substr(sprintf('%o', fileperms($dir.'/.env.secrets')), -4))->toBe('0600');
});

it('keeps every value when the passphrase changes', function () {
    $vault = fastVault(scratchDir());
    $vault->put('ONE', 'first', 'old');
    $vault->put('TWO', 'second', 'old');

    $vault->rekey('old', 'new');

    expect($vault->open('old'))->toBeNull()
        ->and($vault->open('new'))->toBe(['ONE' => 'first', 'TWO' => 'second']);
});

it('leaves the other secrets alone when one is forgotten', function () {
    $vault = fastVault(scratchDir());
    $vault->put('KEEP', 'kept', 'pass');
    $vault->put('DROP', 'dropped', 'pass');

    $vault->forget('DROP', 'pass');

    expect($vault->names())->toBe(['KEEP'])
        ->and($vault->open('pass'))->toBe(['KEEP' => 'kept']);
});

it('will not pretend to forget a secret it never had', function () {
    $vault = fastVault(scratchDir());
    $vault->put('KEEP', 'kept', 'pass');

    expect(fn () => $vault->forget('MISSING', 'pass'))
        ->toThrow(DotlockException::class, 'no secret called');
});

it('will not rekey with a passphrase that was never the one', function () {
    $vault = fastVault(scratchDir());
    $vault->put('SECRET', 'value', 'right');

    expect(fn () => $vault->rekey('wrong', 'new'))
        ->toThrow(DotlockException::class, 'not the passphrase');

    expect($vault->open('right'))->toBe(['SECRET' => 'value']);
});

it('treats a header it cannot make sense of as a vault it cannot open', function () {
    $dir = scratchDir();
    $vault = fastVault($dir);
    $vault->put('SECRET', 'value', 'right');

    $file = $dir.'/.env.secrets';
    $pristine = file_get_contents($file);

    // A version this code does not speak.
    file_put_contents($file, preg_replace('/^'.Vault::META.'="v1:/m', Vault::META.'="v9:', $pristine));
    expect($vault->open('right'))->toBeNull();

    // A salt that is not base64 at all.
    file_put_contents($file, preg_replace('/^'.Vault::META.'="v1:[^:]+:/m', Vault::META.'="v1:!!!:', $pristine));
    expect($vault->open('right'))->toBeNull();

    // Reading degrades to locked; writing through it is refused loudly, since
    // a write that carried on would seal the new value inside a broken file.
    expect(fn () => $vault->put('OTHER', 'value', 'right'))
        ->toThrow(DotlockException::class, 'not a secrets file');
});

it('fails loudly when it cannot write next to the vault', function () {
    $dir = scratchDir();
    $vault = fastVault($dir);
    $vault->put('SECRET', 'value', 'right');

    chmod($dir, 0500);

    try {
        expect(fn () => $vault->put('OTHER', 'value', 'right'))
            ->toThrow(DotlockException::class, 'Could not write next to '.$vault->path());
    } finally {
        chmod($dir, 0700);
    }
});

it('says when the vault exists but cannot be read', function () {
    $dir = scratchDir();
    $vault = fastVault($dir);
    $vault->put('SECRET', 'value', 'right');

    chmod($dir.'/.env.secrets', 0000);

    try {
        expect(fn () => $vault->names())->toThrow(DotlockException::class, 'could not be read');
    } finally {
        chmod($dir.'/.env.secrets', 0600);
    }
});

it('records the cost settings it used, so the file can still be opened when the default changes', function () {
    $dir = scratchDir();

    (new Vault($dir.'/.env.secrets', ops: 3, mem: 32768))->put('SECRET', 'value', 'pass');

    expect(file_get_contents($dir.'/.env.secrets'))->toContain(':3:32768:');

    // A reader that knows nothing about those settings still gets in, because
    // it takes them from the header rather than from its own defaults.
    expect((new Vault($dir.'/.env.secrets'))->open('pass'))->toBe(['SECRET' => 'value']);
});

it('will not let a secret be called the name the header uses', function () {
    $vault = fastVault(scratchDir());

    expect(fn () => $vault->put(Vault::META, 'value', 'pass'))
        ->toThrow(DotlockException::class)
        ->and(fn () => $vault->put('not a name', 'value', 'pass'))
        ->toThrow(DotlockException::class);
});

it('refuses inputs the file format could never produce', function () {
    // Each of these guards a way a tampered header could reach the cipher:
    // a truncated salt, settings weakened to nothing, a key cut short.
    expect(fn () => Cipher::deriveKey('pass', 'short-salt', 1, 8192))
        ->toThrow(DotlockException::class, 'salt of the wrong size')
        ->and(fn () => Cipher::deriveKey('pass', Cipher::salt(), 0, 8192))
        ->toThrow(DotlockException::class, 'too weak')
        ->and(fn () => Cipher::deriveKey('', Cipher::salt(), 1, 8192))
        ->toThrow(DotlockException::class, 'empty passphrase')
        ->and(fn () => Cipher::seal('value', 'short-key'))
        ->toThrow(DotlockException::class, 'wrong size');

    // And a value that is not even base64, or too short to hold a nonce, is
    // answered with null the same way a failed MAC is.
    expect(Cipher::open('not base64 !!!', Cipher::newKey()))->toBeNull()
        ->and(Cipher::open(base64_encode('short'), Cipher::newKey()))->toBeNull();
});

it('reads a .env the way dotenv does', function () {
    $env = scratchEnv(scratchDir(), <<<'ENV'
        PLAIN=abc
        QUOTED="a b c"
        SINGLE='a b c'
        WITH_COMMENT=abc # trailing
        EXPORTED=export-is-not-part-of-the-name
        export EXPORTED_TOO=value
        EMPTY=
        # COMMENTED=nope
        a line that assigns nothing at all
        ENV);

    expect($env->values())->toBe([
        'PLAIN' => 'abc',
        'QUOTED' => 'a b c',
        'SINGLE' => 'a b c',
        'WITH_COMMENT' => 'abc',
        'EXPORTED' => 'export-is-not-part-of-the-name',
        'EXPORTED_TOO' => 'value',
        'EMPTY' => '',
    ]);
});

it('replaces one line of .env and copies every other byte through', function () {
    $original = <<<'ENV'
        # A comment at the top

        APP_NAME=Example
        API_TOKEN="the-secret"

        # A comment further down.
        OTHER_KEY=not-a-secret
        ENV;

    $dir = scratchDir();
    $env = scratchEnv($dir, $original);

    $env->moveOut('API_TOKEN', '# API_TOKEN -> .env.secrets');

    expect(file_get_contents($dir.'/.env'))->toBe(str_replace(
        'API_TOKEN="the-secret"',
        '# API_TOKEN -> .env.secrets',
        $original,
    ));
});

it('refuses to edit a .env value that runs over several lines', function () {
    $env = scratchEnv(scratchDir(), "KEY=\"line one\nline two\"\n");

    expect(fn () => $env->values())->toThrow(DotlockException::class, 'by hand');
});

it('says which names .env still sets', function () {
    $env = scratchEnv(scratchDir(), "SET=value\n# NOT_SET=value\n");

    expect($env->has('SET'))->toBeTrue()
        ->and($env->has('NOT_SET'))->toBeFalse()
        ->and(fn () => $env->moveOut('NOT_SET', '# note'))
        ->toThrow(DotlockException::class, 'nothing to move');
});

it('reports a .env it cannot read or cannot write', function () {
    $dir = scratchDir();
    $env = scratchEnv($dir, "API_TOKEN=value\n");

    chmod($env->path(), 0000);

    try {
        expect(fn () => $env->values())->toThrow(DotlockException::class, 'could not be read');
    } finally {
        chmod($env->path(), 0600);
    }

    chmod($env->path(), 0400);

    try {
        expect(fn () => $env->moveOut('API_TOKEN', '# moved'))
            ->toThrow(DotlockException::class, 'Could not write');
    } finally {
        chmod($env->path(), 0600);
    }
});

it('unlocks for real outside a test run', function () {
    $dir = scratchDir();
    $name = uniqueName();

    fastVault($dir)->put($name, 'value', 'right');

    // Make this process look like a normal boot for a moment. The guard reads
    // APP_ENV from all three sources, so all three are moved aside.
    $server = $_SERVER['APP_ENV'] ?? null;
    $env = $_ENV['APP_ENV'] ?? null;
    $exported = getenv('APP_ENV');

    unset($_SERVER['APP_ENV'], $_ENV['APP_ENV']);
    putenv('APP_ENV');
    $_SERVER[Secrets::KEY] = 'right';

    try {
        Secrets::unlock($dir);

        expect(getenv($name))->toBe('value')
            ->and(Secrets::isUnlocked())->toBeTrue()
            ->and(Secrets::loaded())->toContain($name);
    } finally {
        if ($server !== null) {
            $_SERVER['APP_ENV'] = $server;
        }

        if ($env !== null) {
            $_ENV['APP_ENV'] = $env;
        }

        if ($exported !== false) {
            putenv('APP_ENV='.$exported);
        }

        unset($_SERVER[Secrets::KEY]);
        putenv($name);
        unset($_SERVER[$name], $_ENV[$name]);
    }
});

it('never overwrites something the environment already sets', function () {
    $name = uniqueName();
    putenv($name.'=from-the-shell');
    $_SERVER[$name] = 'from-the-shell';

    Secrets::inject([$name => 'from-the-vault']);

    expect(getenv($name))->toBe('from-the-shell')
        ->and($_SERVER[$name])->toBe('from-the-shell');

    putenv($name);
    unset($_SERVER[$name]);
});

it('puts a secret everywhere the environment is read from', function () {
    $name = uniqueName();

    Secrets::inject([$name => 'value']);

    // All three, because they are not the same thing: Laravel reads $_SERVER,
    // and putenv is what carries a value into a child process.
    expect(getenv($name))->toBe('value')
        ->and($_SERVER[$name])->toBe('value')
        ->and($_ENV[$name])->toBe('value');

    putenv($name);
    unset($_SERVER[$name], $_ENV[$name]);
});

it('does not open the vault during a test run, even with the right passphrase', function () {
    $dir = scratchDir();
    $name = uniqueName();

    fastVault($dir)->put($name, 'value', 'right');

    $_SERVER[Secrets::KEY] = 'right';

    // The guarded entry point, which is what `bootstrap/app.php` calls. Real
    // credentials must not reach a process whose whole job is to fake things,
    // and this is the line that keeps them out.
    Secrets::unlock($dir);

    expect(getenv($name))->toBeFalse();

    // The very same passphrase and file, through the unguarded one.
    Secrets::load($dir);

    expect(getenv($name))->toBe('value');

    unset($_SERVER[Secrets::KEY]);
    putenv($name);
    unset($_SERVER[$name], $_ENV[$name]);
});

describe('locked means unset', function () {
    /**
     * The governing rule, checked from every direction it can be reached.
     * Whatever is wrong, the answer is the same: the variable is not there,
     * nothing was said, and nothing was thrown.
     *
     * These go through `load()` rather than `unlock()` on purpose: `unlock()`
     * refuses outright inside a test run, which is asserted just above, and
     * what is being checked here is the behaviour it guards.
     */
    beforeEach(function () {
        $this->dir = scratchDir();
        $this->name = uniqueName();
    });

    afterEach(function () {
        unset($_SERVER[Secrets::KEY]);
        putenv($this->name);
        unset($_SERVER[$this->name], $_ENV[$this->name]);
    });

    it('with no passphrase', function () {
        (new Vault($this->dir.'/.env.secrets', ops: 1, mem: 8192))
            ->put($this->name, 'value', 'right');

        Secrets::load($this->dir);

        expect(getenv($this->name))->toBeFalse();
    });

    it('with the wrong passphrase', function () {
        (new Vault($this->dir.'/.env.secrets', ops: 1, mem: 8192))
            ->put($this->name, 'value', 'right');

        $_SERVER[Secrets::KEY] = 'wrong';

        Secrets::load($this->dir);

        expect(getenv($this->name))->toBeFalse();
    });

    it('with no file at all', function () {
        $_SERVER[Secrets::KEY] = 'right';

        Secrets::load($this->dir);

        expect(getenv($this->name))->toBeFalse();
    });

    it('with a file that is not a vault', function () {
        file_put_contents($this->dir.'/.env.secrets', "this is not a vault\n".$this->name."=plain\n");

        $_SERVER[Secrets::KEY] = 'right';

        Secrets::load($this->dir);

        expect(getenv($this->name))->toBeFalse();
    });

    it('with a damaged value, which would otherwise throw', function () {
        $vault = new Vault($this->dir.'/.env.secrets', ops: 1, mem: 8192);
        $vault->put($this->name, 'value', 'right');

        $contents = file_get_contents($this->dir.'/.env.secrets');
        file_put_contents($this->dir.'/.env.secrets', preg_replace(
            '/^'.$this->name.'="./m',
            $this->name.'="Z',
            $contents,
        ));

        $_SERVER[Secrets::KEY] = 'right';

        Secrets::load($this->dir);

        expect(getenv($this->name))->toBeFalse();
    });

    it('but the passphrase that works does work', function () {
        (new Vault($this->dir.'/.env.secrets', ops: 1, mem: 8192))
            ->put($this->name, 'value', 'right');

        $_SERVER[Secrets::KEY] = 'right';

        Secrets::load($this->dir);

        expect(getenv($this->name))->toBe('value');
    });
});
