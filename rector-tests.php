<?php

declare(strict_types=1);

use Pest\Rector\Rules\ChainExpectCallsRector;
use Pest\Rector\Rules\SimplifyToLiteralBooleanRector;
use Pest\Rector\Set\PestSetList;
use Rector\Config\RectorConfig;

/*
|--------------------------------------------------------------------------
| Rector, for the tests
|--------------------------------------------------------------------------
|
| Separate from `rector.php` because the source's sets are about code that
| runs in someone's application — dead branches, narrowed types, privatised
| methods — and a test is not that kind of code. What a test needs is that
| the assertion names what it checks, so this config carries one set: Pest's
| own coding style.
|
*/

return RectorConfig::configure()
    ->withPaths([
        __DIR__.'/tests',
    ])
    ->withSets([
        PestSetList::CODING_STYLE,
    ])
    ->withSkip([
        // Rewrites `->toBe([])` as `->toBeEmpty()`, which is a weaker
        // assertion wearing a shorter name: `toBeEmpty` also passes on null,
        // on 0 and on ''. This suite asserts that no `.tmp` file survives a
        // failed write by checking `glob()` returns exactly `[]`, and that an
        // empty secret round-trips as exactly `''`. Taking those is losing
        // the test.
        SimplifyToLiteralBooleanRector::class,

        // Welds consecutive `expect()` statements into one `->and()` chain.
        // The tests here are written as paragraphs — an action, a blank line,
        // a comment saying what to look at, then what it should be. The chain
        // is one sentence, so the comment has nowhere to stand and the
        // separation that carried the argument goes.
        ChainExpectCallsRector::class,
    ]);
