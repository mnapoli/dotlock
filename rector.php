<?php

declare(strict_types=1);

use Rector\CodeQuality\Rector\ClassMethod\LocallyCalledStaticMethodToNonStaticRector;
use Rector\CodeQuality\Rector\If_\ExplicitBoolCompareRector;
use Rector\CodingStyle\Rector\Catch_\CatchExceptionNameMatchingTypeRector;
use Rector\CodingStyle\Rector\ClassMethod\MakeInheritedMethodVisibilitySameAsParentRector;
use Rector\CodingStyle\Rector\Encapsed\EncapsedStringsToSprintfRector;
use Rector\Config\RectorConfig;
use Rector\EarlyReturn\Rector\If_\ChangeOrIfContinueToMultiContinueRector;
use Rector\Php83\Rector\ClassMethod\AddOverrideAttributeToOverriddenMethodsRector;
use Rector\Privatization\Rector\MethodCall\PrivatizeLocalGetterToPropertyRector;

return RectorConfig::configure()
    ->withPaths([
        __DIR__.'/src',
    ])
    ->withPreparedSets(
        deadCode: true,
        codeQuality: true,
        typeDeclarations: true,
        privatization: true,
        earlyReturn: true,
        codingStyle: true,
    )
    ->withPhpSets()
    ->withSkip([
        // `#[Override]` on every framework method we implement is a lot of
        // noise for a fact the signature already carries.
        AddOverrideAttributeToOverriddenMethodsRector::class,

        // The rules below are skipped for one reason between them: this
        // codebase is written to be read, and each of these trades a sentence
        // for a construction.

        // `"{$name} is gone."` becomes `sprintf('%s is gone.', $name)`. The
        // first one is the sentence you are printing.
        EncapsedStringsToSprintfRector::class,

        // Renames the caught exception after its class, so `catch (DotlockException
        // $failure)` becomes `$dotlockException`. The name was chosen — it says
        // what happened, which the type already told you it was.
        CatchExceptionNameMatchingTypeRector::class,

        // A private static helper is a deliberate signal here: it touches
        // nothing on the instance. Making it non-static because it happens to
        // be called from one throws that away.
        LocallyCalledStaticMethodToNonStaticRector::class,
        PrivatizeLocalGetterToPropertyRector::class,

        // Widening a method's visibility to match a parent we are not trying
        // to be substitutable for.
        MakeInheritedMethodVisibilitySameAsParentRector::class,

        // Rewrites readable conditions into explicit comparisons that say no
        // more than they did. Strictness is PHPStan's job here, at level 10.
        ExplicitBoolCompareRector::class,

        // Splits `if ($a === null || $a[0] !== $name) { continue; }` into two
        // guards. One skip condition read as one sentence is the clearer of
        // the two.
        ChangeOrIfContinueToMultiContinueRector::class,
    ]);
