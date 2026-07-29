<?php

declare(strict_types=1);

namespace Dotlock\Console\Concerns;

trait MasksValues
{
    /**
     * Enough of a value to recognise it, never enough to use it.
     *
     * Short values show nothing at all: four characters with two of them
     * printed is not a mask, and a secret short enough for that is one you can
     * afford to look up properly.
     */
    protected function mask(string $value): string
    {
        $length = mb_strlen($value);

        if ($length < 12) {
            return str_repeat('•', max($length, 1));
        }

        return mb_substr($value, 0, 3).str_repeat('•', 8).mb_substr($value, -2);
    }
}
