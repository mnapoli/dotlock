<?php

declare(strict_types=1);

namespace Dotlock;

/**
 * The plain `.env`, read and edited one line at a time.
 *
 * This exists so that moving a secret out does not reformat somebody's `.env`.
 * The file is rewritten by replacing exactly one line and copying every other
 * byte through — comments, blank lines, ordering and all. A dotenv writer that
 * regenerates the file from a parsed array would lose all of that, and the
 * diff would bury the one change that matters.
 */
final readonly class EnvFile
{
    public function __construct(private string $path) {}

    public function path(): string
    {
        return $this->path;
    }

    public function exists(): bool
    {
        return is_file($this->path);
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->values());
    }

    public function get(string $name): ?string
    {
        return $this->values()[$name] ?? null;
    }

    /**
     * @return array<string, string>
     */
    public function values(): array
    {
        $values = [];

        foreach ($this->lines() as $line) {
            $assignment = $this->assignment($line);

            if ($assignment !== null) {
                $values[$assignment[0]] = $assignment[1];
            }
        }

        return $values;
    }

    /**
     * Replace the assignment with a comment saying where the value went.
     *
     * A marker rather than a deletion: `.env` is where anyone looks first, and
     * a name that has simply vanished reads as never configured. This way the
     * file still answers the question, it just answers it differently.
     */
    public function moveOut(string $name, string $marker): void
    {
        $lines = $this->lines();
        $found = false;

        foreach ($lines as $index => $line) {
            $assignment = $this->assignment($line);

            if ($assignment === null || $assignment[0] !== $name) {
                continue;
            }

            // Carriage returns are kept so a CRLF file does not end up with one
            // stray line in the other convention.
            $lines[$index] = $marker.(str_ends_with($line, "\r") ? "\r" : '');
            $found = true;
        }

        if (! $found) {
            throw new DotlockException("{$name} is not set in {$this->path}, so there is nothing to move.");
        }

        if (@file_put_contents($this->path, implode("\n", $lines)) === false) {
            throw new DotlockException("Could not write {$this->path}.");
        }
    }

    /**
     * @return list<string>
     */
    private function lines(): array
    {
        if (! $this->exists()) {
            return [];
        }

        $contents = @file_get_contents($this->path);

        if ($contents === false) {
            throw new DotlockException("{$this->path} exists but could not be read.");
        }

        return explode("\n", $contents);
    }

    /**
     * The name and value on this line, or null if it does not set one.
     *
     * @return array{0: string, 1: string}|null
     */
    private function assignment(string $line): ?array
    {
        $trimmed = trim($line);

        if ($trimmed === '' || str_starts_with($trimmed, '#')) {
            return null;
        }

        if (str_starts_with($trimmed, 'export ')) {
            $trimmed = ltrim(substr($trimmed, 7));
        }

        if (! preg_match('/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s', $trimmed, $matches)) {
            return null;
        }

        return [$matches[1], $this->unquote($matches[2])];
    }

    private function unquote(string $value): string
    {
        $value = trim($value);

        foreach (['"', "'"] as $quote) {
            if (! str_starts_with($value, $quote)) {
                continue;
            }

            $closing = strrpos($value, $quote);

            if ($closing === 0) {
                // The value opens a quote it never closes, which means it runs
                // on to the next line. Refusing beats rewriting three lines
                // when we meant to rewrite one.
                throw new DotlockException(
                    'This value spans several lines in .env. Move it across by hand.',
                );
            }

            $value = substr($value, 1, $closing - 1);

            return $quote === '"'
                ? str_replace(['\\n', '\\"', '\\\\'], ["\n", '"', '\\'], $value)
                : $value;
        }

        // Unquoted values end at an inline comment, the way dotenv reads them.
        $comment = strpos($value, ' #');

        return rtrim($comment === false ? $value : substr($value, 0, $comment));
    }
}
