<?php

declare(strict_types=1);

namespace Dotlock;

use RuntimeException;

/**
 * Something went wrong with the vault, and the message is already written for
 * a person — a command can print it as-is.
 *
 * A wrong passphrase is not one of these. That is an ordinary answer to an
 * ordinary question, and it comes back as a `null` from the method that was
 * asked to open something. Exceptions here mean the file, the name or the
 * arguments are wrong, which is a different conversation.
 */
final class DotlockException extends RuntimeException {}
