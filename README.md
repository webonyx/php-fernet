# PHP-Fernet

Fernet-PHP implementation of the [Fernet token specification](https://github.com/fernet/spec/blob/master/Spec.md)
in PHP. This is a fork of Kelvinmo implementation at [fernet-php](https://github.com/kelvinmo/fernet-php) with some improvements:

- Drop supporting old PHP versions
- Exception base for error handling
- Support `msgpack` wrapper to reduce token size
- _Key rotation (TBD)_


## Requirements

- PHP 5.6 or later
- `hash` extension
- `openssl` or `mcrypt` extension
- `mbstring.func_overload` needs to be switched **off** in `php.ini`

## Installation

You can install via [Composer](http://getcomposer.org/).

```json
{
    "require": {
        "webonyx/php-fernet": "dev-master"
    }
}
```

## Usage

```php
<?php
require 'vendor/autoload.php';

use Fernet\Fernet;
use Fernet\InvalidTokenException;

$key = '[Base64url encoded fernet key]'; // or $key = Fernet::generateKey();
$fernet = new Fernet($key); // or new FernetMsgpack($key);

$token = $fernet->encode('string message');

try {
    $message = $fernet->decode('fernet token');
} catch (InvalidTokenException $exception) {
    echo 'Token is not valid';
}
?>
```

## License

BSD 3 clause
