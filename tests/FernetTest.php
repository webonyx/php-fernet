<?php
namespace Fernet;

use PHPUnit_Framework_TestCase;

class FernetTest extends PHPUnit_Framework_TestCase
{
    public static $opensslVerifyReturnValue;

    public function testEncodeDecode()
    {
        $key = Fernet::generateKey();
        $fernet = new Fernet($key);

        $msg = $fernet->encode('abc');
        $this->assertEquals($fernet->decode($msg), 'abc');
    }
}
