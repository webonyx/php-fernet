<?php
namespace Fernet;

use PHPUnit_Framework_TestCase;

class FernetMsgpackTest extends PHPUnit_Framework_TestCase
{
    public function testEncodeDecode()
    {
        $key = Fernet::generateKey();
        $fernet = new FernetMsgpack($key);

        $msg = $fernet->encode('abc');
        $this->assertEquals($fernet->decode($msg), 'abc');
    }

    public function testEncodeDecodeArrayMessage()
    {
        $key = Fernet::generateKey();
        $fernet = new FernetMsgpack($key);

        $payload = ['id' => \random_bytes(32)];
        $msg = $fernet->encode($payload);
        $this->assertEquals($fernet->decode($msg), $payload);
    }
}
