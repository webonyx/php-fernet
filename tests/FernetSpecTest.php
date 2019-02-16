<?php

namespace Fernet;

use PHPUnit_Framework_TestCase;

class FernetMock extends Fernet
{
    private $time;

    public function __construct($key, $time)
    {
        parent::__construct($key);
        $this->time = $time;
    }

    protected function getTime()
    {
        return $this->time;
    }
}

class FernetGenerateMock extends FernetMock
{
    private $iv;

    public function __construct($key, $time, $iv)
    {
        parent::__construct($key, $time);
        $this->iv = $iv;
    }

    protected function getIV()
    {
        return $this->iv;
    }
}

class FernetSpecTest extends PHPUnit_Framework_TestCase
{
    public function __construct()
    {
        parent::__construct();
        date_default_timezone_set('UTC');
    }

    protected function getGenerateInstance($key, $time, $iv)
    {
        return new FernetGenerateMock($key, $time, $iv);
    }

    protected function getVerifyInstance($key, $time)
    {
        return new FernetMock($key, $time);
    }


    function testGenerate()
    {
        $tests = json_decode(file_get_contents(__DIR__ . '/spec/generate.json'));
        foreach ($tests as $test) {
            $iv = implode(array_map('chr', $test->iv));;
            $time = strtotime($test->now);
            // re-encode to remove ==
            $token = Fernet::urlsafeB64Encode(Fernet::urlsafeB64Decode($test->token));
            $fernet = $this->getGenerateInstance($test->secret, $time, $iv);
            $this->assertEquals($token, $fernet->encode($test->src));
        }
    }

    function testVerify()
    {
        $tests = json_decode(file_get_contents(__DIR__ . '/spec/verify.json'));
        foreach ($tests as $test) {
            $time = strtotime($test->now);
            $fernet = $this->getVerifyInstance($test->secret, $time);
            $this->assertEquals($test->src, $fernet->decode($test->token, $test->ttl_sec));
        }
    }

    function testInvalid()
    {
        $this->setExpectedException('Fernet\InvalidTokenException');
        $tests = json_decode(file_get_contents(__DIR__ . '/spec/invalid.json'));
        foreach ($tests as $test) {
            $time = strtotime($test->now);
            $fernet = $this->getVerifyInstance($test->secret, $time);
            $fernet->decode($test->token, $test->ttl_sec);
        }
    }
}
