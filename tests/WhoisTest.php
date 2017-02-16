<?php
use PHPUnit\Framework\TestCase;

use Whois\Client as WhoisClient;

class WhoisTest extends TestCase
{
    private static $client;

    public function testCreate()
    {
        static::$client = new WhoisClient;
    }

    public function testDomain()
    {
        static::$client->lookup('flash.moe');
    }

    public function testIP()
    {
        static::$client->lookup('8.8.8.8');
        static::$client->lookup('2001:4860:4860::8888');
    }

    /**
     * @expectedException \Whois\WhoisException
     */
    public function testException()
    {
        static::$client->lookup('not a domain');
    }
}
