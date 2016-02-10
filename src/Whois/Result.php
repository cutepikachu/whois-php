<?php
namespace Whois;

class Result
{
    /**
     * The target whois domain/ip.
     *
     * @var string
     */
    public $target = '';

    /**
     * The amount of whois results.
     *
     * @var int
     */
    public $count = 0;

    /**
     * The results in order from last to first
     *
     * @var array
     */
    public $responses = [];

    /**
     * The result type.
     * Possible values are empty, domain and ip.
     *
     * @var string
     */
    public $type = 'empty';
}
