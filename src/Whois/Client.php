<?php
namespace Whois;

class Client
{
    /**
     * Container for the Servers class.
     *
     * @var Servers
     */
    private $servers;

    /**
     * Constructor.
     *
     * @param Servers $servers Class containing the Whois servers.
     */
    public function __construct(Servers $servers = null)
    {
        // Check if $servers is null
        if ($servers == null) {
            // Assign the standard Servers class
            $servers = Servers::class;
        }

        // Apply the servers
        $this->servers = $servers;
    }

    /**
     * Loop up a target (ip/domain) on whois
     *
     * @param string $target The target domain/ip.
     *
     * @throws WhoisException if the given target doesn't validate as an IP or domain.
     *
     * @return Result The response from the whois server
     */
    public function lookup($target)
    {
        // Check if IP
        if (filter_var($target, FILTER_VALIDATE_IP)) {
            return $this->lookupIP($target);
        }

        // Check if domain
        if ($this->verifyDomainName($target)) {
            return $this->lookupDomain($target);
        }

        // Throw an error if both are false
        throw new WhoisException('The target supplied does not appear to be a valid IP or domain name.');
    }

    private function lookupDomain($target)
    {
        // Make target completely lowercase
        $target = strtolower($target);

        // Split the dots
        $targetSplit = explode('.', $target);

        // Create server variable
        $server = null;

        // Select a server
        while (count($targetSplit)) {
            // Glue array
            $tld = implode($targetSplit, '.');

            // Check if it exists in the tld servers variable
            if (array_key_exists($tld, $this->servers::$tld)) {
                $server = $this->servers::$tld[$tld];
                break;
            }

            // Remove first entry
            array_shift($targetSplit);
        }

        // If we get here and $server is still null throw an exception
        if ($server === null) {
            throw new WhoisException('No whois server found for this domain.');
        }

        // Create a Result object
        $result = new Result();

        // Set the domain
        $result->target = $target;

        // Set the type
        $result->type = 'domain';

        // Create responses container
        $responses = [];

        // Query the server
        $response = $this->query($target, $server);

        // Process the data if anything was returned
        if ($response) {
            // Add the response to the array
            $responses[$server] = $response;

            // Check if there's a secondary whois server
            if ($position = strpos(strtolower($response), 'whois server:')) {
                // Grab the uri from the response
                preg_match("/whois server: (.*)/", strtolower($response), $matches);

                // Set the secondary server
                $second = trim($matches[1]);

                // Check if it's not the same server
                if (trim(strtolower($server)) !== $second) {
                    // Do a query
                    $response = $this->query($target, $second);

                    // Check if that was something
                    if ($response) {
                        // Add it to the responses
                        $responses[$second] = $response;
                    }
                }
            }
        }

        // Set the count
        $result->count = count($responses);

        // Set the responses
        $result->responses = array_reverse($responses);

        // Return the result
        return $result;
    }

    /**
     * Whois an IP address.
     *
     * @param string $address The IP address to query.
     *
     * @return Result The whois results.
     */
    private function lookupIP($address)
    {
        // Create the responses storage array
        $responses = [];

        // Query every server in the IP list
        foreach ($this->servers::$ip as $server) {
            // Check if we haven't queried this server yet
            if (array_key_exists($server, $responses)) {
                continue;
            }

            // Query the server
            $responses[$server] = $this->query($address, $server);
        }

        // Create a result object
        $result = new Result();

        // Set target
        $result->target = $address;

        // Set the type
        $result->type = 'ip';

        // Set response count
        $result->count = count($responses);

        // Set responses
        $result->responses = array_reverse($responses);

        // Return the Result object
        return $result;
    }

    /**
     * Validates a domain name.
     *
     * @param string $domain The string to validate as a domain.
     *
     * @return bool will be positive if the string is a domain.
     */
    private function verifyDomainName($domain)
    {
        return (preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $domain) // Valid chars check
             && preg_match("/^.{1,253}$/", $domain) // Overall length check
             && preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $domain)); // Length of each label
    }

    /**
     * Query the whois server.
     *
     * @param string $target The target IP/domain.
     * @param string $server The server to be queried.
     * @param int $port The port for the whois server.
     * @param int $timeout The timeout.
     *
     * @throws WhoisException if the socket failed to open.
     *
     * @return string The response from the whois server.
     */
    private function query($target, $server, $port = 43, $timeout = 5)
    {
        // Create the socket
        $sock = @fsockopen($server, $port, $errno, $errstr, $timeout);

        // Check for errors
        if (!$sock) {
            // Throw an exception with the error string
            throw new WhoisException($errstr);
        }

        // Write the target to the socket
        fwrite($sock, $target . "\r\n");

        // Create storage variable
        $response = '';

        // Await output
        while ($line = fgets($sock)) {
            $response .= $line;
        }

        // Close the socket
        fclose($sock);

        // Return the response
        return $response;
    }
}
