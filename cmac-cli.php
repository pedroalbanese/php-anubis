#!/usr/bin/env php
<?php
/**
 * Anubis CMAC Command Line Interface
 */

require_once 'Anubis-CTR.php';

class AnubisCMACCLI {
    private $anubis;
    
    public function __construct($key) {
        // Ensure key is 16 bytes
        if (strlen($key) !== 16) {
            if (strlen($key) > 16) {
                $key = substr($key, 0, 16);
            } else {
                $key = str_pad($key, 16, "\0");
            }
        }
        $this->anubis = new Anubis($key);
    }
    
    public function generate($message) {
        return $this->anubis->generate($message);
    }
    
    public function verify($message, $tag) {
        $generated = $this->generate($message);
        
        if (strlen($tag) === 32 && ctype_xdigit($tag)) {
            $tag = hex2bin($tag);
        }
        
        return hash_equals($generated, $tag);
    }
}

function printHelp() {
    echo "Anubis CMAC CLI\n";
    echo "===============\n\n";
    echo "SYNOPSIS\n";
    echo "    php " . basename(__FILE__) . " [OPTIONS]\n\n";
    echo "DESCRIPTION\n";
    echo "    Generate or verify CMAC (Cipher-based Message Authentication Code)\n";
    echo "    using the Anubis block cipher.\n\n";
    echo "OPTIONS\n";
    echo "    -g, --generate          Generate CMAC tag\n";
    echo "    -v, --verify            Verify CMAC tag\n";
    echo "    -m, --message TEXT      Input message\n";
    echo "    -M, --message-file FILE Read message from file\n";
    echo "    -k, --key KEY           Encryption key (16 bytes)\n";
    echo "    -K, --key-file FILE     Read key from file\n";
    echo "    -t, --tag TAG           CMAC tag for verification (hex)\n";
    echo "    -T, --tag-file FILE     Read tag from file\n";
    echo "    -q, --quiet             Quiet mode (no output except result)\n";
    echo "    -h, --help              Display this help\n\n";
    echo "EXAMPLES\n";
    echo "    Generate CMAC:\n";
    echo "        php " . basename(__FILE__) . " -g -m \"secret data\" -k \"0123456789ABCDEF\"\n\n";
    echo "    Verify CMAC:\n";
    echo "        php " . basename(__FILE__) . " -v -m \"secret data\" -k \"0123456789ABCDEF\" \\\n";
    echo "            -t \"a1b2c3d4e5f67890a1b2c3d4e5f67890\"\n\n";
    echo "    Read from files:\n";
    echo "        php " . basename(__FILE__) . " -g -M data.txt -K key.bin\n";
    exit(0);
}

function readInput($source) {
    if ($source === '-') {
        return stream_get_contents(STDIN);
    }
    
    if (file_exists($source)) {
        return file_get_contents($source);
    }
    
    return $source;
}

function parseArgs() {
    $shortOpts = "gvm:M:k:K:t:T:qh";
    $longOpts = [
        "generate",
        "verify",
        "message:",
        "message-file:",
        "key:",
        "key-file:",
        "tag:",
        "tag-file:",
        "quiet",
        "help"
    ];
    
    return getopt($shortOpts, $longOpts);
}

function main() {
    $args = parseArgs();
    
    // Show help if requested
    if (isset($args['h']) || isset($args['help'])) {
        printHelp();
    }
    
    // Check operation mode
    $generate = isset($args['g']) || isset($args['generate']);
    $verify = isset($args['v']) || isset($args['verify']);
    $quiet = isset($args['q']) || isset($args['quiet']);
    
    if (!$generate && !$verify) {
        fwrite(STDERR, "Error: Specify operation mode (--generate or --verify)\n");
        exit(1);
    }
    
    if ($generate && $verify) {
        fwrite(STDERR, "Error: Cannot both generate and verify\n");
        exit(1);
    }
    
    // Get message
    $message = '';
    if (isset($args['m']) || isset($args['message'])) {
        $message = $args['m'] ?? $args['message'];
        $message = readInput($message);
    } elseif (isset($args['M']) || isset($args['message-file'])) {
        $file = $args['M'] ?? $args['message-file'];
        $message = readInput($file);
    }
    
    if (empty($message)) {
        fwrite(STDERR, "Error: No message provided\n");
        exit(1);
    }
    
    // Get key
    $key = '';
    if (isset($args['k']) || isset($args['key'])) {
        $key = $args['k'] ?? $args['key'];
        $key = readInput($key);
    } elseif (isset($args['K']) || isset($args['key-file'])) {
        $file = $args['K'] ?? $args['key-file'];
        $key = readInput($file);
    }
    
    if (empty($key)) {
        fwrite(STDERR, "Error: No key provided\n");
        exit(1);
    }
    
    // Create CMAC instance
    try {
        $cmac = new AnubisCMACCLI($key);
    } catch (Exception $e) {
        fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
        exit(1);
    }
    
    // Perform operation
    if ($generate) {
        $tag = $cmac->generate($message);
        echo bin2hex($tag) . "\n";
        exit(0);
    }
    
    if ($verify) {
        // Get tag for verification
        $tag = '';
        if (isset($args['t']) || isset($args['tag'])) {
            $tag = $args['t'] ?? $args['tag'];
            $tag = readInput($tag);
        } elseif (isset($args['T']) || isset($args['tag-file'])) {
            $file = $args['T'] ?? $args['tag-file'];
            $tag = readInput($file);
        }
        
        if (empty($tag)) {
            fwrite(STDERR, "Error: No tag provided for verification\n");
            exit(1);
        }
        
        $isValid = $cmac->verify($message, $tag);
        
        if (!$quiet) {
            echo $isValid ? "CMAC verification: VALID\n" : "CMAC verification: INVALID\n";
        }
        
        exit($isValid ? 0 : 1);
    }
}

// Run the application
if (PHP_SAPI === 'cli') {
    main();
} else {
    echo "This script must be run from the command line.\n";
    exit(1);
}
