<?php

namespace Fernet;

/**
 * Fernet Token implementation, based on this spec:
 * https://github.com/fernet/spec
 *
 * PHP version 5.6 or above
 *
 * @category Authentication
 * @author   Viet Pham <viet@webonyx.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/webonyx/php-fernet
 */
class Fernet
{

    const VERSION = "\x80";

    /**
     * @var string
     */
    private $encryptionKey;

    /**
     * @var string
     */
    private $signingKey;

    /**
     * Creates an instance of the Fernet encoder/decoder
     *
     * @param $key string Fernet key, encoded in base64url format
     * @throws \Exception
     */
    public function __construct($key)
    {
        if (!extension_loaded('openssl') && !extension_loaded('mcrypt')) {
            throw new \Exception('No backend library found');
        }

        $key = self::urlsafeB64Decode($key);
        if (strlen($key) != 32) {
            throw new \Exception('Incorrect key. Hint: The key must be base64 encoded 32-byte');
        }

        $this->signingKey = substr($key, 0, 16);
        $this->encryptionKey = substr($key, 16);
    }

    /**
     * Encodes a Fernet token.
     *
     * @param string $message the message to be encoded in the token
     * @return string
     * @throws \Exception
     */
    public function encode($message)
    {
        if (!is_string($message)) {
            throw new TypeException("'message' type must be string");
        }

        $iv = $this->getIV();

        // PKCS7 padding
        $pad = 16 - (strlen($message) % 16);
        $message .= str_repeat(chr($pad), $pad);

        if (function_exists('openssl_encrypt')) {
            $ciphertext = base64_decode(openssl_encrypt($message, 'aes-128-cbc', $this->encryptionKey, OPENSSL_ZERO_PADDING, $iv));
        } else {
            $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->encryptionKey, $message, 'cbc', $iv);
        }

        $signing_base = self::VERSION . pack('NN', 0, $this->getTime()) . $iv . $ciphertext;
        $hash = hash_hmac('sha256', $signing_base, $this->signingKey, true);

        return self::urlsafeB64Encode($signing_base . $hash);
    }

    /**
     * Decodes a Fernet token.
     *
     * @param string $token the token to decode
     * @param int $ttl the maximum number of seconds since the creation of the
     * token for the token to be considered valid
     * @return string|null the decoded message, or null if the token is invalid
     * for whatever reason.
     *
     * @return bool|null|string
     * @throws Exception
     */
    public function decode($token, $ttl = null)
    {
        if (!is_string($token)) {
            throw new TypeException("'message' type must be string");
        }

        $raw = self::urlsafeB64Decode($token);
        $hash = substr($raw, -32);
        if (!is_string($hash)) {
            throw new InvalidTokenException();
        }

        $signing_base = substr($raw, 0, -32);
        $expected_hash = hash_hmac('sha256', $signing_base, $this->signingKey, true);

        // Timing attack safe string comparison
        if (!hash_equals($hash, $expected_hash)) {
            throw new InvalidTokenException("Invalid signature");
        }

        $parts = unpack('Cversion/Ndummy/Ntime', substr($signing_base, 0, 9));
        if (chr($parts['version']) != self::VERSION) {
            throw new InvalidTokenException("Token version mismatched");
        }

        if ($ttl != null) {
            if ($parts['time'] + $ttl < $this->getTime()) {
                throw new InvalidTokenException("Token is expired");
            }
        }

        $iv = substr($signing_base, 9, 16);
        $ciphertext = substr($signing_base, 25);

        if (function_exists('openssl_decrypt')) {
            $message = openssl_decrypt(base64_encode($ciphertext), 'aes-128-cbc', $this->encryptionKey, OPENSSL_ZERO_PADDING, $iv);
        } else {
            $message = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->encryptionKey, $ciphertext, 'cbc', $iv);
        }

        $pad = ord($message[strlen($message) - 1]);
        if (substr_count(substr($message, -$pad), chr($pad)) != $pad) {
            throw new InvalidTokenException("Token is malformed");
        }

        return substr($message, 0, -$pad);
    }

    /**
     * Generates an initialisation vector for AES encryption
     *
     * @return string a bytestream containing an initialisation vector
     * @throws \Exception
     */
    protected function getIV()
    {
        return random_bytes(16);
    }

    /**
     * Obtains the current time.
     *
     * @return int the current time
     */
    protected function getTime()
    {
        return time();
    }

    /**
     * Generates a random key
     *
     * @return string
     * @throws \Exception
     */
    static public function generateKey()
    {
        return self::urlsafeB64Encode(random_bytes(32));
    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     *
     * @return string The base64 encode of what you passed in
     */
    public static function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     */
    public static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }

        return base64_decode(strtr($input, '-_', '+/'));
    }
}
