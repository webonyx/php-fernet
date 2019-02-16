<?php

namespace Fernet;

/**
 * A wrapper to pack message using msgpack. An efficient way to reduce token size
 *
 * https://msgpack.org
 *
 * @category Authentication
 * @author   Viet Pham <viet@webonyx.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/webonyx/php-fernet
 */
class FernetMsgpack extends Fernet
{
    /**
     * Creates an instance of the FernetMsgpack encoder/decoder
     * Throw exception if a prerequisite extension is not installed
     *
     * @throws \Exception
     * @inheritdoc
     */
    public function __construct($key)
    {
        if (!extension_loaded('msgpack')) {
            throw new \Exception('msgpack is not installed');
        }

        parent::__construct($key);
    }

    /**
     * Encode a message. Accept types: string, array
     *
     * @inheritdoc
     */
    public function encode($message)
    {
        if (!is_string($message) && !is_array($message)) {
            throw new TypeException("'message' type must be either string or array");
        }

        $packedMessage = msgpack_pack($message);
        $token = parent::encode($packedMessage);

        return $token;
    }

    /**
     * @inheritdoc
     */
    public function decode($token, $ttl = null)
    {
        $packedMessage = parent::decode($token, $ttl);
        $message = msgpack_unpack($packedMessage);

        return $message;
    }
}
