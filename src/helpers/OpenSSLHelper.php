<?php
/**
 * OpenSSLHelper class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stomemax\acme2\helpers;

use stomemax\acme2\exceptions\OpenSSLException;

/**
 * Class OpenSSLHelper
 * @package stomemax\acme2\helpers
 */
class OpenSSLHelper
{
    /**
     * Genarate rsa public/private key pair
     * @return array
     * @throws OpenSSLException
     */
    public static function generateRSAKeyPair()
    {
        $resource = openssl_pkey_new([
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "private_key_bits" => 4096,
        ]);

        if ($resource === FALSE)
        {
            throw new OpenSSLException("Generate rsa key pair failed.");
        }

        if (openssl_pkey_export($resource, $privateKey) === FALSE)
        {
            throw new OpenSSLException("Export private key failed.");
        }

        $detail = openssl_pkey_get_details($resource);

        if ($detail === FALSE)
        {
            throw new OpenSSLException("Get key details failed.");
        }

        openssl_pkey_free($resource);

        return [
            'privateKey' => $privateKey,
            'publicKey' => $detail['key'],
        ];
    }
}
