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

use stomemax\acme2\Client;
use stomemax\acme2\constants\CommonConstant;
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
        return self::generateKeyPair(CommonConstant::KEY_PAIR_TYPE_RSA);
    }

    /**
     * Genarate ec public/private key pair
     * @return array
     * @throws OpenSSLException
     */
    public static function generateECKeyPair()
    {
        return self::generateKeyPair(CommonConstant::KEY_PAIR_TYPE_EC);
    }

    /**
     * Generate private/public key pair
     * @param $type
     * @return array
     * @throws OpenSSLException
     */
    public static function generateKeyPair($type)
    {
        $configMap = [
            CommonConstant::KEY_PAIR_TYPE_RSA => [
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
                'private_key_bits' => 4096,
            ],

            CommonConstant::KEY_PAIR_TYPE_EC => [
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'curve_name' => 'prime256v1',
            ],
        ];

        $typeNameMap = [
            CommonConstant::KEY_PAIR_TYPE_RSA => 'RSA',
            CommonConstant::KEY_PAIR_TYPE_EC => 'EC',
        ];

        $resource = openssl_pkey_new($configMap[$type]);

        if ($resource === FALSE)
        {
            throw new OpenSSLException("Generate {$typeNameMap[$type]} key pair failed.");
        }

        if (openssl_pkey_export($resource, $privateKey) === FALSE)
        {
            throw new OpenSSLException("Export {$typeNameMap[$type]} private key failed.");
        }

        $detail = openssl_pkey_get_details($resource);

        if ($detail === FALSE)
        {
            throw new OpenSSLException("Get {$typeNameMap[$type]} key details failed.");
        }

        openssl_pkey_free($resource);

        return [
            'privateKey' => $privateKey,
            'publicKey' => $detail['key'],
        ];
    }

    /**
     * Generate JWS(Json Web Signature) with field `jwk`
     * @param string $url
     * @param array|string $payload
     * @param string|null $privateKey
     * @return string
     * @throws \stomemax\acme2\exceptions\NonceException
     * @throws \stomemax\acme2\exceptions\RequestException
     */
    public static function generateJWSOfJWK($url, $payload, $privateKey = NULL)
    {
        $privateKey = openssl_pkey_get_private($privateKey ?: Client::$runtime->account->getPrivateKey());
        $detail = openssl_pkey_get_details($privateKey);

        $protected = [
            'alg' => 'RS256',
            'jwk' => [
                'kty' => 'RSA',
                'n' => CommonHelper::base64UrlSafeEncode($detail['rsa']['n']),
                'e' => CommonHelper::base64UrlSafeEncode($detail['rsa']['e']),
            ],
            'nonce' => Client::$runtime->nonce->get(),
            'url' => $url,
        ];

        $protectedBase64 = CommonHelper::base64UrlSafeEncode(json_encode($protected));
        $payloadBase64 = CommonHelper::base64UrlSafeEncode(is_array($payload) ? json_encode($payload) : $payload);

        openssl_sign($protectedBase64.'.'.$payloadBase64, $signature, $privateKey, 'SHA256');
        $signatureBase64 = CommonHelper::base64UrlSafeEncode($signature);

        return json_encode([
            'protected' => $protectedBase64,
            'payload' => $payloadBase64,
            'signature' => $signatureBase64,
        ]);
    }

    /**
     * Generate JWS(Json Web Signature) with field `kid`
     * @param string $url
     * @param string $kid
     * @param array|string $payload
     * @return string
     * @throws \stomemax\acme2\exceptions\NonceException
     * @throws \stomemax\acme2\exceptions\RequestException
     */
    public static function generateJWSOfKid($url, $kid, $payload)
    {
        $privateKey = openssl_pkey_get_private(Client::$runtime->account->getPrivateKey());

        $protected = [
            'alg' => 'RS256',
            'kid' => $kid,
            'nonce' => Client::$runtime->nonce->get(),
            'url' => $url,
        ];

        $protectedBase64 = CommonHelper::base64UrlSafeEncode(json_encode($protected));
        $payloadBase64 = CommonHelper::base64UrlSafeEncode(is_array($payload) ? json_encode($payload) : $payload);

        openssl_sign($protectedBase64.'.'.$payloadBase64, $signature, $privateKey, 'SHA256');
        $signatureBase64 = CommonHelper::base64UrlSafeEncode($signature);

        return json_encode([
            'protected' => $protectedBase64,
            'payload' => $payloadBase64,
            'signature' => $signatureBase64,
        ]);
    }
}
