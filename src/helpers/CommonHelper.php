<?php
/**
 * CommonHelper class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stomemax\acme2\helpers;

/**
 * Class CommonHelper
 * @package stomemax\acme2\helpers
 */
class CommonHelper
{
    /**
     * Base64 url safe encode
     * @param string $string
     * @return mixed
     */
    public static function base64UrlSafeEncode($string)
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($string));
    }

    /**
     * Get replay nonce from http response header
     * @param string $header
     * @return bool|string
     */
    public static function getNonceFromResponseHeader($header)
    {
        return self::getFieldFromHeader('Replay-Nonce', $header);
    }

    /**
     * Get location field from http response header
     * @param string $header
     * @return bool|string
     */
    public static function getLocationFiledFromHeader($header)
    {
        return self::getFieldFromHeader('Location', $header);
    }

    /**
     * Get field from http response header
     * @param string $field
     * @param string $header
     * @return bool|string
     */
    public static function getFieldFromHeader($field, $header)
    {
        if (!preg_match("/{$field}:\s*(\S+)/i", $header, $matches))
        {
            return FALSE;
        }

        return trim($matches[1]);
    }

    /**
     * Check http challenge locally
     * @param string $domain
     * @param string $fileName
     * @param string $fileContent
     * @return bool
     * @throws \stomemax\acme2\exceptions\RequestException
     */
    public static function checkHttpChallenge($domain, $fileName, $fileContent)
    {
        $baseUrl = "{$domain}/.well-known/acme-challenge/{$fileName}";

        foreach (['http', 'https'] as $schema)
        {
            $url = "{$schema}://$baseUrl";

            list(, , $body) = RequestHelper::get($url);

            if ($body == $fileContent)
            {
                return TRUE;
            }
        }

        return FALSE;
    }

    /**
     * Check dns challenge locally
     * @param string $domain
     * @param string $dnsContent
     * @return bool
     */
    public static function checkDNSChallenge($domain, $dnsContent)
    {
        $host = '_acme-challenge.'.str_replace('*.', '', $domain);
        $recordList = dns_get_record($host, DNS_TXT);

        foreach ($recordList as $record)
        {
            if ($record['host'] == $host && $record['type'] == 'TXT' && $record['txt'] == $dnsContent)
            {
                return TRUE;
            }
        }

        return FALSE;
    }
}
