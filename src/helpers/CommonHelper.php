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
     * @param $header
     * @return bool|string
     */
    public static function getNonceFromResponseHeader($header)
    {
        if (!preg_match('/Replay-Nonce:\s*(\S+)/i', $header, $matches))
        {
            return FALSE;
        }

        return trim($matches[1]);
    }
}
