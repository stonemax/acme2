<?php
/**
 * RequestHelper class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php  MIT License
 */

namespace stomemax\acme2\helpers;

use stomemax\acme2\exceptions\RequestException;

/**
 * Class RequestHelper
 * @package stomemax\acme2\helpers
 */
class Request
{
    /**
     * Make http GET request
     * @param string $url
     * @return array
     * @throws RequestException
     */
    public static function get($url)
    {
        $crlf = "\r\n";
        $urlMap = self::parseUrl($url);

        $requestData = [
            "GET {$urlMap['path']}{$urlMap['query']} HTTP/1.1",
            "Host: {$urlMap['host']}",
            "Accept: application/json",
            "Connection: close{$crlf}{$crlf}",
        ];

        return self::doRequest(
            $urlMap['hostWithSchema'],
            $urlMap['port'],
            implode($crlf, $requestData)
        );
    }

    /**
     * Make http POST request
     * @param string $url
     * @param array $data
     * @return array
     * @throws RequestException
     */
    public static function post($url, $data)
    {
        $crlf = "\r\n";
        $urlMap = self::parseUrl($url);
        $data = json_encode($data);

        $requestData = [
            "POST {$urlMap['path']}{$urlMap['query']} HTTP/1.1",
            "Host: {$urlMap['host']}",
            "Accept: application/json",
            "Content-Type: application/json",
            "Content-Length: ".strlen($data).$crlf,
            $data
        ];

        return self::doRequest(
            $urlMap['hostWithSchema'],
            $urlMap['port'],
            implode($crlf, $requestData)
        );
    }

    /**
     * Make http HEAD request
     * @param string $url
     * @return array
     * @throws RequestException
     */
    public static function head($url)
    {
        $crlf = "\r\n";
        $urlMap = self::parseUrl($url);

        $requestData = [
            "HEAD {$urlMap['path']}{$urlMap['query']} HTTP/1.1",
            "Host: {$urlMap['host']}",
            "Accept: application/json",
            "Connection: close{$crlf}{$crlf}",
        ];

        return self::doRequest(
            $urlMap['hostWithSchema'],
            $urlMap['port'],
            implode($crlf, $requestData)
        );
    }

    /**
     * Parse url
     * @param string $url
     * @return array
     */
    public static function parseUrl($url)
    {
        $tmp = parse_url($url);

        $hostWithSchema = $tmp['scheme'] == 'https'
            ? "ssl://{$tmp['host']}"
            : "tcp://{$tmp['host']}";

        $port = isset($tmp['port'])
            ? intval($tmp['port'])
            : ($tmp['scheme'] == 'https' ? 443 : 80);

        return [
            'hostWithSchema' => $hostWithSchema,
            'host' => $tmp['host'],
            'port' => $port,
            'path' => isset($tmp['path']) ? $tmp['path'] : '/',
            'query' => isset($tmp['query']) ? '?'.$tmp['query'] : '',
        ];
    }

    /**
     * Make http request
     * @param string $hostWithSchema
     * @param integer $port
     * @param string $requestData
     * @return array
     * @throws RequestException
     */
    public static function doRequest($hostWithSchema, $port, $requestData)
    {
        $crlf = "\r\n";
        $response = '';
        $handler = fsockopen($hostWithSchema, $port, $errorNumber, $errorString, 10);

        if (!$handler)
        {
            throw new RequestException("Open http sock open failed, the error number is: {$errorNumber}, the error message is: {$errorString}");
        }

        fwrite($handler, $requestData);

        while (!feof($handler))
        {
            $response .= fread($handler, 128);
        }

        fclose($handler);

        list($header, $body) = explode($crlf.$crlf, $response, 2);

        preg_match('/\d{3}/', trim($header), $matches);

        return [
            'code' => intval($matches[0]),
            'data' => json_decode(trim($body), TRUE),
        ];
    }
}
