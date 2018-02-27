<?php
/**
 * RequestHelper class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stomemax\acme2\helpers;

use stomemax\acme2\Client;
use stomemax\acme2\exceptions\RequestException;

/**
 * Class RequestHelper
 * @package stomemax\acme2\helpers
 */
class RequestHelper
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
            "User-Agent: ".Client::$runtime->params['software'].'/'.Client::$runtime->params['version'],
            "Connection: close{$crlf}{$crlf}",
        ];

        return self::run(
            $urlMap['hostWithSchema'],
            $urlMap['port'],
            implode($crlf, $requestData)
        );
    }

    /**
     * Make http POST request
     * @param string $url
     * @param string $data
     * @return array
     * @throws RequestException
     */
    public static function post($url, $data)
    {
        $crlf = "\r\n";
        $urlMap = self::parseUrl($url);

        $requestData = [
            "POST {$urlMap['path']}{$urlMap['query']} HTTP/1.1",
            "Host: {$urlMap['host']}",
            "Accept: application/json",
            "User-Agent: ".Client::$runtime->params['software'].'/'.Client::$runtime->params['version'],
            "Connection: close",
            "Content-Type: application/json",
            "Content-Length: ".strlen($data).$crlf,
            $data
        ];

        return self::run(
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
            "User-Agent: ".Client::$runtime->params['software'].'/'.Client::$runtime->params['version'],
            "Connection: close{$crlf}{$crlf}",
        ];

        return self::run(
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
    public static function run($hostWithSchema, $port, $requestData)
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

        /* Get replay nonce from this request's header */
        if ($nonce = CommonHelper::getNonceFromResponseHeader($header))
        {
            Client::$runtime->nonce->set($nonce);
        }

        preg_match('/\d{3}/', trim($header), $matches);

        $body = trim($body);
        $bodyDecoded = json_decode(trim($body), TRUE);

        return [
            intval($matches[0]),                             // response http status code
            $header,                                         // response http header
            $bodyDecoded !== NULL ? $bodyDecoded : $body,    // response data
        ];
    }
}
