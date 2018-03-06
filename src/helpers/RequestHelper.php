<?php
/**
 * RequestHelper class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stonemax\acme2\helpers;

use stonemax\acme2\Client;
use stonemax\acme2\constants\CommonConstant;
use stonemax\acme2\exceptions\RequestException;

/**
 * Class RequestHelper
 * @package stonemax\acme2\helpers
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
        return self::run(
            $url,
            CommonConstant::REQUEST_TYPE_GET
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
        return self::run(
            $url,
            CommonConstant::REQUEST_TYPE_POST,
            $data
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
        return self::run(
            $url,
            CommonConstant::REQUEST_TYPE_HEAD
        );
    }

    /**
     * Make http request
     * @param string $url
     * @param string $requestType
     * @param string|null $data
     * @return array
     * @throws RequestException
     */
    public static function run($url, $requestType, $data = NULL)
    {
        $handler = self::getHandler($url, $requestType, $data);

        $response = curl_exec($handler);

        if($errorString = curl_errno($handler))
        {
            throw new RequestException("Request to {$url}({$requestType}) failed, the error message is: {$errorString}");
        }

        $info = curl_getinfo($handler);
        $header = trim(substr($response, 0, $info['header_size']));
        $body = trim(substr($response, $info['header_size']));

        /* Get replay nonce from this request's header */
        if ($nonce = CommonHelper::getNonceFromResponseHeader($header))
        {
            Client::$runtime->nonce->set($nonce);
        }

        $bodyDecoded = json_decode(trim($body), TRUE);

        return [
            intval($info['http_code']),                      // response http status code
            $header,                                         // response http header
            $bodyDecoded !== NULL ? $bodyDecoded : $body,    // response data
        ];
    }

    /**
     * Get curl handler
     * @param string $url
     * @param string $requestType
     * @param string|null $data
     * @return resource
     * @throws RequestException
     */
    public static function getHandler($url, $requestType, $data)
    {
        $header = [
            'Accept: application/json',
            'Content-Type: application/json',
            'User-Agent: '.Client::$runtime->params['software'].'/'.Client::$runtime->params['version'],
        ];

        $handler = curl_init($url);

        curl_setopt($handler, CURLOPT_HTTPHEADER, $header);
        curl_setopt($handler, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($handler, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($handler, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($handler, CURLOPT_FOLLOWLOCATION, TRUE);
        curl_setopt($handler, CURLOPT_HEADER, TRUE);
        curl_setopt($handler, CURLOPT_RETURNTRANSFER, TRUE);

        switch ($requestType)
        {
            case CommonConstant::REQUEST_TYPE_GET:
                break;

            case CommonConstant::REQUEST_TYPE_POST:
                curl_setopt($handler, CURLOPT_POST, TRUE);
                curl_setopt($handler, CURLOPT_POSTFIELDS, $data);

                break;

            case CommonConstant::REQUEST_TYPE_HEAD:
                curl_setopt($handler, CURLOPT_CUSTOMREQUEST, CommonConstant::REQUEST_TYPE_HEAD);
                curl_setopt($handler, CURLOPT_NOBODY, TRUE);

                break;

            default:
                throw new RequestException("Request type is invalid({$requestType})");
        }

        return $handler;
    }
}
