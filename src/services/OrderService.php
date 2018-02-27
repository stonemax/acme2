<?php
/**
 * OrderService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stomemax\acme2\services;
use stomemax\acme2\Client;
use stomemax\acme2\constants\CommonConstant;
use stomemax\acme2\exceptions\OrderException;
use stomemax\acme2\helpers\CommonHelper;
use stomemax\acme2\helpers\OpenSSLHelper;
use stomemax\acme2\helpers\RequestHelper;

/**
 * Class OrderService
 * @package stomemax\acme2\services
 */
class OrderService
{
    public $status;

    public $expires;

    public $identifiers;

    public $authorizations;

    public $finalize;

    public $orderUrl;

    private $_authorizationList;

    private $_baseDomain;

    private $_domainList;

    private $_algorithm;

    private $_notBefore;

    private $_notAfter;

    public function __construct($baseDomain, $domainList, $algorithm, $notBefore = '', $notAfter = '')
    {
        $this->_baseDomain = $baseDomain;
        $this->_domainList = $domainList;
        $this->_algorithm = $algorithm;
        $this->_notBefore = $notBefore;
        $this->_notAfter = $notAfter;
    }

    public function createOrder()
    {
        $identifierList = [];

        foreach ($this->_domainList as $domain)
        {
            $identifierList[] = [
                'type' => 'dns',
                'value' => $domain,
            ];
        }

        $payload = [
            'identifiers' => $identifierList,
            'notBefore' => $this->_notBefore,
            'notAfter' => $this->_notAfter,
        ];

        $jws = OpenSSLHelper::generateJWSOfKid(
            Client::$runtime->endpoint->newOrder,
            Client::$runtime->account->getAccountUrl(),
            $payload
        );

        list($code, $header, $body) = RequestHelper::post(Client::$runtime->endpoint->newOrder, $jws);

        if ($code != 201)
        {
            throw new OrderException('Create order failed, the domain list is: '.implode(', ', $this->_domainList).", the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        if (($orderUrl = CommonHelper::getLocationFiledFromHeader($header)) === FALSE)
        {
            throw new OrderException('Get order url failed during order creation, the domain list is: '.implode(', ', $this->_domainList));
        }

        $orderInfo = array_merge($body, ['orderUrl' => $orderUrl]);

        $this->populate($orderInfo);

        return $orderInfo;
    }

    public function getOrder()
    {
        $orderUrl = $this->getOrderUrl();

        list($code, $header, $body) = RequestHelper::get($orderUrl);

        if ($code != 200)
        {
            throw new OrderException("Get order info failed, the order url is: {$orderUrl}, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        $this->populate($body);

        return [$body, ['orderUrl' => $orderUrl]];
    }

    public function getOrderUrl()
    {
        return '';
    }

    public function getPendingChallenge($type)
    {
        $challengeList = [];
        $thumbprint = $this->generateThumbprint();

        /* @var $authorization \stomemax\acme2\services\AuthorizationService */
        foreach ($this->_authorizationList as $authorization)
        {
            if ($authorization->status != 'pending')
            {
                continue;
            }

            $challenge = $authorization->getChallenge($type);

            if ($challenge['status'] != 'pending')
            {
                continue;
            }

            $challengeContent = $challenge['token'].'.'.$thumbprint;

            /* Generate challenge info for http-01 */
            if ($type == CommonConstant::CHALLENGE_TYPE_HTTP)
            {
                $challengeList[] = [
                    'type' => $type,
                    'identifier' => $authorization->identifier['value'],
                    'fileName' => $challenge['token'],
                    'fileContent' => $challengeContent,
                ];
            }

            /* Generate challenge info for dns-01 */
            else
            {
                $challengeList[] = [
                    'type' => $type,
                    'identifier' => $authorization->identifier['value'],
                    'dnsContent' => CommonHelper::base64UrlSafeEncode(hash('sha256', $challengeContent, TRUE)),
                ];
            }
        }

        return $challengeList;
    }

    public function verifyChallenge($type)
    {

    }

    private function getAuthorizationList()
    {
        foreach ($this->authorizations as $authorizationUrl)
        {
            $this->_authorizationList[] = new AuthorizationService($authorizationUrl);
        }
    }

    private function generateThumbprint()
    {
        $privateKey = openssl_pkey_get_private(Client::$runtime->account->getPrivateKey());
        $detail = openssl_pkey_get_details($privateKey);

        $accountKey = [
            'kty' => 'RSA',
            'n' => CommonHelper::base64UrlSafeEncode($detail['rsa']['n']),
            'e' => CommonHelper::base64UrlSafeEncode($detail['rsa']['e']),
        ];

        return CommonHelper::base64UrlSafeEncode(hash('sha256', json_encode($accountKey), TRUE));
    }

    private function populate($orderInfo)
    {
        foreach ($orderInfo as $key => $value)
        {
            $this->{$key} = $value;
        }
    }
}
