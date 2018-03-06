<?php
/**
 * OrderService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stonemax\acme2\services;

use stonemax\acme2\Client;
use stonemax\acme2\constants\CommonConstant;
use stonemax\acme2\exceptions\OrderException;
use stonemax\acme2\helpers\CommonHelper;
use stonemax\acme2\helpers\OpenSSLHelper;
use stonemax\acme2\helpers\RequestHelper;

/**
 * Class OrderService
 * @package stonemax\acme2\services
 */
class OrderService
{
    /**
     * Order status: pending, processing, valid, invalid
     * @var string
     */
    public $status;

    /**
     * Order expire time
     * @var string
     */
    public $expires;

    /**
     * Domains info
     * @var array
     */
    public $identifiers;

    /**
     * Domain authorization info
     * @var array
     */
    public $authorizations;

    /**
     * Finalize order url
     * @var string
     */
    public $finalize;

    /**
     * Fetch certificate content url
     * @var string
     */
    public $certificate;

    /**
     * Order info url
     * @var string
     */
    public $orderUrl;

    /**
     * Order AuthorizationService instance list
     * @var AuthorizationService[]
     */
    private $_authorizationList;

    /**
     * Domain list
     * @var array
     */
    private $_domainList;

    /**
     * Domain challenge type info
     * @var array
     */
    private $_domainChallengeTypeMap;

    /**
     * Certificate encrypt type
     * @var int
     */
    private $_algorithm;

    /**
     * Is a new order
     * @var bool
     */
    private $_renew;

    /**
     * Certificate private key file path
     * @var string
     */
    private $_privateKeyPath;

    /**
     * Certificate public key file path
     * @var string
     */
    private $_publicKeyPath;

    /**
     * Certificate csr file storage path
     * @var string
     */
    private $_csrPath;

    /**
     * Certificate storage file path
     * @var string
     */
    private $_certificatePath;

    /**
     * Certificate full-chained file storage path
     * @var string
     */
    private $_certificateFullChainedPath;

    /**
     * Order info file storage path
     * @var string
     */
    private $_orderInfoPath;

    /**
     * OrderService constructor.
     * @param array $domainInfo
     * @param string $algorithm
     * @param bool $renew
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function __construct($domainInfo, $algorithm, $renew = FALSE)
    {
        $this->_algorithm = $algorithm;
        $this->_renew = boolval($renew);

        if ($this->_algorithm == CommonConstant::KEY_PAIR_TYPE_EC && version_compare(PHP_VERSION, '7.1.0') == -1)
        {
            throw new OrderException("PHP version 7.1 or higher required for generating EC certificates.");
        }

        foreach ($domainInfo as $challengeType => $domainList)
        {
            foreach ($domainList as $domain)
            {
                $domain = trim($domain);

                $this->_domainList[] = $domain;
                $this->_domainChallengeTypeMap[$domain] = $challengeType;
            }
        }

        $this->_domainList = array_unique($this->_domainList);

        sort($this->_domainList);

        $this->init();
    }

    /**
     * Initialization
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function init()
    {
        $flag = substr(md5(implode(',', $this->_domainList)), 11, 8);

        $algorithmNameMap = [
            CommonConstant::KEY_PAIR_TYPE_RSA => 'rsa',
            CommonConstant::KEY_PAIR_TYPE_EC => 'ec',
        ];

        $algorithmName = $algorithmNameMap[$this->_algorithm];
        $basePath = Client::$runtime->storagePath.DIRECTORY_SEPARATOR.$flag.DIRECTORY_SEPARATOR.$algorithmName;

        if (!is_dir($basePath))
        {
            mkdir($basePath, 0755, TRUE);
        }

        $pathMap = [
            '_privateKeyPath' => 'private.pem',
            '_publicKeyPath' => 'public.pem',
            '_csrPath' => 'certificate.csr',
            '_certificatePath' => 'certificate.crt',
            '_certificateFullChainedPath' => 'certificate-fullchained.crt',
            '_orderInfoPath' => 'ORDER',
        ];

        foreach ($pathMap as $propertyName => $fileName)
        {
            $this->{$propertyName} = $basePath.DIRECTORY_SEPARATOR.$fileName;
        }

        if ($this->_renew)
        {
            foreach ($pathMap as $propertyName => $fileName)
            {
                @unlink($basePath.DIRECTORY_SEPARATOR.$fileName);
            }
        }

        is_file($this->_orderInfoPath) ? $this->getOrder() : $this->createOrder();

        file_put_contents(
            Client::$runtime->storagePath.DIRECTORY_SEPARATOR.$flag.DIRECTORY_SEPARATOR.'DOMAIN',
            implode("\r\n", $this->_domainList)
        );
    }

    /**
     * Create new order
     * @return array
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    private function createOrder()
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
            'notBefore' => '',
            'notAfter' => '',
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

        if (($orderUrl = CommonHelper::getLocationFieldFromHeader($header)) === FALSE)
        {
            throw new OrderException('Get order url failed during order creation, the domain list is: '.implode(', ', $this->_domainList));
        }

        $orderInfo = array_merge($body, ['orderUrl' => $orderUrl]);

        $this->populate($orderInfo);
        $this->setOrderInfoToCache(['orderUrl' => $orderUrl]);
        $this->getAuthorizationList();

        return $orderInfo;
    }

    /**
     * Get an existed order info
     * @return array
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    private function getOrder()
    {
        $orderUrl = $this->getOrderInfoFromCache()['orderUrl'];

        list($code, $header, $body) = RequestHelper::get($orderUrl);

        if ($code != 200)
        {
            throw new OrderException("Get order info failed, the order url is: {$orderUrl}, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        $this->populate(array_merge($body, ['orderUrl' => $orderUrl]));
        $this->getAuthorizationList();

        return array_merge($body, ['orderUrl' => $orderUrl]);
    }

    /**
     * Get pending challenges info
     * @return ChallengeService[]
     */
    public function getPendingChallengeList()
    {
        if ($this->isOrderFinalized() === TRUE || $this->isAllAuthorizationValid() === TRUE)
        {
            return [];
        }

        $challengeList = [];
        $thumbprint = OpenSSLHelper::generateThumbprint();

        foreach ($this->_authorizationList as $authorization)
        {
            if ($authorization->status != 'pending')
            {
                continue;
            }

            $challengeType = $this->_domainChallengeTypeMap[$authorization->domain];
            $challenge = $authorization->getChallenge($challengeType);

            if ($challenge['status'] != 'pending')
            {
                continue;
            }

            $challengeContent = $challenge['token'].'.'.$thumbprint;
            $challengeService = new ChallengeService($challengeType, $authorization);

            /* Generate challenge info for http-01 */
            if ($challengeType == CommonConstant::CHALLENGE_TYPE_HTTP)
            {
                $challengeCredential = [
                    'identifier' => $authorization->identifier['value'],
                    'fileName' => $challenge['token'],
                    'fileContent' => $challengeContent,
                ];
            }

            /* Generate challenge info for dns-01 */
            else
            {
                $challengeCredential = [
                    'identifier' => $authorization->identifier['value'],
                    'dnsContent' => CommonHelper::base64UrlSafeEncode(hash('sha256', $challengeContent, TRUE)),
                ];
            }

            $challengeService->setCredential($challengeCredential);

            $challengeList[] = $challengeService;
        }

        return $challengeList;
    }

    /**
     * Get certificate file path info after verifying
     * @param string|null $csr
     * @return array
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function getCertificateFile($csr = NULL)
    {
        if ($this->isAllAuthorizationValid() === FALSE)
        {
            throw new OrderException("There are still some authorizations that are not valid.");
        }

        if ($this->status == 'pending')
        {
            if (!$csr)
            {
                $csr = $this->getCSR();
            }

            $this->finalizeOrder(CommonHelper::getCSRWithoutComment($csr));
        }

        while ($this->status != 'valid')
        {
            sleep(3);

            $this->getOrder();
        }

        list($code, $header, $body) = RequestHelper::get($this->certificate);

        if ($code != 200)
        {
            throw new OrderException("Fetch certificate from letsencrypt failed, the url is: {$this->certificate}, the domain list is: ".implode(', ', $this->_domainList).", the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        $certificateMap = CommonHelper::extractCertificate($body);

        file_put_contents($this->_certificatePath, $certificateMap['certificate']);
        file_put_contents($this->_certificateFullChainedPath, $certificateMap['certificateFullChained']);

        $certificateInfo = openssl_x509_parse($certificateMap['certificate']);

        $this->setOrderInfoToCache([
            'validFromTimestamp' => $certificateInfo['validFrom_time_t'],
            'validToTimestamp' => $certificateInfo['validTo_time_t'],
            'validFromTime' => date('Y-m-d H:i:s', $certificateInfo['validFrom_time_t']),
            'validToTime' => date('Y-m-d H:i:s', $certificateInfo['validTo_time_t']),
        ]);

        return [
            'privateKey' => realpath($this->_privateKeyPath),
            'publicKey' => realpath($this->_publicKeyPath),
            'certificate' => realpath($this->_certificatePath),
            'certificateFullChained' => realpath($this->_certificateFullChainedPath),
            'validFromTimestamp' => $certificateInfo['validFrom_time_t'],
            'validToTimestamp' => $certificateInfo['validTo_time_t'],
        ];
    }

    /**
     * Revoke certificate
     * @param int $reason you can find the code in `https://tools.ietf.org/html/rfc5280#section-5.3.1`
     * @return bool
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\OpenSSLException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function revokeCertificate($reason = 0)
    {
        if ($this->status != 'valid')
        {
            throw new OrderException("Revoke certificate failed because of invalid status({$this->status})");
        }

        if (!is_file($this->_certificatePath))
        {
            throw new OrderException("Revoke certificate failed because of certicate file missing({$this->_certificatePath})");
        }

        $certificate = CommonHelper::getCertificateWithoutComment(file_get_contents($this->_certificatePath));
        $certificate = trim(CommonHelper::base64UrlSafeEncode(base64_decode($certificate)));

        $jws = OpenSSLHelper::generateJWSOfJWK(
            Client::$runtime->endpoint->revokeCert,
            [
                'certificate' => $certificate,
                'reason' => $reason,
            ],
            $this->getPrivateKey()
        );

        list($code, $header, $body) = RequestHelper::post(Client::$runtime->endpoint->revokeCert, $jws);

        if ($code != 200)
        {
            throw new OrderException("Revoke certificate failed, the domain list is: ".implode(', ', $this->_domainList).", the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        return TRUE;
    }

    /**
     * Check weather all authorization is valid, if yes, it means all the challenges had passed
     * @return bool
     */
    public function isAllAuthorizationValid()
    {
        foreach ($this->_authorizationList as $authorization)
        {
            if ($authorization->status != 'valid')
            {
                return FALSE;
            }
        }

        return TRUE;
    }

    /**
     * Check weather order had been finalized
     * @return bool
     */
    public function isOrderFinalized()
    {
        return ($this->status == 'processing' || $this->status == 'valid');
    }

    /**
     * Finalize order to get certificate
     * @param string $csr
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    private function finalizeOrder($csr)
    {
        $jws = OpenSSLHelper::generateJWSOfKid(
            $this->finalize,
            Client::$runtime->account->getAccountUrl(),
            ['csr' => trim(CommonHelper::base64UrlSafeEncode(base64_decode($csr)))]
        );

        list($code, $header, $body) = RequestHelper::post($this->finalize, $jws);

        if ($code != 200)
        {
            throw new OrderException("Finalize order failed, the url is: {$this->finalize}, the domain list is: ".implode(', ', $this->_domainList).", the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        $this->populate($body);
        $this->getAuthorizationList();
    }

    /**
     * Generate authorization instances according to order info
     */
    private function getAuthorizationList()
    {
        $this->_authorizationList = [];

        foreach ($this->authorizations as $authorizationUrl)
        {
            $authorization = new AuthorizationService($authorizationUrl);

            $this->_authorizationList[] = $authorization;
        }
    }

    /**
     * Get csr info, if the csr doesn't exist then create it
     * @return bool|string
     */
    private function getCSR()
    {
        if (!is_file($this->_csrPath))
        {
            $this->createCSRFile();
        }

        return file_get_contents($this->_csrPath);
    }

    /**
     * Create csr file
     */
    private function createCSRFile()
    {
        $domainList = array_map(
            function($identifier) {
                return $identifier['value'];
            },
            $this->identifiers
        );

        $csr = OpenSSLHelper::generateCSR(
            $domainList,
            ['commonName' => CommonHelper::getCommonNameForCSR($domainList)],
            $this->getPrivateKey()
        );

        file_put_contents($this->_csrPath, $csr);
    }

    /**
     * Get private key info, if private/public key files doesn't exist then create them
     * @return bool|string
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\OpenSSLException
     */
    private function getPrivateKey()
    {
        if (!is_file($this->_privateKeyPath) || !is_file($this->_publicKeyPath))
        {
            $this->createKeyPairFile();
        }

        return file_get_contents($this->_privateKeyPath);
    }

    /**
     * Create private/public key files
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\OpenSSLException
     */
    private function createKeyPairFile()
    {
        $keyPair = OpenSSLHelper::generateKeyPair($this->_algorithm);

        $result = file_put_contents($this->_privateKeyPath, $keyPair['privateKey'])
            && file_put_contents($this->_publicKeyPath, $keyPair['publicKey']);

        if ($result === FALSE)
        {
            throw new OrderException('Create order key pair files failed, the domain list is: '.implode(', ', $this->_domainList).", the private key path is: {$this->_privateKeyPath}, the public key path is: {$this->_publicKeyPath}");
        }
    }

    /**
     * Get order basic info from file cache
     * @return array
     */
    private function getOrderInfoFromCache()
    {
        $orderInfo = [];

        if (is_file($this->_orderInfoPath))
        {
            $orderInfo = json_decode(file_get_contents($this->_orderInfoPath), TRUE);
        }

        return $orderInfo ?: [];
    }

    /**
     * Set order basic info to file cache
     * @param array $orderInfo
     * @return bool|int
     */
    private function setOrderInfoToCache($orderInfo)
    {
        $orderInfo = array_merge($this->getOrderInfoFromCache(), $orderInfo);

        return file_put_contents($this->_orderInfoPath, json_encode($orderInfo));
    }

    /**
     * Populate properties of this instance
     * @param array $orderInfo
     */
    private function populate($orderInfo)
    {
        foreach ($orderInfo as $key => $value)
        {
            $this->{$key} = $value;
        }
    }
}
