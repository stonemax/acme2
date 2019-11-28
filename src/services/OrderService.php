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
use stonemax\acme2\exceptions\StorageException;
use stonemax\acme2\helpers\CommonHelper;
use stonemax\acme2\helpers\OpenSSLHelper;
use stonemax\acme2\helpers\RequestHelper;
use stonemax\acme2\storage\FileSystemStorageProvider;
use stonemax\acme2\storage\StorageProvider;

/**
 * Class OrderService
 * @package stonemax\acme2\services
 */
class OrderService
{

    const PRIVATE_KEY_PATH = "private.pem";
    const PUBLIC_KEY_PATH = "public.pem";
    const CSR_PATH = "certificate.csr";
    const CERTIFICATE_PATH = "certificate.crt";
    const CERTIFICATE_FULL_CHAIN_PATH = "certificate-fullchained.crt";
    const ORDER_INFO_PATH = "ORDER";

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
     * Whether to generate a new order or not. When `true` the existing files will be removed.
     * @var bool
     */
    private $_generateNewOrder;

    /**
     * @var StorageProvider
     */
    private $_storageProvider;

    private $_storagePath;
    private $_storageAlgorithm;

    /**
     * OrderService constructor.
     * OrderService constructor.
     * @param array $domainInfo
     * @param int $algorithm
     * @param bool $generateNewOder
     * @param StorageProvider $storageProvider
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function __construct($storageProvider, $domainInfo, $algorithm, $generateNewOder)
    {
        $this->_algorithm = $algorithm;
        $this->_generateNewOrder = boolval($generateNewOder);

        $this->_storageProvider = $storageProvider;

        if ($this->_algorithm == CommonConstant::KEY_PAIR_TYPE_EC && version_compare(PHP_VERSION, '7.1.0') == -1)
        {
            throw new OrderException("PHP version 7.1.0 or higher required for generating EC certificates.");
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
        $this->_storagePath = substr(md5(implode(',', $this->_domainList)), 11, 8);

        $algorithmNameMap = [
            CommonConstant::KEY_PAIR_TYPE_RSA => 'rsa',
            CommonConstant::KEY_PAIR_TYPE_EC => 'ec',
        ];

        $this->_storageAlgorithm = $algorithmNameMap[$this->_algorithm];

        if ($this->_generateNewOrder === TRUE)
        {
            foreach ([
                        OrderService::PRIVATE_KEY_PATH,
                        OrderService::PUBLIC_KEY_PATH,
                        OrderService::CSR_PATH,
                        OrderService::CERTIFICATE_PATH,
                        OrderService::CERTIFICATE_FULL_CHAIN_PATH,
                        OrderService::ORDER_INFO_PATH
                     ] as $fileName)
            {
                $this->_storageProvider->deleteDomainDataFile($this->_storagePath, $this->_storageAlgorithm, $fileName);
            }
        }

        ($this->_generateNewOrder === TRUE)
            ? $this->createOrder()
            : $this->getOrder();

        $this->_storageProvider->saveDomainDataFile($this->_storagePath, $this->_storageAlgorithm, 'DOMAIN', implode("\r\n", $this->_domainList));
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
     * @param bool $getAuthorizationList
     * @return array
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    private function getOrder($getAuthorizationList = TRUE)
    {
        if (!is_file($this->_orderInfoPath))
        {
            throw new OrderException("Get order info failed, the local order info file doesn't exist, the order info file path is: {$this->_orderInfoPath}");
        }

        $orderUrl = $this->getOrderInfoFromCache()['orderUrl'];

        list($code, $header, $body) = RequestHelper::get($orderUrl);

        if ($code != 200)
        {
            throw new OrderException("Get order info failed, the order url is: {$orderUrl}, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        $this->populate(array_merge($body, ['orderUrl' => $orderUrl]));

        if ($getAuthorizationList === TRUE)
        {
            $this->getAuthorizationList();
        }

        return array_merge($body, ['orderUrl' => $orderUrl]);
    }

    /**
     * Get pending challenges info
     * @return ChallengeService[]
     */
    public function getPendingChallengeList()
    {
        if ($this->isAllAuthorizationValid() === TRUE)
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
     * @deprecated Use {@link OrderService::getFile($file)} to actually get the final files. Migration in place for filesystem provider only.
     */
    public function getCertificateFile($csr = NULL)
    {
        if ($this->isAllAuthorizationValid() === FALSE)
        {
            throw new OrderException("There are still some authorizations that are not valid.");
        }

        $this->waitStatus('ready');
        $this->finalizeOrder(CommonHelper::getCSRWithoutComment($csr ?: $this->getCSR()));
        $this->waitStatus('valid');

        list($code, $header, $body) = RequestHelper::get($this->certificate);

        if ($code != 200)
        {
            throw new OrderException("Fetch certificate from letsencrypt failed, the url is: {$this->certificate}, the domain list is: ".implode(', ', $this->_domainList).", the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        $certificateMap = CommonHelper::extractCertificate($body);

        $this->_storageProvider->saveDomainDataFile($this->_storagePath, $this->_storageAlgorithm, OrderService::CERTIFICATE_PATH, $certificateMap['certificate']);
        $this->_storageProvider->saveDomainDataFile($this->_storagePath, $this->_storageAlgorithm, OrderService::CERTIFICATE_FULL_CHAIN_PATH, $certificateMap['certificateFullChained']);

        $certificateInfo = openssl_x509_parse($certificateMap['certificate']);

        $this->setOrderInfoToCache([
            'validFromTimestamp' => $certificateInfo['validFrom_time_t'],
            'validToTimestamp' => $certificateInfo['validTo_time_t'],
            'validFromTime' => date('Y-m-d H:i:s', $certificateInfo['validFrom_time_t']),
            'validToTime' => date('Y-m-d H:i:s', $certificateInfo['validTo_time_t']),
        ]);

        $r = [
            'validFromTimestamp' => $certificateInfo['validFrom_time_t'],
            'validToTimestamp' => $certificateInfo['validTo_time_t'],
        ];

        if($this->_storageProvider instanceof FileSystemStorageProvider)
        {
            $base = $this->_storageProvider->getBaseDir().FileSystemStorageProvider::DOMAIN_DIR . DIRECTORY_SEPARATOR . $this->_storagePath . DIRECTORY_SEPARATOR . $this->_storageAlgorithm;
            $r = array_merge($r, [
                'privateKey' => realpath($base . DIRECTORY_SEPARATOR . OrderService::PRIVATE_KEY_PATH),
                'publicKey' => realpath($base . DIRECTORY_SEPARATOR . OrderService::PUBLIC_KEY_PATH),
                'certificate' => realpath($base . DIRECTORY_SEPARATOR . OrderService::CERTIFICATE_PATH),
                'certificateFullChained' => realpath($base . DIRECTORY_SEPARATOR . OrderService::CERTIFICATE_FULL_CHAIN_PATH),
            ]);
        }

        return $r;
    }

    /**
     * Get file contents for domain
     * @param $file
     * @return string
     * @throws StorageException
     */
    public function getFile($file) {
        if(!$this->_storageProvider->getDomainDataFileExists($this->_storagePath, $this->_storageAlgorithm, $file))
        {
            throw new StorageException("{$file} does not exist!");
        }
        return $this->_storageProvider->getDomainDataFile($this->_storagePath, $this->_storageAlgorithm, $file);
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

        if (!$this->_storageProvider->getDomainDataFileExists($this->_storagePath, $this->_storageAlgorithm, OrderService::CERTIFICATE_PATH))
        {
            throw new OrderException("Revoke certificate failed because of certicate file missing(".OrderService::CERTIFICATE_PATH.")");
        }

        $certificate = CommonHelper::getCertificateWithoutComment($this->_storageProvider->getDomainDataFile($this->_storagePath, $this->_storageAlgorithm, OrderService::CERTIFICATE_PATH));
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
        if (!$this->_storageProvider->getDomainDataFileExists($this->_storagePath, $this->_storageAlgorithm, OrderService::CSR_PATH))
        {
            $this->createCSRFile();
        }

        return $this->_storageProvider->getDomainDataFile($this->_storagePath, $this->_storageAlgorithm, OrderService::CSR_PATH);
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

        $this->_storageProvider->saveDomainDataFile($this->_storagePath, $this->_storageAlgorithm, OrderService::CSR_PATH, $csr);
    }

    /**
     * Get private key info, if private/public key files doesn't exist then create them
     * @return bool|string
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\OpenSSLException
     */
    private function getPrivateKey()
    {
        if (!$this->_storageProvider->getDomainDataFileExists($this->_storagePath, $this->_storageAlgorithm, OrderService::PRIVATE_KEY_PATH)
            || !$this->_storageProvider->getDomainDataFileExists($this->_storagePath, $this->_storageAlgorithm, OrderService::PUBLIC_KEY_PATH))
        {
            $this->createKeyPairFile();
        }

        return $this->_storageProvider->getDomainDataFile($this->_storagePath, $this->_storageAlgorithm, OrderService::PRIVATE_KEY_PATH);
    }

    /**
     * Create private/public key files
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\OpenSSLException
     */
    private function createKeyPairFile()
    {
        $keyPair = OpenSSLHelper::generateKeyPair($this->_algorithm);

        $result = $this->_storageProvider->saveDomainDataFile($this->_storagePath, $this->_storageAlgorithm, OrderService::PRIVATE_KEY_PATH, $keyPair['privateKey'])
            && $this->_storageProvider->saveDomainDataFile($this->_storagePath, $this->_storageAlgorithm, OrderService::PUBLIC_KEY_PATH, $keyPair['publicKey']);

        if ($result === FALSE)
        {
            throw new OrderException('Create order key pair files failed, the domain list is: '.implode(', ', $this->_domainList).", the private key path is: ".OrderService::PRIVATE_KEY_PATH.", the public key path is: ".OrderService::PUBLIC_KEY_PATH);
        }
    }

    /**
     * Get order basic info from file cache
     * @return array
     */
    private function getOrderInfoFromCache()
    {
        $orderInfo = [];

        if ($this->_storageProvider->getDomainDataFileExists($this->_storagePath, $this->_storageAlgorithm, OrderService::ORDER_INFO_PATH))
        {
            $orderInfo = json_decode($this->_storageProvider->getDomainDataFile($this->_storagePath, $this->_storageAlgorithm, OrderService::ORDER_INFO_PATH), TRUE);
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

        return $this->_storageProvider->saveDomainDataFile($this->_storagePath, $this->_storageAlgorithm, OrderService::ORDER_INFO_PATH, json_encode($orderInfo));
    }

    /**
     * 等待订单状态
     * @param $staus
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    private function waitStatus($staus)
    {
        while ($this->status != $staus)
        {
            sleep(3);

            $this->getOrder(FALSE);
        }
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
