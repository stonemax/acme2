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
     * Order status: pending, processing, valid
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
     * Base domain name
     * @var string
     */
    private $_baseDomain;

    /**
     * Domain list
     * @var array
     */
    private $_domainList;

    /**
     * Certificate encrypt type
     * @var int
     */
    private $_algorithm;

    /**
     * Certificate becomes valid at this time
     * @var string
     */
    private $_notBefore;

    /**
     * Certificate becomes invalid until this time
     * @var string
     */
    private $_notAfter;

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
     * @param string $baseDomain
     * @param array $domainList
     * @param string $algorithm
     * @param string $notBefore
     * @param string $notAfter
     * @throws OrderException
     * @throws \stonemax\acme2\exceptions\AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function __construct($baseDomain, $domainList, $algorithm, $notBefore, $notAfter)
    {
        $this->_baseDomain = $baseDomain;
        $this->_domainList = $domainList;
        $this->_algorithm = $algorithm;
        $this->_notBefore = $notBefore;
        $this->_notAfter = $notAfter;

        $algorithmNameMap = [
            CommonConstant::KEY_PAIR_TYPE_RSA => 'rsa',
            CommonConstant::KEY_PAIR_TYPE_EC => 'ec',
        ];

        $algorithmName = $algorithmNameMap[$algorithm];
        $basePath = Client::$runtime->storagePath.DIRECTORY_SEPARATOR.$algorithmName;

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
            '_orderInfoPath' => 'INFO',
        ];

        foreach ($pathMap as $propertyName => $fileName)
        {
            $this->{$propertyName} = $basePath.DIRECTORY_SEPARATOR.$fileName;
        }

        is_file($this->_orderInfoPath) ? $this->getOrder() : $this->createOrder();
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
        $this->getAuthorizationList();

        file_put_contents($this->_orderInfoPath, $orderUrl);

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
        $orderUrl = file_get_contents($this->_orderInfoPath);

        list($code, $header, $body) = RequestHelper::get($orderUrl);

        if ($code != 200)
        {
            throw new OrderException("Get order info failed, the order url is: {$orderUrl}, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        $this->populate($body);
        $this->getAuthorizationList();

        return array_merge($body, ['orderUrl' => $orderUrl]);
    }

    /**
     * Get pending challenges info
     * @param int $type
     * @return array
     */
    public function getPendingChallenge($type)
    {
        if ($this->isOrderFinalized() === TRUE || $this->isAllAuthorizationValid() === TRUE)
        {
            return [];
        }

        $challengeList = [];
        $thumbprint = $this->generateThumbprint();

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

    /**
     * Verify authorization challenges
     * @param int $type
     * @throws \stonemax\acme2\exceptions\AccountException
     * @throws \stonemax\acme2\exceptions\AuthorizationException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function verifyChallenge($type)
    {
        if ($this->isOrderFinalized() === TRUE || $this->isAllAuthorizationValid() === TRUE)
        {
            return;
        }

        $thumbprint = $this->generateThumbprint();

        while (TRUE)
        {
            $failCount = 0;

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

                if ($authorization->verify($type, $thumbprint) === FALSE)
                {
                    $failCount++;
                }
            }

            if ($failCount == 0)
            {
                break;
            }
        }
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

        return [
            'certificate' => realpath($this->_certificatePath),
            'certificateFullChained' => realpath($this->_certificateFullChainedPath),
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
            $this->_authorizationList[] = new AuthorizationService($authorizationUrl);
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
            $this->generateDNForCSR($domainList),
            $this->getPrivateKey()
        );

        file_put_contents($this->_csrPath, $csr);
    }

    /**
     * Generate dn info for csr
     * @param array $domainList
     * @return array
     */
    private function generateDNForCSR($domainList)
    {
        if (in_array($this->_baseDomain, $domainList))
        {
            $commonName = $this->_baseDomain;
        }
        else if (in_array("*.{$this->_baseDomain}", $domainList))
        {
            $commonName = "*.{$this->_baseDomain}";
        }
        else
        {
            $commonName = $domainList[0];
        }

        return [
            'commonName' => $commonName,
        ];
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
     * Generate thumbprint
     * @return mixed
     */
    private function generateThumbprint()
    {
        $privateKey = openssl_pkey_get_private(Client::$runtime->account->getPrivateKey());
        $detail = openssl_pkey_get_details($privateKey);

        $accountKey = [
            'e' => CommonHelper::base64UrlSafeEncode($detail['rsa']['e']),
            'kty' => 'RSA',
            'n' => CommonHelper::base64UrlSafeEncode($detail['rsa']['n']),
        ];

        return CommonHelper::base64UrlSafeEncode(hash('sha256', json_encode($accountKey), TRUE));
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
