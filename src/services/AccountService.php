<?php
/**
 * AccountService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stonemax\acme2\services;

use stonemax\acme2\Client;
use stonemax\acme2\exceptions\AccountException;
use stonemax\acme2\helpers\CommonHelper;
use stonemax\acme2\helpers\OpenSSLHelper;
use stonemax\acme2\helpers\RequestHelper;
use stonemax\acme2\storage\StorageProvider;

/**
 * Class AccountService
 * @package stonemax\acme2\services
 */
class AccountService
{

    const PRIVATE_KEY_PATH = DIRECTORY_SEPARATOR. "private.pem";
    const PUBLIC_KEY_PATH = DIRECTORY_SEPARATOR. "public.pem";

    /**
     * Account id
     * @var string
     */
    public $id;

    /**
     * Account key
     * @var array
     */
    public $key;

    /**
     * Account contact list
     * @var array
     */
    public $contact;

    /**
     * Account agreement file url
     * @var string
     */
    public $agreement;

    /**
     * Account initial ip
     * @var string
     */
    public $initialIp;

    /**
     * Account creation time
     * @var string
     */
    public $createdAt;

    /**
     * Account status
     * @var string
     */
    public $status;

    /**
     * Access account info url
     * @var string
     */
    public $accountUrl;

    /**
     * @var StorageProvider
     */
    private $_storageProvider;

    /**
     * AccountService constructor.
     * @param StorageProvider $storageProvider
     */
    public function __construct($storageProvider)
    {
        $this->_storageProvider = $storageProvider;
    }

    /**
     * Init
     * @throws AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\OpenSSLException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function init()
    {
        if ($this->_storageProvider->getAccountDataFileExists(AccountService::PUBLIC_KEY_PATH)
            && $this->_storageProvider->getAccountDataFileExists(AccountService::PRIVATE_KEY_PATH))
        {
            $this->getAccount();

            return;
        }

        $this->_storageProvider->deleteAccountDataFile(AccountService::PRIVATE_KEY_PATH);
        $this->_storageProvider->deleteAccountDataFile(AccountService::PUBLIC_KEY_PATH);

        $this->createAccount();
    }

    /**
     * Create new account
     * @return array
     * @throws AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\OpenSSLException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    private function createAccount()
    {
        $this->createKeyPairFile();

        $contactList = array_map(
            function($email) {
                return "mailto:{$email}";
            },
            Client::$runtime->emailList
        );

        $payload = [
            'contact' => $contactList,
            'termsOfServiceAgreed' => TRUE,
        ];

        $jws = OpenSSLHelper::generateJWSOfJWK(
            Client::$runtime->endpoint->newAccount,
            $payload
        );

        list($code, $header, $body) = RequestHelper::post(Client::$runtime->endpoint->newAccount, $jws);

        if ($code != 201)
        {
            throw new AccountException("Create account failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        if (!($accountUrl = CommonHelper::getLocationFieldFromHeader($header)))
        {
            throw new AccountException("Parse account url failed, the header is: {$header}");
        }

        $accountInfo = array_merge($body, ['accountUrl' => $accountUrl]);

        $this->populate($accountInfo);

        return $accountInfo;
    }

    /**
     * Get account info
     * @return array
     * @throws AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    private function getAccount()
    {
        $accountUrl = $this->getAccountUrl();

        $jws = OpenSSLHelper::generateJWSOfKid(
            $accountUrl,
            $accountUrl,
            ['' => '']
        );

        list($code, $header, $body) = RequestHelper::post($accountUrl, $jws);

        if ($code != 200)
        {
            throw new AccountException("Get account info failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        $this->populate($body);

        return array_merge($body, ['accountUrl' => $accountUrl]);
    }

    /**
     * Get account url
     * @return string
     * @throws AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function getAccountUrl()
    {
        if ($this->accountUrl)
        {
            return $this->accountUrl;
        }

        $jws = OpenSSLHelper::generateJWSOfJWK(
            Client::$runtime->endpoint->newAccount,
            ['onlyReturnExisting' => TRUE]
        );

        list($code, $header, $body) = RequestHelper::post(Client::$runtime->endpoint->newAccount, $jws);

        if ($code != 200)
        {
            throw new AccountException("Get account url failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        if (!($accountUrl = CommonHelper::getLocationFieldFromHeader($header)))
        {
            throw new AccountException("Parse account url failed, the header is: {$header}");
        }

        $this->accountUrl = $accountUrl;

        return $this->accountUrl;
    }

    /**
     * Update account contact info
     * @param $emailList
     * @return array
     * @throws AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function updateAccountContact($emailList)
    {
        $accountUrl = $this->getAccountUrl();

        $contactList = array_map(
            function($email) {
                return "mailto:{$email}";
            },
            $emailList
        );

        $jws = OpenSSLHelper::generateJWSOfKid(
            $accountUrl,
            $accountUrl,
            ['contact' => $contactList]
        );

        list($code, $header, $body) = RequestHelper::post($accountUrl, $jws);

        if ($code != 200)
        {
            throw new AccountException("Update account contact info failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        $this->populate($body);

        return array_merge($body, ['accountUrl' => $accountUrl]);
    }

    /**
     * Update accout private/public keys
     * @throws AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\OpenSSLException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function updateAccountKey()
    {
        $keyPair = OpenSSLHelper::generateRSAKeyPair();

        $privateKey = openssl_pkey_get_private($keyPair['privateKey']);
        $detail = openssl_pkey_get_details($privateKey);

        $innerPayload = [
            'account' => $this->getAccountUrl(),
            'newKey' => [
                'kty' => 'RSA',
                'n' => CommonHelper::base64UrlSafeEncode($detail['rsa']['n']),
                'e' => CommonHelper::base64UrlSafeEncode($detail['rsa']['e']),
            ],
        ];

        $outerPayload = OpenSSLHelper::generateJWSOfJWK(
            Client::$runtime->endpoint->keyChange,
            $innerPayload,
            $keyPair['privateKey']
        );

        $jws = OpenSSLHelper::generateJWSOfKid(
            Client::$runtime->endpoint->keyChange,
            $this->getAccountUrl(),
            $outerPayload
        );

        list($code, $header, $body) = RequestHelper::post(Client::$runtime->endpoint->keyChange, $jws);

        if ($code != 200)
        {
            throw new AccountException("Update account key failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        $this->populate($body);
        $this->createKeyPairFile($keyPair);

        return array_merge($body, ['accountUrl' => $this->getAccountUrl()]);
    }

    /**
     * Deactivate account
     * @return array
     * @throws AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function deactivateAccount()
    {
        $jws = OpenSSLHelper::generateJWSOfKid(
            $this->getAccountUrl(),
            $this->getAccountUrl(),
            ['status' => 'deactivated']
        );

        list($code, $header, $body) = RequestHelper::post($this->getAccountUrl(), $jws);

        if ($code != 200)
        {
            throw new AccountException("Deactivate account failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        $this->populate($body);

        $this->_storageProvider->deleteAccountDataFile(AccountService::PRIVATE_KEY_PATH);
        $this->_storageProvider->deleteAccountDataFile(AccountService::PUBLIC_KEY_PATH);

        return array_merge($body, ['accountUrl' => $this->getAccountUrl()]);
    }

    /**
     * Get private key content
     * @return bool|string
     */
    public function getPrivateKey()
    {
        return $this->_storageProvider->getAccountDataFile(AccountService::PRIVATE_KEY_PATH);
    }

    /**
     * Create private/public key pair files
     * @param array|null $keyPair
     * @throws AccountException
     * @throws \stonemax\acme2\exceptions\OpenSSLException
     */
    private function createKeyPairFile($keyPair = NULL)
    {
        $keyPair = $keyPair ?: OpenSSLHelper::generateRSAKeyPair();

        $result = $this->_storageProvider->saveAccountDataFile(AccountService::PRIVATE_KEY_PATH, $keyPair["privateKey"])
            && $this->_storageProvider->saveAccountDataFile(AccountService::PUBLIC_KEY_PATH, $keyPair["publicKey"]);

        if ($result === FALSE)
        {
            throw new AccountException("Create account key pair files failed, the private key path is: ".AccountService::PRIVATE_KEY_PATH.", the public key path is: ".AccountService::PUBLIC_KEY_PATH);
        }
    }

    /**
     * Populate properties of instance
     * @param array $accountInfo
     */
    private function populate($accountInfo)
    {
        foreach ($accountInfo as $key => $value)
        {
            $this->{$key} = $value;
        }
    }
}
