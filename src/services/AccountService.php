<?php
/**
 * AccountService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stomemax\acme2\services;

use stomemax\acme2\Client;
use stomemax\acme2\exceptions\AccountException;
use stomemax\acme2\helpers\OpenSSLHelper;
use stomemax\acme2\helpers\RequestHelper;

/**
 * Class AccountService
 * @package stomemax\acme2\services
 */
class AccountService
{
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
     * Private key storate path
     * @var string
     */
    private $_privateKeyPath;

    /**
     * Public key storage path
     * @var string
     */
    private $_publicKeyPath;

    /**
     * AccountService constructor.
     * @param $accountStoragePath
     * @throws AccountException
     */
    public function __construct($accountStoragePath)
    {
        if (
               !is_dir($accountStoragePath)
            && mkdir($accountStoragePath, 0755, TRUE) === FALSE
        )
        {
            throw new AccountException("create directory({$accountStoragePath}) failed, please check the permission.");
        }

        $this->_privateKeyPath = $accountStoragePath.'/private.pem';
        $this->_publicKeyPath = $accountStoragePath.'/public.pem';
    }

    /**
     * Init
     * @throws AccountException
     * @throws \stomemax\acme2\exceptions\NonceException
     * @throws \stomemax\acme2\exceptions\OpenSSLException
     * @throws \stomemax\acme2\exceptions\RequestException
     */
    public function init()
    {
        if (is_file($this->_publicKeyPath) && is_file($this->_privateKeyPath))
        {
            $this->getAccount();

            return;
        }

        @unlink($this->_privateKeyPath);
        @unlink($this->_publicKeyPath);

        $this->createAccount();
    }

    /**
     * Create new account
     * @return array
     * @throws AccountException
     * @throws \stomemax\acme2\exceptions\NonceException
     * @throws \stomemax\acme2\exceptions\OpenSSLException
     * @throws \stomemax\acme2\exceptions\RequestException
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

        list($code, $header, $body) = RequestHelper::post(Client::$runtime->endpoint->newAccount, $jws);print_r($body);

        if ($code != 201)
        {
            throw new AccountException("Create account failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        if (!preg_match('/Location:\s*(\S+)/i', $header, $matches))
        {
            throw new AccountException("Parse account url failed, the header is: {$header}");
        }

        $accountInfo = array_merge($body, ['accountUrl' => trim($matches[1])]);

        $this->populate($accountInfo);

        return $accountInfo;
    }

    /**
     * Get account info
     * @return array
     * @throws AccountException
     * @throws \stomemax\acme2\exceptions\NonceException
     * @throws \stomemax\acme2\exceptions\RequestException
     */
    public function getAccount()
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
            throw new AccountException("Get account info failed, the code is: {$code}, the header is: {$header}, the body is: {$body}");
        }

        $accountInfo = array_merge($body, ['accountUrl' => $accountUrl]);

        $this->populate($accountInfo);

        return $accountInfo;
    }

    /**
     * Get account url
     * @return string
     * @throws AccountException
     * @throws \stomemax\acme2\exceptions\NonceException
     * @throws \stomemax\acme2\exceptions\RequestException
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
            throw new AccountException("Get account url failed, the code is: {$code}, the header is: {$header}, the body is: {$body}");
        }

        if (!preg_match('/Location:\s*(\S+)/i', $header, $matches))
        {
            throw new AccountException("Parse account url failed, the header is: {$header}");
        }

        $this->accountUrl = trim($matches[1]);

        return $this->accountUrl;
    }

    /**
     * Update account contact info
     * @param $emailList
     * @return array
     * @throws AccountException
     * @throws \stomemax\acme2\exceptions\NonceException
     * @throws \stomemax\acme2\exceptions\RequestException
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
            throw new AccountException("Update account contact info failed, the code is: {$code}, the header is: {$header}, the body is: {$body}");
        }

        $accountInfo = array_merge($body, ['accountUrl' => $accountUrl]);

        $this->populate($accountInfo);

        return $accountInfo;
    }

    public function updateAccountKey()
    {

    }

    /**
     * Get private key content
     * @return bool|string
     */
    public function getPrivateKey()
    {
        return file_get_contents($this->_privateKeyPath);
    }

    /**
     * Create private/public key pair files
     * @throws AccountException
     * @throws \stomemax\acme2\exceptions\OpenSSLException
     */
    protected function createKeyPairFile()
    {
        $keyPair = OpenSSLHelper::generateRSAKeyPair();

        $result = file_put_contents($this->_privateKeyPath, $keyPair['privateKey'])
            && file_put_contents($this->_publicKeyPath, $keyPair['publicKey']);

        if ($result === FALSE)
        {
            throw new AccountException("Create account key pair files failed, the private key path is: {$this->_privateKeyPath}, the public key path is: {$this->_publicKeyPath}");
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
