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
    private $_privateKeyPath;

    private $_publicKeyPath;

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

        if (is_file($this->_publicKeyPath) && is_file($this->_privateKeyPath))
        {

        }

        @unlink($accountStoragePath.'/private.pem');
        @unlink($accountStoragePath.'/public.pem');

        $this->createAccount();
    }

    protected function createAccount()
    {
        $keyPair = OpenSSLHelper::generateRSAKeyPair();

        file_put_contents($this->_privateKeyPath, $keyPair['privateKey']);
        file_put_contents($this->_publicKeyPath, $keyPair['publicKey']);

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
            $payload,
            $keyPair['privateKey']
        );

        list($code, $header, $body) = RequestHelper::post(Client::$runtime->endpoint->newAccount, $jws);

        if ($code != 201)
        {
            throw new AccountException("Create account failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        if (!preg_match('/Location:\s*(\S+)/i', $header, $matches))
        {
            throw new AccountException("Get account url failed, the header is: {$header}");
        }

        print_r($matches);

        $accountUrl = trim($matches[1]);
    }

    /**
     * Get private key content
     * @return bool|string
     */
    public function getPrivateKey()
    {
        return file_get_contents($this->_privateKeyPath);
    }
}
