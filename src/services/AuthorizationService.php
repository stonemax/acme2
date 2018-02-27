<?php
/**
 * AuthorizationService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stomemax\acme2\services;

use stomemax\acme2\Client;
use stomemax\acme2\constants\CommonConstant;
use stomemax\acme2\exceptions\AuthorizationException;
use stomemax\acme2\helpers\CommonHelper;
use stomemax\acme2\helpers\OpenSSLHelper;
use stomemax\acme2\helpers\RequestHelper;

/**
 * Class AuthorizationService
 * @package stomemax\acme2\services
 */
class AuthorizationService
{
    /**
     * Domain info
     * @var array
     */
    public $identifier;

    /**
     * Authorization status
     * @var string
     */
    public $status;

    /**
     * Expire time, like yyyy-mm-ddThh:mm:ssZ
     * @var string
     */
    public $expires;

    /**
     * Supplied challenge types
     * @var array
     */
    public $challenges;

    /**
     * Access this url to get authorization info
     * @var string
     */
    public $authorizationUrl;

    /**
     * AuthorizationService constructor.
     * @param string $authorizationUrl
     * @throws AuthorizationException
     * @throws \stomemax\acme2\exceptions\RequestException
     */
    public function __construct($authorizationUrl)
    {
        $this->authorizationUrl = $authorizationUrl;

        $this->getAuthorization();
    }

    /**
     * Get authorization info
     * @return array
     * @throws AuthorizationException
     * @throws \stomemax\acme2\exceptions\RequestException
     */
    public function getAuthorization()
    {
        list($code, $header , $body) = RequestHelper::get($this->authorizationUrl);

        if ($code != 200)
        {
            throw new AuthorizationException("Get authorization info failed, the authorization url is: {$this->authorizationUrl}, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        $this->populate($body);

        return array_merge($body, ['authorizationUrl' => $this->authorizationUrl]);
    }

    /**
     * Get challenge to verify
     * @param string $type http-01 or dns-01
     * @return mixed|null
     */
    public function getChallenge($type)
    {
        foreach ($this->challenges as $challenge)
        {
            if ($challenge['type'] == $type)
            {
                return $challenge;
            }
        }

        return NULL;
    }

    /**
     * Make letsencrypt to verify
     * @param string $type
     * @param string $thumbprint
     * @return bool
     * @throws AuthorizationException
     * @throws \stomemax\acme2\exceptions\AccountException
     * @throws \stomemax\acme2\exceptions\NonceException
     * @throws \stomemax\acme2\exceptions\RequestException
     */
    public function verify($type, $thumbprint)
    {
        $challenge = $this->getChallenge($type);
        $keyAuthorization = $challenge['token'].'.'.$thumbprint;

        if ($this->verifyLocally($type, $keyAuthorization) === FALSE)
        {
            return FALSE;
        }

        $jwk = OpenSSLHelper::generateJWSOfKid(
            $challenge['url'],
            Client::$runtime->account->getAccountUrl(),
            ['keyAuthorization' => $keyAuthorization]
        );

        list($code, $header, $body) = RequestHelper::post($challenge['url'], $jwk);

        if ($code != 200)
        {
            throw new AuthorizationException("Send Request to letsencrypt to verify authorization failed, the url is: {$challenge['url']}, the domain is: {$this->identifier['value']}, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
        }

        while ($this->status == 'pending')
        {
            sleep(1);

            $this->getAuthorization();
        }

        return TRUE;
    }

    /**
     * Check locally
     * @param string $type
     * @param string $keyAuthorization
     * @return bool
     * @throws \stomemax\acme2\exceptions\RequestException
     */
    private function verifyLocally($type, $keyAuthorization)
    {
        $challenge = $this->getChallenge($type);

        if ($type == CommonConstant::CHALLENGE_TYPE_HTTP)
        {
            if (!CommonHelper::checkHttpChallenge($challenge['identifier'], $challenge['token'], $keyAuthorization))
            {
                return FALSE;
            }
        }
        else
        {
            $dnsContent = CommonHelper::base64UrlSafeEncode(hash('sha256', $keyAuthorization, TRUE));

            if (!CommonHelper::checkDNSChallenge($challenge['identifier'], $dnsContent))
            {
                return FALSE;
            }
        }

        return TRUE;
    }

    /**
     * Populate properties of this instance
     * @param array $authorizationInfo
     */
    private function populate($authorizationInfo)
    {
        foreach ($authorizationInfo as $key => $value)
        {
            $this->{$key} = $value;
        }
    }
}
