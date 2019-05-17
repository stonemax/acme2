<?php
/**
 * AuthorizationService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stonemax\acme2\services;

use stonemax\acme2\Client;
use stonemax\acme2\constants\CommonConstant;
use stonemax\acme2\exceptions\AuthorizationException;
use stonemax\acme2\exceptions\timeout\VerifyCATimeoutException;
use stonemax\acme2\exceptions\timeout\VerifyLocallyTimeoutException;
use stonemax\acme2\helpers\CommonHelper;
use stonemax\acme2\helpers\OpenSSLHelper;
use stonemax\acme2\helpers\RequestHelper;

/**
 * Class AuthorizationService
 * @package stonemax\acme2\services
 */
class AuthorizationService
{
    /**
     * Domain info
     * @var array
     */
    public $identifier;

    /**
     * Authorization status: pending, valid, invalid
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
     * Wildcard domain or not
     * @var bool
     */
    public $wildcard = FALSE;

    /**
     * Initial domain name
     * @var string
     */
    public $domain;

    /**
     * Access this url to get authorization info
     * @var string
     */
    public $authorizationUrl;

    /**
     * AuthorizationService constructor.
     * @param string $authorizationUrl
     * @throws AuthorizationException
     * @throws \stonemax\acme2\exceptions\RequestException
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
     * @throws \stonemax\acme2\exceptions\RequestException
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
     * @param int $verifyLocallyTimeout
     * @param int $verifyCATimeout
     * @return bool
     * @throws AuthorizationException
     * @throws VerifyCATimeoutException
     * @throws VerifyLocallyTimeoutException
     * @throws \stonemax\acme2\exceptions\AccountException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    public function verify($type, $verifyLocallyTimeout, $verifyCATimeout)
    {
        $challenge = $this->getChallenge($type);

        if ($this->status != 'pending' || $challenge['status'] != 'pending')
        {
            return TRUE;
        }

        $keyAuthorization = $challenge['token'].'.'.OpenSSLHelper::generateThumbprint();

        $this->verifyLocally($type, $keyAuthorization, $verifyLocallyTimeout);

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

        $this->verifyCA($type, $verifyCATimeout);

        return TRUE;
    }

    /**
     * Verify locally
     * @param string $type
     * @param string $keyAuthorization
     * @param int $verifyLocallyTimeout
     * @throws VerifyLocallyTimeoutException
     */
    private function verifyLocally($type, $keyAuthorization, $verifyLocallyTimeout)
    {
        $verifyStartTime = time();

        while (TRUE)
        {
            if ($verifyLocallyTimeout > 0 && (time() - $verifyStartTime) > $verifyLocallyTimeout)
            {
                throw new VerifyLocallyTimeoutException("Verify `{$this->domain}` via {$type} timeout, the timeout setting is: {$verifyLocallyTimeout} seconds");
            }

            $challenge = $this->getChallenge($type);
            $domain = $this->identifier['value'];

            if ($type == CommonConstant::CHALLENGE_TYPE_HTTP)
            {
                if (CommonHelper::checkHttpChallenge($domain, $challenge['token'], $keyAuthorization) === TRUE)
                {
                    break;
                }
            }
            else
            {
                $dnsContent = CommonHelper::base64UrlSafeEncode(hash('sha256', $keyAuthorization, TRUE));

                if (CommonHelper::checkDNSChallenge($domain, $dnsContent) === TRUE)
                {
                    break;
                }
            }

            sleep(3);
        }
    }

    /**
     * Verify via Let's encrypt
     * @param string $type
     * @param int $verifyCATimeout
     * @throws AuthorizationException
     * @throws VerifyCATimeoutException
     * @throws \stonemax\acme2\exceptions\RequestException
     */
    private function verifyCA($type, $verifyCATimeout)
    {
        $verifyStartTime = time();

        while ($this->status == 'pending')
        {
            if ($verifyCATimeout > 0 && (time() - $verifyStartTime) > $verifyCATimeout)
            {
                throw new VerifyCATimeoutException("Verify `{$this->domain}` via {$type} timeout, the timeout setting is: {$verifyCATimeout} seconds");
            }

            sleep(3);

            $this->getAuthorization();
        }

        if ($this->status != 'valid')
        {
            throw new AuthorizationException("Verify {$this->domain} via {$type} failed, the authorization status becomes {$this->status}.");
        }
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

        $this->domain = ($this->wildcard ? '*.' : '').$this->identifier['value'];
    }
}
