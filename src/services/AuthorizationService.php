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
use stomemax\acme2\exceptions\AuthorizationException;
use stomemax\acme2\helpers\OpenSSLHelper;
use stomemax\acme2\helpers\RequestHelper;

/**
 * Class AuthorizationService
 * @package stomemax\acme2\services
 */
class AuthorizationService
{
    public $identifier;

    public $status;

    public $expires;

    public $challenges;

    public $authorizationUrl;

    public function __construct($authorizationUrl)
    {
        $this->authorizationUrl = $authorizationUrl;

        $this->getAuthorization();
    }

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

    public function verify($type, $keyAuthorization)
    {
        $challenge = $this->getChallenge($type);

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

    private function populate($authorizationInfo)
    {
        foreach ($authorizationInfo as $key => $value)
        {
            $this->{$key} = $value;
        }
    }
}
