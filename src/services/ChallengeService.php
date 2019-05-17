<?php
/**
 * ChallengeService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stonemax\acme2\services;

use stonemax\acme2\Client;

/**
 * Class ChallengeService
 * @package stonemax\acme2\services
 */
class ChallengeService
{
    /**
     * Challenge type: http-01, dns-01
     * @var string
     */
    private $_type;

    /**
     * challenge Credential
     * @var array
     */
    private $_credential;

    /**
     * Authorization inntance
     * @var \stonemax\acme2\services\AuthorizationService
     */
    private $_authorication;

    /**
     * ChallengeService constructor.
     * @param string $type
     * @param \stonemax\acme2\services\AuthorizationService $authorization
     */
    public function __construct($type, $authorization)
    {
        $this->_type = $type;
        $this->_authorication = $authorization;
    }

    /**
     * Get challenge type
     * @return string
     */
    public function getType()
    {
        return $this->_type;
    }

    /**
     * Get challenge credential
     * @return array
     */
    public function getCredential()
    {
        return $this->_credential;
    }

    /**
     * Set challenge credential
     * @param array $credential
     */
    public function setCredential($credential)
    {
        $this->_credential = $credential;
    }

    /**
     * Verify
     * @param int $verifyLocallyTimeout
     * @param int $verifyCATimeout
     * @return bool
     * @throws \stonemax\acme2\exceptions\AccountException
     * @throws \stonemax\acme2\exceptions\AuthorizationException
     * @throws \stonemax\acme2\exceptions\NonceException
     * @throws \stonemax\acme2\exceptions\RequestException
     * @throws \stonemax\acme2\exceptions\timeout\VerifyCATimeoutException
     * @throws \stonemax\acme2\exceptions\timeout\VerifyLocallyTimeoutException
     */
    public function verify($verifyLocallyTimeout = 0, $verifyCATimeout = 0)
    {
        $orderService = Client::$runtime->order;

        if ($orderService->isAllAuthorizationValid() === TRUE)
        {
            return TRUE;
        }

        return $this->_authorication->verify($this->_type, $verifyLocallyTimeout, $verifyCATimeout);
    }
}
