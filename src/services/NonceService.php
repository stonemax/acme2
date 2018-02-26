<?php
/**
 * NonceService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stomemax\acme2\services;

use stomemax\acme2\Client;
use stomemax\acme2\exceptions\NonceException;
use stomemax\acme2\helpers\CommonHelper;
use stomemax\acme2\helpers\RequestHelper;

/**
 * Class NonceService
 * @package stomemax\acme2\services
 */
class NonceService
{
    /**
     * Request nonce anti replay attack
     * @var string
     */
    private $_nonce;

    /**
     * NonceService constructor.
     * @throws NonceException
     * @throws \stomemax\acme2\exceptions\RequestException
     */
    public function __construct()
    {

    }

    /**
     * Get nonce
     * @return string
     * @throws NonceException
     * @throws \stomemax\acme2\exceptions\RequestException
     */
    public function get()
    {
        if (!$this->_nonce)
        {
            $this->_nonce = $this->getNew();
        }

        $nonce = $this->_nonce;

        $this->destroy();

        return $nonce;
    }

    /**
     * Set nonce
     * @param $nonce
     */
    public function set($nonce)
    {
        $this->_nonce = $nonce;
    }

    /**
     * Destroy nonce
     */
    public function destroy()
    {
        $this->_nonce = NULL;
    }

    /**
     * Get new nonce for next request
     * @return string
     * @throws NonceException
     * @throws \stomemax\acme2\exceptions\RequestException
     */
    private function getNew()
    {
        $newNonceUrl = Client::$runtime->endpoint->newNonce;

        list($code, $header, ) = RequestHelper::head($newNonceUrl);

        if ($code != 204)
        {
            throw new NonceException("Get new nonce failed, the url is: {$newNonceUrl}");
        }

        $nonce = CommonHelper::getNonceFromResponseHeader($header);

        if (!$nonce)
        {
            throw new NonceException("Get new nonce failed, the header doesn't contain `Replay-Nonce` filed, the url is: {$newNonceUrl}");
        }

        return $nonce;
    }
}
