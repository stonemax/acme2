<?php
/**
 * Runtime class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stomemax\acme2;

use stomemax\acme2\exceptions\RuntimeException;
use stomemax\acme2\helpers\RequestHelper;
use stomemax\acme2\services\AccountService;
use stomemax\acme2\services\EndpointService;
use stomemax\acme2\services\NonceService;

/**
 * Class Runtime
 * @package stomemax\acme2
 */
class Runtime
{
    /**
     * Email list
     * @var array
     */
    public $emailList;

    /**
     * Storage path for certificate keys, public/private key pair and so on
     * @var string
     */
    public $storagePath;

    /**
     * If staging status
     * @var bool
     */
    public $staging;

    /**
     * Config params
     * @var array
     */
    public $params;

    /**
     * Account service instance
     * @var \stomemax\acme2\services\AccountService
     */
    public $account;

    /**
     * Endpoint service instance
     * @var \stomemax\acme2\services\EndpointService
     */
    public $endpoint;

    /**
     * Nonce service instance
     * @var \stomemax\acme2\services\NonceService
     */
    public $nonce;

    /**
     * Runtime constructor.
     * @param array $emailList
     * @param string $storagePath
     * @param bool $staging
     */
    public function __construct($emailList, $storagePath, $staging = FALSE)
    {
        $this->emailList = array_filter(array_unique($emailList));
        $this->storagePath = trim($storagePath);
        $this->staging = boolval($staging);

        sort($this->emailList);
    }

    /**
     * Init
     */
    public function init()
    {
        $this->params = require(__DIR__.'/config.php');

        $this->endpoint = new EndpointService();
        $this->nonce = new NonceService();
        $this->account = new AccountService($this->storagePath.'/account');
    }
}
