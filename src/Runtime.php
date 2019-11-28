<?php
/**
 * Runtime class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stonemax\acme2;

use stonemax\acme2\exceptions\RuntimeException;
use stonemax\acme2\services\AccountService;
use stonemax\acme2\services\EndpointService;
use stonemax\acme2\services\NonceService;
use stonemax\acme2\services\OrderService;
use stonemax\acme2\storage\FileSystemStorageProvider;
use stonemax\acme2\storage\StorageProvider;

/**
 * Class Runtime
 * @package stonemax\acme2
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
     * @var StorageProvider
     */
    public $storageProvider;

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
     * @var \stonemax\acme2\services\AccountService
     */
    public $account;

    /**
     * Order service instance
     * @var \stonemax\acme2\services\OrderService
     */
    public $order;

    /**
     * Endpoint service instance
     * @var \stonemax\acme2\services\EndpointService
     */
    public $endpoint;

    /**
     * Nonce service instance
     * @var \stonemax\acme2\services\NonceService
     */
    public $nonce;

    /**
     * Runtime constructor.
     * @param array $emailList
     * @param string|StorageProvider $storageProvider
     * @param bool $staging
     * @throws exceptions\StorageException
     * @throws RuntimeException
     */
    public function __construct($emailList, $storageProvider, $staging = FALSE)
    {
        $this->emailList = array_filter(array_unique($emailList));
        if(is_string($storageProvider)) // Convert fs path to provider
        {
            $storageProvider = rtrim(trim($storageProvider), '/\\');
            $this->storageProvider = new FileSystemStorageProvider($storageProvider);
        }
        else if ($storageProvider instanceof StorageProvider)
        {
            $this->storageProvider = $storageProvider;
        }
        else
        {
            throw new RuntimeException("Invalid storage provider passed. Must either be a file system path or an actual StorageProvider");
        }
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
        $this->account = new AccountService($this->storageProvider);

        $this->account->init();
    }

    /**
     * Get order service instance
     * @param array $domainInfo
     * @param string $algorithm
     * @param bool $generateNewOder
     * @return OrderService
     * @throws exceptions\AccountException
     * @throws exceptions\NonceException
     * @throws exceptions\OrderException
     * @throws exceptions\RequestException
     */
    public function getOrder($domainInfo, $algorithm, $generateNewOder)
    {
        if (!$this->order)
        {
            $this->order = new OrderService($this->storageProvider, $domainInfo, $algorithm, $generateNewOder);
        }

        return $this->order;
    }
}
