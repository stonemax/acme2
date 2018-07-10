<?php
/**
 * CommonConstant class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace stonemax\acme2\constants;

/**
 * Class CommonConstant
 * @package stonemax\acme2\constants
 */
class CommonConstant
{
    /**
     * Http Request type: get
     * @var string
     */
    const REQUEST_TYPE_GET = 'GET';

    /**
     * Http Request type: post
     * @var string
     */
    const REQUEST_TYPE_POST = 'POST';

    /**
     * Http Request type: head
     * @var string
     */
    const REQUEST_TYPE_HEAD = 'HEAD';

    /**
     * Key pair type: rsa
     * @var int
     */
    const KEY_PAIR_TYPE_RSA = 1;

    /**
     * Key pair type: ec
     * @var int
     */
    const KEY_PAIR_TYPE_EC = 2;

    /**
     * Challenge type: http-01
     * @var int
     */
    const CHALLENGE_TYPE_HTTP = 'http-01';

    /**
     * Challenge type: dns-01
     * @var int
     */
    const CHALLENGE_TYPE_DNS = 'dns-01';

    /**
     * Order status: pending
     * @var string
     */
    const ORDER_STATUS_PENDING = 'pending';

    /**
     * Order status: ready
     * @var string
     */
    const ORDER_STATUS_READY = 'ready';

    /**
     * Order status: valid
     * @var string
     */
    const ORDER_STATUS_VALID = 'valid';

    /**
     * Order status: processing
     * @var string
     */
    const ORDER_STATUS_PROCESSING = 'processing';
}
