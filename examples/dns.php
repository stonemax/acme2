<?php
/**
 * dns php file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

include('../vendor/autoload.php');

use stonemax\acme2\Client;
use stonemax\acme2\constants\CommonConstant;

$domainInfo = [
    CommonConstant::CHALLENGE_TYPE_DNS => [
        '*.www.99xs.cn',
        '*.a.www.99xs.cn',
    ],
    CommonConstant::CHALLENGE_TYPE_HTTP => [
        'www.99xs.cn',
    ],
];

$client = new Client(['zjl@99xs.com'], '../data/', TRUE);

$order = $client->getOrder('99xs.cn', $domainInfo, CommonConstant::KEY_PAIR_TYPE_RSA);

$challengeList = $order->getPendingChallengeList();

foreach ($challengeList as $challenge)
{
    file_put_contents('./a', $challenge->getType()."\n\n".json_encode($challenge->getCredential()));
    $challenge->verify();
}

print_r($order->getCertificateFile());

//$order->revokeCertificate(1);