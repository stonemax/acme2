<?php
/**
 * example php file
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
    CommonConstant::CHALLENGE_TYPE_HTTP => [
        'abc.example.com'
    ],

    CommonConstant::CHALLENGE_TYPE_DNS => [
        '*.www.example.com',
        'www.example.com',
    ],
];

$client = new Client(['alert@example.com'], '../data/', FALSE);

$order = $client->getOrder($domainInfo, CommonConstant::KEY_PAIR_TYPE_RSA, TRUE);
// $order = $client->getOrder($domainInfo, CommonConstant::KEY_PAIR_TYPE_EC, TRUE);    // Issue an ECC certificate

$challengeList = $order->getPendingChallengeList();

/* Get challenges info and set credentials */
foreach ($challengeList as $challenge)
{
    $challengeType = $challenge->getType();    // http-01 or dns-01
    $credential = $challenge->getCredential();

    // echo $challengeType."\n";
    // print_r($credential);

    /* http-01 */
    if ($challengeType == CommonConstant::CHALLENGE_TYPE_HTTP)
    {
        /* example purpose, create or update the ACME challenge file for this domain */
        setChallengeFile(
            $credential['identifier'],
            $credential['fileName'],
            $credential['fileContent']
        );
    }

    /* dns-01 */
    else if ($challengeType == CommonConstant::CHALLENGE_TYPE_DNS)
    {
        /* example purpose, create or update the ACME challenge DNS record for this domain */
        setDNSRecore(
            $credential['identifier'],
            $credential['dnsContent']
        );
    }
}

/* Verify challenges */
foreach ($challengeList as $challenge)
{
    /* Infinite loop until the challenge status becomes valid */
    $challenge->verify();

    /* Or you can specify local verification timeout in seconds */
    // $challenge->verify(60);

    /* Or you can specify Let's Encrypt verification timeout in seconds */
    // $challenge->verify(0, 60);

    /* Or you can specify both timeouts at once */
    // $challenge->verify(60, 60);
}

$certificateInfo = $order->getCertificateFile();

// print_r($certificateInfo);
