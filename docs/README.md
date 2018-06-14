# ACME2

stonemax/acme2 is a simple PHP tool to manage TLS certificates with ACME-compliant CAs, it's mainly used with let's Encrypt, support for both ESA and ECDSA certifacates. It will not set challenge file or DNS record for you, you can do these jobs manually, or automaticlly with you own code and hooks in stonemax/acme2.


## 1. Current Version
The current version is `1.0.0`.


## 2. Prerequisites
This version works with PHP-5.4.0 or higher, if you need to generate ECDSA certificates, PHP version should be 7.1.0 or higher. PHP need curl and openssl extensons enabled in addition.
Although acme2 uses composer, but composer is just uesd as an autoloader, this porject has no any third party dependencies.


## 3. Install
Clone this project and run `compose install`.

```bash
cd example-directory
git clone git@github.com:stonemax/acme2.git .

composer install
```


## 4. Usage
The basic methods and its necessary arguments are shown here. An example is supplied in [examples/](https://github.com/stonemax/acme2/tree/develop/examples).

#### 4.1. Client

```php
$emailList = ['alert@example.com'];                          // Email list as contact info
$storagePath = './data';                                     // Account data and certificates files will be stored here
$staging = TRUE;                                             // Using stage environment or not, make sure to empty $storagePath directory after you change from staging/test server to the real one


$client = new Client($emailList, $storagePath, $staging);    // Initiating a client
```

After `Client` had been initiated, a Let's Encrypt account will be created and the account data will be placed in `$storagePath`.
When you reinitialize the client, the accout will not be created again.

#### 4.2. Account

```php
$account = $client->getAccount();              // Get account service instance

$account->updateAccountContact($emailList);    // Update account contact info with an email list
$account->updateAccountKey();                  // Regenerate private/public key pair，the old will be replaced by the new
$account->deactivateAccount();                 // Deactive the account
```

#### 4.3. Order
These methods bellow are mainly used for generating certificates.

```php
/* Domains and challenges info for a single certificate with multiple SAN: abc.example.com, *.www.example.com and www.example.com */
$domainInfo = [
    CommonConstant::CHALLENGE_TYPE_HTTP => [
        'abc.example.com'
    ],

    CommonConstant::CHALLENGE_TYPE_DNS => [
        '*.www.example.com',
        'www.example.com',
    ],
];

$algorithm = CommonConstant::KEY_PAIR_TYPE_RSA;                 // Generate RSA certificates, `CommonConstant::KEY_PAIR_TYPE_EC` for ECDSA certificates
$renew = FALSE;                                                 // Renew certificates

$order = $client->getOrder($domainInfo, $algorithm, $renew);    // Get an order service instance

$order->getPendingChallengeList();                              // Get all authorization challenges for domains
$order->getCertificateFile();                                   // Get certificates, such as certificates path, private/public key pair path, valid time
$order->revokeCertificate($reason);                             // Revoke certificates, the certificaes ara unavailable after revoked
```

#### 4.4. Challenge

```php
$challengeList = $order->getPendingChallengeList();

foreach ($challengeList as $challenge)
{
    $challenge->getType();          // Challenge type, http-01 or dns-01
    $challenge->getCredential();    // Challenge detail, http-01 with file name and file content, dns-01 with dns record value
    $challenge->verify();           // Do verifying operation, this method will timeout after 180 seconds by default
}
```


## 5. Domain Verification
When generating a certificate, Let's Encrypt need to verify the ownership and validity of the domain. There are two types of verification: http-01, dns-01.
In the following, we take `www.example.com` as an example.

#### 5.1. http-01
As this type, Let's Encrypt will access a specific file under web server to verify domain.
As this time, the `$challenge` info is like bellow.

```php
echo $challenge->getType();

/* output */
'http-01'


print_r($challenge->getCredential());

/* output */
[
    'identifier' => 'www.example.com',
    'fileName' => 'RzMY-HDa1P0DwZalmRyB7wLBNI8fb11LkxdXzNrhA1Y',
    'fileContent' => 'RzMY-HDa1P0DwZalmRyB7wLBNI8fb11LkxdXzNrhA1Y.CNWZAGtAHIUpstBEckq9W_-0ZKxO-IbxF9Y8J_svbqo',
];
```

With the aboved `$challenge` info, Let's Encrypt will access "http://www.example.com/.well-known/acme-challenge/HDa1P0DwZalmRyB7wLBNI8fb11LkxdXzNrhA1Y", and the file content will be expected as "RzMY-HDa1P0DwZalmRyB7wLBNI8fb11LkxdXzNrhA1Y.CNWZAGtAHIUpstBEckq9W_-0ZKxO-IbxF9Y8J_svbqo".

#### 5.2. dns-01
As this type, you should add a DNS TXT record for domain, Let's Encrypt will check domain's specific TXT record value for verification.
As this time, the `$challenge` info is like bellow.

```php
echo $challenge->getType();

/* output */
'dns-01'


print_r($challenge->getCredential());

/* output */
[
    'identifier' => 'www.example.com',
    'dnsContent' => 'xQwerUEsL8UVc6tIahwIVY4e8N5MAf1xhyY20AELurk',
];
```

With the aboved `$challenge` info, you shuoud add a TXT record for domain `www.example.com`, the record name should be "_acme-challenge.www.example.com", the record value should be "xQwerUEsL8UVc6tIahwIVY4e8N5MAf1xhyY20AELurk".
It's worth noting that you should set TTL as short as possible to let the record take effect as soon as possible.

#### 5.3. Wildcard domain verification
This tool supports generating certificates for wildcard domains.
A wildcard domain, like `*.www.example.com`, will be verified as `www.example.com`, this means the DNS record name should be `_acme-challenge.www.example.com`.
Here is a simple summary for dns-01 challenges about domain and DNS record.

|       Domain       |         DNS record name          | Type | TTL |       DNS record value(just examples)       |
| ------------------ | -------------------------------- | ---- | --- | ------------------------------------------- |
| example.com        | \_acme-challenge.example.com     | TXT  |  60 | xQwerUEsL8UVc6tIahwIVY4e8N5MAf1xhyY20AELurk |
| \*.example.com     | \_acme-challenge.example.com     | TXT  |  60 | G2dOkzSjW3ohib5doPRDrz5a5l8JB1qU8CxURtzF7aE |
| www.example.com    | \_acme-challenge.www.example.com | TXT  |  60 | x1sc0pIwN5Sbqx0NO0QQeu8LxIfhbM2eTjwdWliYxF1 |
| \*.www.example.com | \_acme-challenge.www.example.com | TXT  |  60 | eZ9ViY12gKfdruYHOO7Lu74ICXeQRMDLp5GuHLvPsf7 |


## 6. Full example
Project supplies a [full example](https://github.com/stonemax/acme2/blob/develop/examples/example.php) under directory [examples/](https://github.com/stonemax/acme2/tree/develop/examples).


## 7. Thanks
This Project had got a lot of inspirations from [yourivw/LEClient](https://github.com/yourivw/LEClient). Thanks!


## 8. License
This project is licensed under the MIT License, see the [LICENSE](https://github.com/stonemax/acme2/blob/develop/LICENSE) file for detail.
