# ACME2
stonemax/acme2 是一个简单的 PHP 工具，用于生成符合 ACME(Version 2) 协议的CA证书，目前主要用于 [Let's Encrypt](https://letsencrypt.org/) 的证书签发，同时支持 RSA 和 ECDSA 类型证书的签发。本工具仅用于生成证书，并不会如官方工具一样帮助您配置 Web Server 或者 DNS 记录，因此，在域名的校验过程中，无论是在 Web Server 上设置校验文件，还是设置 DNS 记录，都需要您自己处理，您可以手动处理，也可以通过代码中的钩子进行自动化处理。


## 1. 当前版本
stonemax/acme2 当前的版本是 `1.0.4`。


## 2. 先决条件
由于使用了命名空间、三元运算符简写形式等 PHP 特性，因此使用本工具的最低 PHP 版本要求为 5.4.0+（含5.4.0）。但是当您要生成 ECDSA 类型的证书时，需要的 PHP 版本最低为 7.1.0+（含7.1.0）。此外，我们还需要开启 curl 和 openssl 扩展。
虽然stonemax/acme2 使用了 composer 作为包管理器，但是仅将其作为文件的自动加载器使用，实际上并未使用任何外部依赖


## 3. 安装
将代码下载到某个文件夹下，进入此文件夹，在当前目录下执行以下命令即可完成安装：

```bash
cd example-directory
git clone git@github.com:stonemax/acme2.git .

composer install
```


## 4. 使用
在这里，我们将介绍 stonemax/acme2 中对外暴露的方法，通过认识这些方法，您就大致知道如何使用了，我们也提供了一份案例代码，位于 [examples/](https://github.com/stonemax/acme2/tree/master/examples) 目录下。

#### 4.1. 初始化客户端

```php
$emailList = ['alert@example.com'];                          // 邮箱列表，在适当时机，Let's Encrypt 会发送邮件到此邮箱，例如：证书即将过期
$storagePath = './data';                                     // 账户数据以及生成的证书存储的目录
$staging = TRUE;                                             // 是否使用 staging 环境

$client = new Client($emailList, $storagePath, $staging);    // 初始化客户端
```

初始化一个客户端时，工具会自动生成一个 Let's Encrypt 账户，账户数据存储在 `$storagePath/account` 目录下，当您再次初始化客户端时，如果账户数据已经存在，则不会再创建新的账户。

#### 4.2. 账户相关方法

```php
$account = $client->getAccount();              // 获取账户实例

$account->updateAccountContact($emailList);    // 更新账户的联系邮件
$account->updateAccountKey();                  // 重新生成 private/public 密钥对，并使用新的密钥对替换原有的
$account->deactivateAccount();                 // 销毁账户
```

#### 4.3. 订单相关方法
证书的生成，主要使用的就是订单的相关方法。

```php
/* 证书包含的域名及其验证信息 */
$domainInfo = [
    CommonConstant::CHALLENGE_TYPE_HTTP => [
        'abc.example.com'
    ],

    CommonConstant::CHALLENGE_TYPE_DNS => [
        '*.www.example.com',
        'www.example.com',
    ],
];

$algorithm = CommonConstant::KEY_PAIR_TYPE_RSA;                 // 生成 RSA 类型的证书，使用 `CommonConstant::KEY_PAIR_TYPE_EC` 生成 ECDSA 证书

$order = $client->getOrder($domainInfo, $algorithm, TRUE);      // 获取订单实例

$order->getPendingChallengeList();                              // 获取 ChallengeService 实例列表，该列表中存储了域名验证的相关信息
$order->getCertificateFile();                                   // 获取证书的相关信息，包含：证书位置、生成证书的密钥对文件位置、证书有效期
$order->revokeCertificate($reason);                             // 吊销证书，证书吊销后就不能再使用了，需要重新生成
```

`getOrder()` 方法的原型为：

```php
public function getOrder(array $domainInfo,int $algorithm, bool $generateNewOder = TRUE): OrderService
```

其中第三个参数 `$generateNewOder` 控制是否创建新订单。当 `$generateNewOder == TRUE`，原证书目录下的所有文件均会被删除已用于生成新证书；当 `$generateNewOder == FALSE` 时，会返回一个已经存在的订单服务实例，一般用于撤销证书。

#### 4.4. 证书验证相关方法

```php
$challengeList = $order->getPendingChallengeList();

foreach ($challengeList as $challenge)
{
    $challenge->getType();          // 认证方式，http-01 或者 dns-01
    $challenge->getCredential();    // 认证的具体信息，如果认证方式是 http-01，返回的数据中包含文件名和文件内容，如果是 dns-01，则包含 DNS 的记录值
    $challenge->verify();           // 验证域名，这是一个无限循环，直到证书验证成功才返回
}
```

`verify()` 方法的原型为：

```php
public function verify(int $verifyLocallyTimeout = 0, int $verifyCATimeout = 0): bool
```

* 第一个参数 `$verifyLocallyTimeout` 为本地验证的超时时间。默认值 0 表明不会触发超时机制；
* 第二个参数 `$verifyCATimeout` 为 Let's Encrypt 的验证超时时间。默认值 0 表明不会触发超时机制。


## 5. 域名验证
在生成证书时，Let's Encrypt 需要校验域名的所有权和有效性，主要有两种认证方式：域名下的文件校验（http-01）和域名 DNS 的 TXT 记录值认证（dns-01）。下文中，我们一律以 www.example.com 进行举例说明。

#### 5.1. HTTP 认证
在这种认证方式下，需要在域名对应站点的相应位置放置一个特定文件，文件内包含特定的文件内容，Let's Encrypt 会访问该文件以校验域名。
在此种情况下，`$challenge` 的相关信息如下所示。

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

此时，Let's Encrypt 会访问以下地址来进行域名认证：`http://www.example.com/.well-known/acme-challenge/HDa1P0DwZalmRyB7wLBNI8fb11LkxdXzNrhA1Y`。

#### 5.2. DNS 认证
在这种方式下，需要在相应域名的 DNS 记录中增加 TXT 记录，这时 `$challenge` 的相关信息如下所示。

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

此时，需要增加主机记录为 `_acme-challenge.www.example.com`，类型为 TXT 的 DNS 记录，记录值为：`xQwerUEsL8UVc6tIahwIVY4e8N5MAf1xhyY20AELurk`。值得注意的是，记录的 TTL 值需要设置的尽量小，以便尽快生效。

#### 5.3. 通配符域名认证
ACME2支持通配符证书的生成，但仅能使用 DNS 认证。拿 `*.www.example.com` 举例来说，当进行 DNS 认证时，其实是针对域名 `www.example.com` 进行校验的。下面针对 DNS 认证的各种情况做一个说明。

|        域名        |            DNS 记录名            | 类型 | TTL |                 DNS 记录值                  |
| ------------------ | -------------------------------- | ---- | --- | ------------------------------------------- |
| example.com        | \_acme-challenge.example.com     | TXT  |  60 | xQwerUEsL8UVc6tIahwIVY4e8N5MAf1xhyY20AELurk |
| \*.example.com     | \_acme-challenge.example.com     | TXT  |  60 | G2dOkzSjW3ohib5doPRDrz5a5l8JB1qU8CxURtzF7aE |
| www.example.com    | \_acme-challenge.www.example.com | TXT  |  60 | x1sc0pIwN5Sbqx0NO0QQeu8LxIfhbM2eTjwdWliYxF1 |
| \*.www.example.com | \_acme-challenge.www.example.com | TXT  |  60 | eZ9ViY12gKfdruYHOO7Lu74ICXeQRMDLp5GuHLvPsf7 |


## 6. 状态机
[各对象状态机](https://github.com/stonemax/acme2/blob/master/docs/state-machine-zh.md)


## 7. 完整例子
stonemax/acme2 随代码附上了一个完整的例子，位于 [examples/](https://github.com/stonemax/acme2/tree/master/examples) 目录下，也可以点击 [examples/example.php](https://github.com/stonemax/acme2/blob/master/examples/example.php) 直接查看。


## 8. 感谢
[yourivw/LEClient](https://github.com/yourivw/LEClient) 项目对本项目有很大帮助，在此表示感谢！


## 9. 许可证
此项目使用的是 MIT 许可证，[查看许可证信息](https://github.com/stonemax/acme2/blob/master/LICENSE)。
