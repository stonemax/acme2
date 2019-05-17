## 1. 挑战 Challenge
挑战创建后进入 `pending` 状态。当客户端发起验证挑战请求后，进入 `processing` 状态，此时，服务器端开始验证客户端是否完成了挑战。值得注意的是，在 `processing` 阶段，服务器端可能会多次验证挑战是否完成。类似的，客户端请求重试验证不会造成状态改变。如果验证成功，挑战状态变更为 `valid`；如果发生错误，状态变更为 `invalid`。

```text
         pending
            |
            | Receive
            | response
            V
        processing <-+
            |   |    | Server retry or
            |   |    | client retry request
            |   +----+
            |
            |
Successful  |   Failed
validation  |   validation
  +---------+---------+
  |                   |
  V                   V
valid              invalid
```


## 2. 授权 Authorization
授权创建后进入 `pending` 状态。如果授权的任意一个挑战转变为 `valid` 状态，授权也会进入 `valid` 状态。如果服务器端验证挑战失败，或者发生了错误（当授权状态仍为 `pending` 时），授权将进入 `invalid` 状态。一旦授权进入 `valid` 状态，授权可以过期 `expired`，可以被客户端停用 `deactivated`，可以被服务器端撤销 `revoked`。

```text
               pending --------------------+
                  |                        |
Challenge failure |                        |
       or         |                        |
      Error       |  Challenge valid       |
        +---------+---------+              |
        |                   |              |
        V                   V              |
     invalid              valid            |
                            |              |
                            |              |
                            |              |
             +--------------+--------------+
             |              |              |
             |              |              |
      Server |       Client |   Time after |
      revoke |   deactivate |    "expires" |
             V              V              V
          revoked      deactivated      expired
```


## 3. 订单 Order
订单创建后进入 `pending` 状态。只有当订单下的所有授权均进入 `valid` 状态，订单才会进入 `ready` 状态。当客户端调用了订单的 `finalize` URL，订单进入 `processing` 状态，此时服务器端开始签发证书。一旦证书签发完成，订单进入 `valid` 状态。如果在上述任一状态时发生错误，订单将进入 `invalid` 状态。如果订单过期了，或者任一授权的最终状态不是 `valid`（`expired`，`revoked`，或者 `deactivated`），订单也会进入 `invalid` 状态。

```text
 pending --------------+
    |                  |
    | All authz        |
    | "valid"          |
    V                  |
  ready ---------------+
    |                  |
    | Receive          |
    | finalize         |
    | request          |
    V                  |
processing ------------+
    |                  |
    | Certificate      | Error or
    | issued           | Authorization failure
    V                  V
  valid             invalid
```


## 4. 账户 Account
创建账户请求调用后，如果没有再进行后续的动作，账户进入 `valid` 状态。如果账户被客户端停用或者被服务器端撤销，将进入相应的状态：`deactivated`、`revoked`。

```text
                  valid
                    |
                    |
        +-----------+-----------+
Client  |                Server |
deactiv.|                revoke |
        V                       V
   deactivated               revoked
```

---

需要注意的是，根据服务器端具体的实现行为，上述的某些状态可能不会出现。例如：

* 如果服务器端签发证书的动作是同步的，那么订单就不会进入 `processing` 状态；
* 如果服务器端将已过期的授权立即删除，那么授权就不会进入 `expired` 状态。
