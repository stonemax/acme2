## 1. Challenge
Challenge objects are created in the "pending" state. They transition to the "processing" state when the client responds to the challenge (see Section 7.5.1) and the server begins attempting to validate that the client has completed the challenge. Note that within the "processing" state, the server may attempt to validate the challenge multiple times (see Section 8.2). Likewise, client requests for retries do not cause a state change. If validation is successful, the challenge moves to the "valid" state; if there is an error, the challenge moves to the "invalid" state.

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


## 2. Authorization
Authorization objects are created in the "pending" state. If one of the challenges listed in the authorization transitions to the "valid" state, then the authorization also changes to the "valid" state. If the client attempts to fulfill a challenge and fails, or if there is an error while the authorization is still pending, then the authorization transitions to the "invalid" state. Once the authorization is in the "valid" state, it can expire ("expired"), be deactivated by the client ("deactivated", see Section 7.5.2), or revoked by the server ("revoked").

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


## 3. Order
Order objects are created in the "pending" state. Once all of the authorizations listed in the order object are in the "valid" state, the order transitions to the "ready" state. The order moves to the "processing" state after the client submits a request to the order’s "finalize" URL and the CA begins the issuance process for the certificate. Once the certificate is issued, the order enters the "valid" state. If an error occurs at any of these stages, the order moves to the "invalid" state. The order also moves to the "invalid" state if it expires or one of its authorizations enters a final state other than "valid" ("expired", "revoked", or "deactivated").

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
Account objects are created in the "valid" state, since no further action is required to create an account after a successful newAccount request. If the account is deactivated by the client or revoked by the server, it moves to the corresponding state.

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

Note that some of these states may not ever appear in a "status" field, depending on server behavior. For example, a server that issues synchronously will never show an order in the "processing" state. A server that deletes expired authorizations immediately will never show an authorization in the "expired" state.
