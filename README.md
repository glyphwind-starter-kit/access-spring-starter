# access-spring-starter

Spring Boot starter that gives a service its caller. The API gateway is the only place
that knows sessions; it forwards the identity as signed headers, and this starter turns
them into a `Caller` and enforces the access annotations. Services never see cookies,
tokens or the session store.

## Model

- **Authentication** happens once, at the gateway. It resolves the session and sets
  `X-Auth-User`, `X-Auth-Username`, `X-Auth-Session`, `X-Auth-Permissions`, `X-Auth-Time`,
  `X-Auth-Signature`.
- **Authorization** happens in the service: it knows its own permissions
  (`resource:action`) and checks them; it does not know roles.
- **Trust** is the signature: HMAC-SHA256 over the identity, the time and the request
  method + path, with a secret shared between the gateway and the service (from Vault).
  Headers without a valid signature are ignored, so a caller inside the network cannot
  impersonate a user; binding the path stops replaying a captured identity elsewhere and
  the time bounds replay on the same path. Repeated identity headers are ignored too.

## Use

```groovy
// settings.gradle - until the library is published, it is a composite build
includeBuild(file('lib').exists() ? 'lib' : '../access-spring-starter')
// build.gradle
implementation 'dev.morvex:access-spring-starter'
```

```yaml
access:
  gateway:
    secret: ${ACCESS_GATEWAY_SECRET}   # >= 32 bytes, same value as in the gateway
  # path-patterns: ["/api/**"]       # where the rules apply (default)
  # default-policy: authenticated    # un-annotated handler needs a signed-in caller
```

```java
@RestController
@RequestMapping("/api/v1/orders")
class OrdersController {

    @GetMapping
    @RequiresPermission({"orders:read", "orders:admin"})   // any of
    List<Order> list(Caller caller) { ... }               // Caller is injectable

    @PostMapping("/{id}/cancel")
    @Authenticated                                         // any signed-in user ...
    void cancel(@PathVariable UUID id, Caller caller) {
        if (!owner(id).equals(caller.userId())) {
            caller.require("orders:admin");                // ... plus a rule in code
        }
    }

    @GetMapping("/ping")
    @PublicEndpoint                                        // no identity needed
    Map<String, String> ping() { ... }
}
```

Deny by default: under `/api/**` a handler without any of the three annotations requires
a signed-in caller. A service without a protected API can set `access.default-policy: public`.

Errors use the shared body `{status, code, error, params}`: `401 not_authenticated`,
`403 permission_required` with `params.permission`.

## Local runs without a gateway

`access.gateway.required=false` trusts the headers unsigned and logs a warning at start-up.
Only for `application-local.yaml`; a deployed service without a secret refuses to start.

## Gateway side

`GatewaySigner` and `IdentityHeaders` live here too, so both ends share one algorithm:

```java
var signer = new GatewaySigner(secret);
long now = Instant.now().getEpochSecond();
String signature = signer.sign(identity, now, request.getMethod(), request.getRequestURI());
```
