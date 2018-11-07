# oauth2-jwt-bearer

This is an implementation of the jwt-bearer authorization grant flow
that is specified by the OAuth2 JWT profile in
[rfc7523](https://tools.ietf.org/html/rfc7523).

The goal is to implement a portable implementation of this flow that
can be used against multiple servers. Its goal is to be pretty
general, and has been tested against the [Google Cloud Platform OAuth2
implementation](https://developers.google.com/identity/protocols/OAuth2ServiceAccount),
and the [Smith implementation](http://smith.st/) as well as a generic
test server, but there may be a way to go. If you find a server that
this implementation doesn't work with, let me know and I will add a
test and address it.

### Why?

OAuth2 / OIDC flows are complicated enough that it warrants having an
implementation to fall back on. The scope of this library is one
specific flow to make the implementation manageable. It would be nice
to have a complete set of flow implentations, but the reality is that
OAuth2 doesn't really offer much in the terms of interoperability - it
is about consistency/security, not about interchangable
implementations - this means that implementing everything at once is a
somewhat lost battle. Restricting ourselves to this specific flow
allows us to provide something useful and possible.

### Stability

This library is new, and should have the disclaimers that normally
comes with that, but the API should be stable and is currently in
production level usage. The library will be maintained going forward.


### Example

A crude example:

```
import           Crypto.JWT (JWT)
import           Network.OAuth2.JWT.Client
import           Network.HTTP.Client (Manager)

example :: Manager -> JWK -> IO (Either GrantError AccessToken)
example manager key =  do
  let
    endpoint = TokenEndpoint "https://www.googleapis.com/oauth2/v4/token"
    iss = Issuer "example@example.org"
    scopes = [Scope "profile"]
    aud = Audience "https://www.googleapis.com/oauth2/v4/token"
    expiry = ExpiresIn 3600
    claims = Claims iss Nothing aud scopes expiry []
  store <- newStore manager endpoint claims key
  grant store
```

The key function here is the `grant` function which is what you call
to get your access token.

The `grant` function obtains an access token, if we have already
aquired one (and it is still valid) we will re-use that token, if we
don't already have a token or the token has expired, we go and ask for
a new one.

This operation is safe to call from multiple threads. If we are using
a current token reads will happen concurrently, If we have to go to
the network the request will be serialised so that only one request is
made for a new token.

The access token can be used as a bearer token in an `Authorization`
header. See the specification for more details but it would be like:

```
Authorization: Bearer ${ACCESS_TOKEN}
```
