# Operator authentication foundation

## Verified deployment boundary

The current deployment has no FastAPI authentication middleware, identity
provider integration, frontend login/session, or reverse proxy configuration.
The backend is published directly on host port `8555`, and CORS is configured
permissively for the existing dashboard. CORS and Docker networking are not
authentication controls. Existing read-only routes therefore retain their
current compatibility behavior, but campaign mutation routes must remain
unexposed.

## Provider-neutral foundation

`operator_auth.py` defines immutable `VerifiedPrincipal` values and
deny-by-default permissions. A trusted future adapter must verify an IdP
assertion or server-side session before constructing a principal. Query
parameters, request headers, and client-provided roles are never accepted as
identity evidence. The helper is injectable in tests and is not registered as
FastAPI middleware or as a public endpoint.

Roles and permissions are intentionally narrow:

- `analyst`: `adhoc:read`
- `administrator`: read, create, cancel, and run targeted campaigns

Authentication, expiry, unknown-role, permission, and audit failures deny
access. Audit events contain only subject, authentication source, action,
outcome, and reason code; they do not contain tokens or claims.

## Recommended deployment model

For a remote operator workflow, place an authenticated reverse proxy in front
of the backend and validate OIDC/OAuth2 or an equivalent enterprise identity
provider there. The proxy-to-backend link must be private and authenticated;
the application must receive a server-verified principal through an internal
adapter, never an arbitrary public `X-User` or role header. Cookie-based
sessions additionally require secure, HttpOnly, SameSite cookies and CSRF
protection on every state-changing request.

For the standalone installation, the smallest safe exposure reduction is to
bind host port `8555` to `127.0.0.1` in Compose and keep dashboard access on
the local operator workstation. If remote access is required, use the
authenticated proxy model instead of publishing the backend directly.

Before campaign APIs are enabled, the deployment still needs a selected IdP,
trusted proxy or application adapter, operator-role mapping, audit sink,
CSRF/session policy if applicable, and an explicit protected create/cancel
route. None of those choices are silently assumed by this foundation.
