"""Internal service-to-service authentication using self-signed JWTs.

Re-exports from common.internal_auth for backward compatibility.
"""

from common.auth.internal import (  # noqa: F401
    _INTERNAL_JWT_AUDIENCE,
    _INTERNAL_JWT_ISSUER,
    _INTERNAL_JWT_TTL_SECONDS,
    generate_internal_token,
    validate_internal_auth,
)
