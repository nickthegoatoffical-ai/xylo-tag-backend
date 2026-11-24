# Xylo Tag Backend (Vercel + Flask)

Only the PlayFab title ID (B0BEA) is in the code. Everything else is an environment variable.

REQUIRED (the app refuses to start without them):
| Name | What |
|---|---|
| PLAYFAB_SECRET_KEY | PlayFab secret key of title B0BEA |
| META_ACCESS_TOKEN | OC\|APP_ID\|APP_SECRET of the Xylo Tag Meta app |
| EXPECTED_PACKAGE_ID | the game's Android package name |
| META_CERT_SHA256 | SHA-256 of the signing certificate (colons optional) |
| SESSION_SECRET | any long random string |

OPTIONAL: ANTI_LIB_MODE (off/log/enforce, default enforce), ANTI_LIB_SIGNATURES, ANTI_LIB_ALLOWLIST,
ALLOW_BASIC_DEVICE, REQUIRE_ATTESTATION, MIN_APP_VERSION, EXPOSE_REASONS, MOTD_TEXT.
