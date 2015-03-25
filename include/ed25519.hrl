-define(crypto_sign_ed25519_BYTES, 64).
-define(crypto_sign_ed25519_SEEDBYTES, 32).
-define(crypto_sign_ed25519_PUBLICKEYBYTES, 32).
-define(crypto_sign_ed25519_SECRETKEYBYTES, 64).

-define(crypto_sign_BYTES, ?crypto_sign_ed25519_BYTES).
-define(crypto_sign_SEEDBYTES, ?crypto_sign_ed25519_SEEDBYTES).
-define(crypto_sign_PUBLICKEYBYTES, ?crypto_sign_ed25519_PUBLICKEYBYTES).
-define(crypto_sign_SECRETKEYBYTES, ?crypto_sign_ed25519_SECRETKEYBYTES).

-define(crypto_scalarmult_curve25519_SCALARBYTES, 32).
-define(crypto_scalarmult_curve25519_BYTES, 32).

-define(crypto_scalarmult_SCALARBYTES, ?crypto_scalarmult_curve25519_SCALARBYTES).
-define(crypto_scalarmult_BYTES, ?crypto_scalarmult_curve25519_BYTES).

