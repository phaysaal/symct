/*
 * EC Private Key (P-256/secp256r1 curve) for ECDSA signing
 */

const char EC_PRIVATE_KEY_PEM[] =
  "-----BEGIN EC PRIVATE KEY-----\n"
  "MHcCAQEEIOhvRtoVTyERtfITpyZCRsVYSdi/lNURownT0TQskPNGoAoGCCqGSM49\n"
  "AwEHoUQDQgAEXGKpK6qFt9cGqR/WBwFu2QSjSAD009RgwzO7dASPVX7aIBanZx3w\n"
  "K4aW/77rv+rDm82OsejoNW3dbbPf9vUaWQ==\n"
  "-----END EC PRIVATE KEY-----\n";

const int EC_PRIVATE_KEY_PEM_LEN = sizeof(EC_PRIVATE_KEY_PEM) - 1;
