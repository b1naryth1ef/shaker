module secretbox;

import random;

extern (C) {
  int crypto_secretbox_easy(ubyte *c, ubyte *m, ulong mlen, ref ubyte n[24], ref ubyte k[32]);
  int crypto_secretbox_open_easy(ubyte *m, ubyte *c, ulong clen, ref ubyte n[24], ref ubyte k[32]);
}

unittest {
  ubyte nonce[24];
  ubyte key[32];
  ubyte message[] = cast(ubyte[])"This is a test";
  ubyte output[] = new ubyte[message.length + 16];
  ubyte result[] = new ubyte[message.length];

  randombytes_buf(&nonce[0], nonce.length);
  randombytes_buf(&key[0], key.length);
  assert(crypto_secretbox_easy(&output[0], &message[0], message.length, nonce, key) == 0);
  assert(crypto_secretbox_open_easy(&result[0], &output[0], output.length, nonce, key) == 0);
  assert(message == result);
}
