module secretbox;

import random;
import std.stdio;

extern (C) {
  int crypto_secretbox_easy(ubyte *c, ubyte *m, ulong mlen, ref ubyte[24] n, ref ubyte[32] k);
  int crypto_secretbox_open_easy(ubyte *m, ubyte *c, ulong clen, ref ubyte[24] n, ref ubyte[32] k);
  size_t crypto_secretbox_macbytes();
}

unittest {
  ubyte[24] nonce;
  ubyte[32] key;
  ubyte[32] key2;
  ubyte[] message = cast(ubyte[])"This is a test";
  ubyte[] output = new ubyte[message.length + crypto_secretbox_macbytes()];
  ubyte[] result = new ubyte[message.length];

  randombytes_buf(&nonce[0], nonce.length);
  randombytes_buf(&key[0], key.length);
  randombytes_buf(&key2[0], key2.length);

  // Make sure we can encrypt a message
  assert(crypto_secretbox_easy(&output[0], &message[0], message.length, nonce, key) == 0);

  // Make sure we cannot decrypt it with the wrong key
  assert(crypto_secretbox_open_easy(&result[0], &output[0], output.length, nonce, key2) != 0);

  // Make sure we can decrypt it with the right key
  assert(crypto_secretbox_open_easy(&result[0], &output[0], output.length, nonce, key) == 0);
  assert(message == result);
}
