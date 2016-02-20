module hash;

import std.stdio;
import std.conv;

extern (C) {
  int crypto_generichash(ubyte *output, size_t outlen,
      const ubyte *input, ulong inlen,
      const ubyte *key, size_t key);

  size_t crypto_generichash_bytes();
}

string generichash(string input) {
  return cast(string)generichash(cast(ubyte[])input);
}

ubyte[] generichash(ubyte[] input) {
  ubyte[] output = new ubyte[crypto_generichash_bytes()];
  assert(crypto_generichash(&output[0], output.length,
      &input[0], input.length, null, 0) == 0);
  return output;
}

unittest {
  const string TEST = "THIS IS A TEST";
  assert(generichash(TEST) == generichash(TEST));
  assert(generichash(cast(ubyte[])TEST) == generichash(TEST));
}

