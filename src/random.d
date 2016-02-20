module random;

import std.stdio;

extern (C) {
  uint randombytes_random();
  uint randombytes_uniform(const uint upper_bound);
  void randombytes_buf(void *buf, size_t size);
  int randombytes_close();
  void randombytes_stir();
}

unittest {
  randombytes_stir();

  assert(randombytes_random() >= 0);

  for (int i = 0; i < 1000; i++) {
    assert(randombytes_uniform(10) < 10);

    ubyte[24] testa, testb;
    randombytes_buf(&testa[0], 24);
    randombytes_buf(&testb[0], 24);
    assert(testa != testb);
  }

  assert(randombytes_close() == 0);
}


