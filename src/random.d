module random;

extern (C) {
  void randombytes_buf(void *buf, size_t size);
}
