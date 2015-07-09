module box;

import random;

extern (C) {
  size_t crypto_box_seedbytes();
  size_t crypto_box_publickeybytes();
  size_t crypto_box_secretkeybytes();
  size_t crypto_box_beforenmbytes();
  size_t crypto_box_noncebytes();
  size_t crypto_box_zerobytes();
  size_t crypto_box_boxzerobytes();
  size_t crypto_box_macbytes();

  char *crypto_box_primitive();

  int crypto_box_seed_keypair(ref ubyte[32] pk, ref ubyte[32] sk);
  int crypto_box_keypair(ref ubyte[32] pk, ref ubyte[32] sk);
  int crypto_box_easy(ubyte *c, ubyte *m, ulong mlen, ref ubyte[24] n, ref ubyte[32] pk, ref ubyte[32] sk);
  int crypto_box_open_easy(ubyte *m, ubyte *c, ulong clen, ref ubyte[24] n, ref ubyte[32] pk, ref ubyte[32] sk);
}

struct EncryptedBoxMessage {
  ubyte[] message;
  ubyte[24] nonce;
}

class BoxKeyPair {
  ubyte[32] public_key;
  ubyte[32] secret_key;

  this() {
    assert(crypto_box_keypair(this.public_key, this.secret_key) == 0);
  }

  this(ubyte[32] pkey, ubyte[32] skey) {
    this.public_key = pkey;
    this.secret_key = skey;
  }

  EncryptedBoxMessage encrypt(string data, BoxKeyPair other) {
    return this.encrypt(cast(ubyte[])data, other);
  }

  EncryptedBoxMessage encrypt(ubyte[] data, BoxKeyPair other) {
    ubyte[24] nonce;
    randombytes_buf(&nonce[0], 24);
    return this.encrypt(data, nonce, other);
  }

  EncryptedBoxMessage encrypt(ubyte[] data, ubyte[24] nonce, BoxKeyPair other) {
    ubyte[] output = new ubyte[data.length + crypto_box_macbytes()];

    assert(crypto_box_easy(&output[0], &data[0], data.length, nonce, other.public_key, this.secret_key) == 0);
    return EncryptedBoxMessage(output, nonce);
  }

  ubyte[] decrypt(EncryptedBoxMessage msg, BoxKeyPair other) {
    ubyte[] output = new ubyte[msg.message.length - crypto_box_macbytes()];
    assert(crypto_box_open_easy(&output[0], &msg.message[0], msg.message.length, msg.nonce, other.public_key, this.secret_key) == 0);
    return output;
  }

}

unittest {
  auto jim = new BoxKeyPair;
  auto alex = new BoxKeyPair;

  // Test that encryption works
  EncryptedBoxMessage emsg = jim.encrypt("hey alex, your password is 1", alex);
  assert(alex.decrypt(emsg, jim) == "hey alex, your password is 1");

  // Test that encryption with custom nonce works
  ubyte[24] nonce = cast(ubyte[24])"nonce";
  ubyte[] msg = cast(ubyte[])"test";
  EncryptedBoxMessage noncemsg = jim.encrypt(msg, nonce, alex);
  assert(alex.decrypt(noncemsg, jim) == msg);
  assert(noncemsg.nonce == nonce);
}
