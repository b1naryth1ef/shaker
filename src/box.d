module box;

import random;

extern (C) {
  int crypto_box_keypair(ref ubyte[32] pk, ref ubyte[32] sk);
  int crypto_box_easy(ubyte *c, ubyte *m, ulong mlen, ref ubyte[24] n, ref ubyte[32] pk, ref ubyte[32] sk);
  int crypto_box_open_easy(ubyte *m, ubyte *c, ulong clen, ref ubyte[24] n, ref ubyte[32] pk, ref ubyte[32] sk);
}

struct EncryptedMessage {
  ubyte[] message;
  ubyte[24] nonce;
}

class BoxKeyPair {
  ubyte[32] public_key;
  ubyte[32] secret_key;

  this() {
    crypto_box_keypair(this.public_key, this.secret_key);
  }

  this(ubyte[32] pkey, ubyte[32] skey) {
    this.public_key = pkey;
    this.secret_key = skey;
  }

  EncryptedMessage encrypt(string data, BoxKeyPair other) {
    return this.encrypt(cast(ubyte[])data, other);
  }

  EncryptedMessage encrypt(ubyte[] data, BoxKeyPair other) {
    ubyte[24] nonce;
    randombytes_buf(&nonce[0], 24);
    return this.encrypt(data, nonce, other);
  }

  EncryptedMessage encrypt(ubyte[] data, ubyte[24] nonce, BoxKeyPair other) {
    ubyte[] output = new ubyte[data.length + 16];

    crypto_box_easy(&output[0], &data[0], data.length, nonce, other.public_key, this.secret_key);
    return EncryptedMessage(output, nonce);
  }

  ubyte[] decrypt(EncryptedMessage msg, BoxKeyPair other) {
    ubyte[] output = new ubyte[msg.message.length - 16];
    crypto_box_open_easy(&output[0], &msg.message[0], msg.message.length, msg.nonce, other.public_key, this.secret_key);
    return output;
  }

}

unittest {
  auto jim = new BoxKeyPair;
  auto alex = new BoxKeyPair;

  // Test that encryption works
  EncryptedMessage emsg = jim.encrypt("hey alex, your password is 1", alex);
  assert(alex.decrypt(emsg, jim) == "hey alex, your password is 1");

  // Test that encryption with custom nonce works
  ubyte nonce[24] = cast(ubyte[24])"nonce";
  ubyte msg[] = cast(ubyte[])"test";
  EncryptedMessage noncemsg = jim.encrypt(msg, nonce, alex);
  assert(alex.decrypt(noncemsg, jim) == msg);
  assert(noncemsg.nonce == nonce);
}
