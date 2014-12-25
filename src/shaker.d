module shaker;

import std.stdio;

extern (C) {
  int crypto_box_keypair(ref ubyte pk[32], ref ubyte sk[32]);
  int crypto_box_easy(ubyte*, ubyte*, ulong, ref ubyte[24], ref ubyte[32], ref ubyte[32]);
  int crypto_box_open_easy(ubyte*, ubyte*, ulong, ref ubyte[24], ref ubyte[32], ref ubyte[32]);
  int crypto_sign_keypair(ref ubyte pk[32], ref ubyte sk[64]);
  int crypto_sign(ubyte*, ulong*, ubyte*, ulong, ref ubyte[64]);
  int crypto_sign_open(ubyte*, ulong*, ubyte *, ulong, ref ubyte[32]);
  void randombytes_buf(void *, size_t);
}

struct SignedMessage {
  ubyte[] data;

  // signedBy returns true if this messages was signed by the keypair, signer.
  bool signedBy(SignKeyPair signer) {
    ubyte output[] = new ubyte[this.data.length - 64];
    ulong length;
    int valid = crypto_sign_open(&output[0], &length, &this.data[0], this.data.length, signer.public_key);
    return (valid == 0);
  }
}

struct EncryptedMessage {
  ubyte[] message;
  ubyte[24] nonce;
}

class SignKeyPair {
  ubyte public_key[32];
  ubyte secret_key[64];

  this() {
    crypto_sign_keypair(this.public_key, this.secret_key);
  }

  this(ubyte pubk[32], ubyte secretk[64]) {
    this.public_key = pubk;
    this.secret_key = secretk;
  }

  SignedMessage sign(string data) {
    return this.sign(cast(ubyte[])data);
  }

  SignedMessage sign(ubyte[] data) {
    ubyte output[] = new ubyte[data.length + 64];
    ulong length;
    crypto_sign(&output[0], &length, &data[0], data.length, this.secret_key);
    return SignedMessage(output);
  }
}

class BoxKeyPair {
  ubyte public_key[32];
  ubyte secret_key[32];

  this() {
    crypto_box_keypair(this.public_key, this.secret_key);
  }

  this(ubyte pkey[32], ubyte skey[32]) {
    this.public_key = pkey;
    this.secret_key = skey;
  }

  EncryptedMessage encrypt(string data, BoxKeyPair other) {
    return this.encrypt(cast(ubyte[])data, other);
  }

  EncryptedMessage encrypt(ubyte[] data, BoxKeyPair other) {
    ubyte nonce[24];
    randombytes_buf(&nonce[0], 24);
    return this.encrypt(data, nonce, other);
  }

  EncryptedMessage encrypt(ubyte[] data, ubyte[24] nonce, BoxKeyPair other) {
    ubyte output[] = new ubyte[data.length + 16];

    crypto_box_easy(&output[0], &data[0], data.length, nonce, other.public_key, this.secret_key);
    return EncryptedMessage(output, nonce);
  }

  ubyte[] decrypt(EncryptedMessage msg, BoxKeyPair other) {
    ubyte output[] = new ubyte[msg.message.length - 16];
    crypto_box_open_easy(&output[0], &msg.message[0], msg.message.length, msg.nonce, other.public_key, this.secret_key);
    return output;
  }

}

unittest {
  auto bob = new SignKeyPair;
  auto alice = new SignKeyPair;
  auto jim = new BoxKeyPair;
  auto alex = new BoxKeyPair;

  // Test that key signing works
  SignedMessage data = bob.sign("hey alice this is bob!");
  assert(data.signedBy(bob));
  assert(!data.signedBy(alice));

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

