module sign;

extern (C) {
  int crypto_sign_keypair(ref ubyte pk[32], ref ubyte sk[64]);
  int crypto_sign(ubyte *sm, ulong *smlen, ubyte *m, ulong mlen, ref ubyte sk[64]);
  int crypto_sign_open(ubyte *m, ulong *mlen, ubyte *sm, ulong smlen, ref ubyte pk[32]);
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


unittest {
  auto bob = new SignKeyPair;
  auto alice = new SignKeyPair;

  // Test that key signing works
  SignedMessage data = bob.sign("hey alice this is bob!");
  assert(data.signedBy(bob));
  assert(!data.signedBy(alice));

}

