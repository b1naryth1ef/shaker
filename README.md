# Shaker
A D wrapper around [libsodium](http://doc.libsodium.org/) for simple encryption, signing, and other awesome cryptoness. This project is currently in heavy development and I promise to break it often (until a 1.0 like release).

## Usage
Shaker provides two main avenues for using it, the first being a lightweight wrapper over the basics of libsodium allowing you to use it in a very object-oriented way, not present in the original libsodium library. However, for those that have a more custom use case or want to build out object-oriented primitives themselves, Shaker also exports all of the D-compatibile functions directly from libsodium.

## D-like OO Usage

### Encrypting Data
```D
auto alice = new BoxKeyPair;
auto bob = new BoxKeyPair;

EncryptedBoxMessage message = alice.encrypt("Hey Bob, I think your sexy!", bob);
bob.decrypt(message, alice); // "Hey Bob, I think your sexy!"
```

### Signing Data
```D
auto alice = new SignKeyPair;
auto bob = new SignKeyPair;

SignedMessage message = alice.sign("This is definitly alice talking!");
message.signedBy(bob); // true
```

