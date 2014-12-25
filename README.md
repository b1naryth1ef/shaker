# Shaker
A D wrapper around libsodium for simple encryption, signing, and other awesome crypto swag. A WIP.

## Encrypting Data
```D
auto alice = new BoxKeyPair;
auto bob = new BoxKeyPair;

EncryptedMessage message = alice.encrypt("Hey Bob, I think your sexy!", bob);
bob.decrypt(message, alice); // "Hey Bob, I think your sexy!"
```

## Signing Data
```D
auto alice = new SignKeyPair;
auto bob = new SignKeyPair;

SignedMessage message = alice.sign("This is definitly alice talking!");
message.signedBy(bob); // true
```
