# AndroidX3DH

This package implements the <a href="https://signal.org/docs/specifications/x3dh/">X3DH</a> key agreement protocol in Swift. The cryptographic operations are provided by <a href="https://github.com/jedisct1/libsodium">libsodium</a> entirely. Libsodium is integrated via <a href="https://github.com/terl/lazysodium-android.git">Lazysodium</a>.

## Installation

### Jitpack
To integrate the library via jitpack add the jitpack repository to your root `build.gradle` file:

```
allprojects {
  repositories {
    ...
    maven { url  "https://dl.bintray.com/terl/lazysodium-maven" }
    maven { url 'https://jitpack.io' }
  }
}
```

You can then add the dependency to your app's `build.gradle` file where `$VERSION` specifies the specific version of the library:

```
dependencies {
  implementation 'com.github.TICESoftware:AndroidX3DH:$VERSION'
  implementation 'com.github.TICESoftware:AndroidHKDF:1.0.0'
  implementation "com.goterl:lazysodium-android:4.1.0@aar"
  implementation 'net.java.dev.jna:jna:5.5.0@aar'
}
 ```

# Usage

Alice needs to retrieve some public keys from Bob that he has made public previously. She then calculates a shared secret and sends some information to Bob so that he can calculcate the shared secret on his side as well.

```kotlin
val preKeySigner = // ... Signing the key is not part of this library
val prekeySignatureVerifier = // ... and neither is verification

val bob = X3DH()
val bobIdentityKeyPair = bob.generateIdentityKeyPair()
val bobSignedPrekeyPair = bob.generateSignedPrekeyPair { /* Signer */ }
val bobOneTimePrekeyPairs = bob.generateOneTimePrekeyPairs(2)

val alice = X3DH()
val aliceIdentityKeyPair = alice.generateIdentityKeyPair()
val aliceSignedPrekey = alice.generateSignedPrekeyPair { /* Signer */ }

// [Alice fetches bob's prekey bundle ...]

val keyAgreementInitiation = alice.initiateKeyAgreement(bobIdentityKeyPair.publicKey, bobSignedPrekeyPair.keyPair.publicKey, bobSignedPrekeyPair.signature, bobOneTimePrekeyPairs.first().publicKey, aliceIdentityKeyPair, aliceSignedPrekey.keyPair.publicKey, { /* Verifier */ }, info)

// [Alice sends identity key, ephemeral key and used one-time prekey to bob ...]

val sharedSecret = bob.sharedSecretFromKeyAgreement(aliceIdentityKeyPair.publicKey, keyAgreementInitiation.ephemeralPublicKey, bobOneTimePrekeyPairs.first(), bobIdentityKeyPair, bobSignedPrekeyPair.keyPair, info)
```
