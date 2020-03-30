package com.ticeapp.androidx3dh

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.interfaces.KeyExchange
import com.goterl.lazycode.lazysodium.utils.Key
import com.goterl.lazycode.lazysodium.utils.KeyPair
import com.ticeapp.androidhkdf.deriveHKDFKey
import java.security.SignatureException

typealias Signature = ByteArray
typealias PrekeySigner = (Key) -> Signature
typealias PrekeySignatureVerifier = (Signature) -> Boolean

class X3DH {
    private val sodium = LazySodiumAndroid(SodiumAndroid()) as KeyExchange.Lazy

    class SignedPrekeyPair(val keyPair: KeyPair, val signature: ByteArray)
    class KeyAgreementInitiation(val sharedSecret: ByteArray, val associatedData: ByteArray, val ephemeralPublicKey: Key)
    private class DH(val ownKeyPair: KeyPair, val remotePublicKey: Key)

    private interface DHCalculator {
        fun calculateSessionKey(ownKeyPair: KeyPair, remotePublicKey: Key): ByteArray
    }

    private enum class Side : DHCalculator {
        INITIATING {
            override fun calculateSessionKey(ownKeyPair: KeyPair, remotePublicKey: Key): ByteArray = LazySodiumAndroid(SodiumAndroid()).cryptoKxClientSessionKeys(ownKeyPair.publicKey, ownKeyPair.secretKey, remotePublicKey).rx
        },
        RESPONDING {
            override fun calculateSessionKey(ownKeyPair: KeyPair, remotePublicKey: Key): ByteArray = LazySodiumAndroid(SodiumAndroid()).cryptoKxServerSessionKeys(ownKeyPair.publicKey, ownKeyPair.secretKey, remotePublicKey).tx
        }
    }

    fun generateIdentityKeyPair(): KeyPair = sodium.cryptoKxKeypair()

    fun generateSignedPrekeyPair(signer: PrekeySigner): SignedPrekeyPair {
        val keyPair = sodium.cryptoKxKeypair()
        val signature = signer(keyPair.publicKey)
        return SignedPrekeyPair(keyPair, signature)
    }

    fun generateOneTimePrekeyPairs(count: Int): Array<KeyPair> {
        return Array(count) { sodium.cryptoKxKeypair() }
    }

    fun initiateKeyAgreement(
        remotePublicIdentityKey: Key,
        remotePublicPrekey: Key,
        prekeySignature: Signature,
        remoteOneTimePublicPrekey: Key?,
        identityKeyPair: KeyPair,
        publicPrekey: Key,
        prekeySignatureVerifier: PrekeySignatureVerifier,
        info: String
    ): KeyAgreementInitiation {
        if (!prekeySignatureVerifier(prekeySignature)) {
            throw SignatureException()
        }

        val ephemeralKeyPair = sodium.cryptoKxKeypair()

        val dh1 = DH(identityKeyPair, remotePublicPrekey)
        val dh2 = DH(ephemeralKeyPair, remotePublicIdentityKey)
        val dh3 = DH(ephemeralKeyPair, remotePublicPrekey)
        val dh4 = remoteOneTimePublicPrekey?.let { DH(ephemeralKeyPair, it) }

        val sk = sharedSecret(dh1, dh2, dh3, dh4, Side.INITIATING, info)

        var ad = publicPrekey.asBytes.clone()
        ad += remotePublicIdentityKey.asBytes

        return KeyAgreementInitiation(sk, ad, ephemeralKeyPair.publicKey)
    }

    fun sharedSecretFromKeyAgreement(
        remotePublicIdentityKey: Key,
        remotePublicEphemeralKey: Key,
        usedOneTimePrekeyPair: KeyPair?,
        identityKeyPair: KeyPair,
        prekeyPair: KeyPair,
        info: String
    ): ByteArray {
        val dh1 = DH(prekeyPair, remotePublicIdentityKey)
        val dh2 = DH(identityKeyPair, remotePublicEphemeralKey)
        val dh3 = DH(prekeyPair, remotePublicEphemeralKey)
        val dh4 = usedOneTimePrekeyPair?.let { DH(it, remotePublicEphemeralKey) }

        return sharedSecret(dh1, dh2, dh3, dh4, Side.RESPONDING, info)
    }

    private fun sharedSecret(
        DH1: DH,
        DH2: DH,
        DH3: DH,
        DH4: DH?,
        side: Side,
        info: String
    ): ByteArray {
        var input = ByteArray(32) { Byte.MAX_VALUE }
        input += side.calculateSessionKey(DH1.ownKeyPair, DH1.remotePublicKey)
        input += side.calculateSessionKey(DH2.ownKeyPair, DH2.remotePublicKey)
        input += side.calculateSessionKey(DH3.ownKeyPair, DH3.remotePublicKey)

        if (DH4 != null) {
            input += side.calculateSessionKey(DH4.ownKeyPair, DH4.remotePublicKey)
        }

        val salt = ByteArray(32)

        return deriveHKDFKey(ikm = input, salt = salt, info = info, L = 32)
    }
}