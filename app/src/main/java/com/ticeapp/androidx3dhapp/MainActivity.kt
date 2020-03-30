package com.ticeapp.androidx3dhapp

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.ticeapp.androidx3dh.X3DH
import java.lang.Exception
import java.security.SignatureException

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        testLibrary()
    }

    private fun testLibrary() {
        testKeyAgreementWithOneTimePrekey()
        testKeyAgreementWithoutOneTimePrekey()
        testKeyAgreementInvalidSignature()
    }

    private fun testKeyAgreementWithOneTimePrekey() {
        val info = "testKeyAgreement"

        val bob = X3DH()
        val bobIdentityKeyPair = bob.generateIdentityKeyPair()
        val bobSignedPrekeyPair = bob.generateSignedPrekeyPair { ByteArray(0) }
        val bobOneTimePrekeyPairs = bob.generateOneTimePrekeyPairs(2)

        val alice = X3DH()
        val aliceIdentityKeyPair = alice.generateIdentityKeyPair()
        val aliceSignedPrekey = alice.generateSignedPrekeyPair { ByteArray(0) }

        // [Alice fetches bob's prekey bundle ...]

        val keyAgreementInitiation = alice.initiateKeyAgreement(bobIdentityKeyPair.publicKey, bobSignedPrekeyPair.keyPair.publicKey, bobSignedPrekeyPair.signature, bobOneTimePrekeyPairs.first().publicKey, aliceIdentityKeyPair, aliceSignedPrekey.keyPair.publicKey, { true }, info)

        // [Alice sends identity key, ephemeral key and used one-time prekey to bob ...]

        val sharedSecret = bob.sharedSecretFromKeyAgreement(aliceIdentityKeyPair.publicKey, keyAgreementInitiation.ephemeralPublicKey, bobOneTimePrekeyPairs.first(), bobIdentityKeyPair, bobSignedPrekeyPair.keyPair, info)
        if (!sharedSecret.contentEquals(keyAgreementInitiation.sharedSecret)) {
            throw Exception("Test failed")
        }
    }

    private fun testKeyAgreementWithoutOneTimePrekey() {
        val info = "testKeyAgreement"

        val bob = X3DH()
        val bobIdentityKeyPair = bob.generateIdentityKeyPair()
        val bobSignedPrekeyPair = bob.generateSignedPrekeyPair { ByteArray(0) }

        val alice = X3DH()
        val aliceIdentityKeyPair = alice.generateIdentityKeyPair()
        val aliceSignedPrekey = alice.generateSignedPrekeyPair { ByteArray(0) }

        // [Alice fetches bob's prekey bundle ...]

        val keyAgreementInitiation = alice.initiateKeyAgreement(bobIdentityKeyPair.publicKey, bobSignedPrekeyPair.keyPair.publicKey, bobSignedPrekeyPair.signature, null, aliceIdentityKeyPair, aliceSignedPrekey.keyPair.publicKey, { true }, info)

        // [Alice sends identity key, ephemeral key and used one-time prekey to bob ...]

        val sharedSecret = bob.sharedSecretFromKeyAgreement(aliceIdentityKeyPair.publicKey, keyAgreementInitiation.ephemeralPublicKey, null, bobIdentityKeyPair, bobSignedPrekeyPair.keyPair, info)

        if (!sharedSecret.contentEquals(keyAgreementInitiation.sharedSecret)) {
            throw Exception("Test failed")
        }
    }

    private fun testKeyAgreementInvalidSignature() {
        val info = "testKeyAgreement"

        val bob = X3DH()
        val bobIdentityKeyPair = bob.generateIdentityKeyPair()
        val bobSignedPrekeyPair = bob.generateSignedPrekeyPair { ByteArray(0) }
        val bobOneTimePrekeyPairs = bob.generateOneTimePrekeyPairs(2)

        val alice = X3DH()
        val aliceIdentityKeyPair = alice.generateIdentityKeyPair()
        val aliceSignedPrekey = alice.generateSignedPrekeyPair { ByteArray(0) }

        // [Alice fetches bob's prekey bundle ...]

        try {
            val keyAgreementInitiation = alice.initiateKeyAgreement(
                bobIdentityKeyPair.publicKey,
                bobSignedPrekeyPair.keyPair.publicKey,
                bobSignedPrekeyPair.signature,
                bobOneTimePrekeyPairs.first().publicKey,
                aliceIdentityKeyPair,
                aliceSignedPrekey.keyPair.publicKey,
                { false },
                info
            )
        } catch (e: SignatureException) {
            return
        }

        throw Exception("Test failed")
    }
}
