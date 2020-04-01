package com.ticeapp.androidx3dhapp

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.interfaces.KeyExchange
import com.goterl.lazycode.lazysodium.utils.Key
import com.goterl.lazycode.lazysodium.utils.KeyPair
import com.ticeapp.androidx3dh.Signature
import com.ticeapp.androidx3dh.X3DH
import com.ticeapp.androidx3dh.X3DH.*
import java.lang.Exception
import java.security.SignatureException
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.json.*

class MainActivity : AppCompatActivity() {

    @ImplicitReflectionSerializer
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        testLibrary()
        testGenerateKeyStore()
        testGenerateInitiateKeyAgreement()
        testSharedSecretFromKeyAgreement()
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

    @OptIn(UnstableDefault::class)
    @ImplicitReflectionSerializer
    private fun testGenerateKeyStore() {
        val x3dh = X3DH()

        val identityKeyPair = x3dh.generateIdentityKeyPair()
        val signedPrekeyPair = x3dh.generateSignedPrekeyPair { ByteArray(0) }
        val oneTimePrekeyPair = x3dh.generateOneTimePrekeyPairs(1).first()

        val keyStorage = KeyStorage(identityKeyPair, signedPrekeyPair, oneTimePrekeyPair)
        val keyStorageString = Json.stringify(KeyStorageSerializer, keyStorage)

        println(keyStorageString)
    }

    private fun testGenerateInitiateKeyAgreement() {
        val ownKeyStoreString = """{"identityKeyPair":{"secretKey":"9926D26B8BC13472895016509EE6C425632CE2CD1C0BD80E24A0C68BD8965608","publicKey":"302EF301F6F1D7E474AE8C2CD80206EBB908980FBE22EBCAFFBB84C72FD69C05"},"signedPrekeyPair":{"keyPair":{"secretKey":"214C325921FED88CE3E36BD0BA6D94CD0D700D6A0AA6294E43A905FB770D7785","publicKey":"712274556879A740466B53248F1F38969D3C1B4DB2E5D94E5DC258AB569D3D24"},"signature":""},"oneTimePrekeyPair":{"secretKey":"3E44705FD06B2751F2EC5CD51058A3577B463564BBAF080AA18A291B9D319F42","publicKey":"D3023D9013060F1D2552DA963DBBE9B92036854F12A4CEC6AA3DCC153BDE3567"}}"""
        val otherKeyStoreString = """{"identityKeyPair":{"secretKey":"050b410451c4b6749541770f1840bc814767cd0af6592b5347bd9174928d7756","publicKey":"17635f23fcb31ecc8ac0ebb367d789ae9b453966af2b1ee1d1496934fddfb921"},"signedPrekeyPair":{"keyPair":{"secretKey":"e7e87b55aaea39e89f72a978471fc430a483c9a5556fbd7149e8a72d83920912","publicKey":"ba6be55f8b53d09d5e60769d7452312bcb8c52b7bc8214c94a0457d124c9f422"},"signature":""},"oneTimePrekeyPair":{"secretKey":"507e596184c26bb576b21fd7111f386d3d1942557833923a81653be197213932","publicKey":"877389365a313af198c7fca84518e0a6ca7b4c0317709755f6646779af374262"}}"""

        val ownKeyStore = Json.parse(KeyStorageSerializer, ownKeyStoreString)
        val otherKeyStore = Json.parse(KeyStorageSerializer, otherKeyStoreString)

        val x3dh = X3DH()
        val keyAgrement = x3dh.initiateKeyAgreement(otherKeyStore.identityKeyPair.publicKey, otherKeyStore.signedPrekeyPair.keyPair.publicKey, otherKeyStore.signedPrekeyPair.signature, otherKeyStore.oneTimePrekeyPair.publicKey, ownKeyStore.identityKeyPair, ownKeyStore.signedPrekeyPair.keyPair.publicKey, { true }, "Info")

        val keyAgrementString = Json.stringify(KeyAgreementInitiationSerializer, keyAgrement)
        println(keyAgrementString)
    }

    private fun testSharedSecretFromKeyAgreement() {
        val ownKeyStoreString = """{"identityKeyPair":{"secretKey":"9926D26B8BC13472895016509EE6C425632CE2CD1C0BD80E24A0C68BD8965608","publicKey":"302EF301F6F1D7E474AE8C2CD80206EBB908980FBE22EBCAFFBB84C72FD69C05"},"signedPrekeyPair":{"keyPair":{"secretKey":"214C325921FED88CE3E36BD0BA6D94CD0D700D6A0AA6294E43A905FB770D7785","publicKey":"712274556879A740466B53248F1F38969D3C1B4DB2E5D94E5DC258AB569D3D24"},"signature":""},"oneTimePrekeyPair":{"secretKey":"3E44705FD06B2751F2EC5CD51058A3577B463564BBAF080AA18A291B9D319F42","publicKey":"D3023D9013060F1D2552DA963DBBE9B92036854F12A4CEC6AA3DCC153BDE3567"}}"""
        val otherKeyStoreString = """{"identityKeyPair":{"secretKey":"050b410451c4b6749541770f1840bc814767cd0af6592b5347bd9174928d7756","publicKey":"17635f23fcb31ecc8ac0ebb367d789ae9b453966af2b1ee1d1496934fddfb921"},"signedPrekeyPair":{"keyPair":{"secretKey":"e7e87b55aaea39e89f72a978471fc430a483c9a5556fbd7149e8a72d83920912","publicKey":"ba6be55f8b53d09d5e60769d7452312bcb8c52b7bc8214c94a0457d124c9f422"},"signature":""},"oneTimePrekeyPair":{"secretKey":"507e596184c26bb576b21fd7111f386d3d1942557833923a81653be197213932","publicKey":"877389365a313af198c7fca84518e0a6ca7b4c0317709755f6646779af374262"}}"""
        val keyAgreementInitiationString = """{"sharedSecret":"66e083e85cb77783a9a17a1229e3993a707133562e43867af8fa2f705d2e5ddf","associatedData":"ba6be55f8b53d09d5e60769d7452312bcb8c52b7bc8214c94a0457d124c9f422302ef301f6f1d7e474ae8c2cd80206ebb908980fbe22ebcaffbb84c72fd69c05","ephemeralPublicKey":"0959af58803b1b72816bcc4dc81fe69bb14e3b78d64105e6611a28727eb17a7a"}"""

        val ownKeyStore = Json.parse(KeyStorageSerializer, ownKeyStoreString)
        val otherKeyStore = Json.parse(KeyStorageSerializer, otherKeyStoreString)
        val keyAgreementInitiation = Json.parse(KeyAgreementInitiationSerializer, keyAgreementInitiationString)

        val x3dh = X3DH()
        val sharedSecret = x3dh.sharedSecretFromKeyAgreement(otherKeyStore.identityKeyPair.publicKey, keyAgreementInitiation.ephemeralPublicKey, ownKeyStore.oneTimePrekeyPair, ownKeyStore.identityKeyPair, ownKeyStore.signedPrekeyPair.keyPair, "Info")

        if (!sharedSecret.contentEquals(keyAgreementInitiation.sharedSecret)) {
            throw Exception("Test failed")
        }
    }

    object ByteArraySerializer: SerializationStrategy<ByteArray>, DeserializationStrategy<ByteArray> {
        override val descriptor: SerialDescriptor = PrimitiveDescriptor("ByteArrayHex", PrimitiveKind.STRING)
        override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(LazySodiumAndroid(SodiumAndroid()).sodiumBin2Hex(value))
        override fun deserialize(decoder: Decoder): ByteArray = LazySodiumAndroid(SodiumAndroid()).sodiumHex2Bin(decoder.decodeString())
        override fun patch(decoder: Decoder, old: ByteArray): ByteArray = deserialize(decoder)
    }

    object KeySerializer: SerializationStrategy<Key>, DeserializationStrategy<Key> {
        override val descriptor: SerialDescriptor = PrimitiveDescriptor("Key", PrimitiveKind.STRING)
        override fun serialize(encoder: Encoder, value: Key) {
            encoder.encodeString(value.asHexString)
        }

        override fun deserialize(decoder: Decoder): Key = Key.fromHexString(decoder.decodeString())
        override fun patch(decoder: Decoder, old: Key): Key = deserialize(decoder)
    }

    object SignatureSerializer: SerializationStrategy<Signature>, DeserializationStrategy<Signature> {
        override val descriptor: SerialDescriptor = PrimitiveDescriptor("Signature", PrimitiveKind.STRING)
        override fun serialize(encoder: Encoder, value: Signature) = encoder.encodeString(LazySodiumAndroid(SodiumAndroid()).sodiumBin2Hex(value))
        override fun deserialize(decoder: Decoder): Signature = LazySodiumAndroid(SodiumAndroid()).sodiumHex2Bin(decoder.decodeString())
        override fun patch(decoder: Decoder, old: Signature): Signature = deserialize(decoder)
    }

    object KeyPairSerializer: SerializationStrategy<KeyPair>, DeserializationStrategy<KeyPair> {
        @ImplicitReflectionSerializer
        override val descriptor: SerialDescriptor = SerialDescriptor("KeyPair") {
            element<String>("secretKey")
            element<String>("publicKey")
        }
        @ImplicitReflectionSerializer
        override fun serialize(encoder: Encoder, value: KeyPair) {
            val composite = encoder.beginStructure(descriptor)
            composite.encodeSerializableElement(descriptor, 0, KeySerializer, value.secretKey)
            composite.encodeSerializableElement(descriptor, 1, KeySerializer, value.publicKey)
            composite.endStructure(descriptor)
        }

        @ImplicitReflectionSerializer
        override fun deserialize(decoder: Decoder): KeyPair {
            val composite = decoder.beginStructure(descriptor)
            var index = composite.decodeElementIndex(descriptor)
            val secretKey = composite.decodeSerializableElement(descriptor, 0, KeySerializer)
            index = composite.decodeElementIndex(descriptor)
            val publicKey = composite.decodeSerializableElement(descriptor, 1, KeySerializer)
            index = composite.decodeElementIndex(descriptor)
            composite.endStructure(descriptor)

            return KeyPair(publicKey, secretKey)
        }
        @ImplicitReflectionSerializer
        override fun patch(decoder: Decoder, old: KeyPair): KeyPair = deserialize(decoder)
    }

    object SignedPrekeyPairSerializer: SerializationStrategy<SignedPrekeyPair>, DeserializationStrategy<SignedPrekeyPair> {
        @ImplicitReflectionSerializer
        override val descriptor: SerialDescriptor = SerialDescriptor("SignedPrekeyPair") {
            element<String>("keyPair")
            element<String>("signature")
        }
        @ImplicitReflectionSerializer
        override fun serialize(encoder: Encoder, value: SignedPrekeyPair) {
            val composite = encoder.beginStructure(descriptor)
            composite.encodeSerializableElement(descriptor, 0, KeyPairSerializer, value.keyPair)
            composite.encodeSerializableElement(descriptor, 1, SignatureSerializer, value.signature)
            composite.endStructure(descriptor)
        }
        @ImplicitReflectionSerializer
        override fun deserialize(decoder: Decoder): SignedPrekeyPair {
            val composite = decoder.beginStructure(descriptor)
            var index = composite.decodeElementIndex(descriptor)
            val keyPair = composite.decodeSerializableElement(descriptor, 0, KeyPairSerializer)
            index = composite.decodeElementIndex(descriptor)
            val signature = composite.decodeSerializableElement(descriptor, 1, SignatureSerializer)
            index = composite.decodeElementIndex(descriptor)
            composite.endStructure(descriptor)

            return SignedPrekeyPair(keyPair, signature)
        }
        @ImplicitReflectionSerializer
        override fun patch(decoder: Decoder, old: SignedPrekeyPair): SignedPrekeyPair = deserialize(decoder)
    }

    object KeyStorageSerializer: SerializationStrategy<KeyStorage>, DeserializationStrategy<KeyStorage> {
        @ImplicitReflectionSerializer
        override val descriptor: SerialDescriptor = SerialDescriptor("KeyStorage") {
            element<String>("identityKeyPair")
            element<String>("signedPrekeyPair")
            element<String>("oneTimePrekeyPair")
        }
        @ImplicitReflectionSerializer
        override fun serialize(encoder: Encoder, value: KeyStorage) {
            val composite = encoder.beginStructure(descriptor)
            composite.encodeSerializableElement(descriptor, 0, KeyPairSerializer, value.identityKeyPair)
            composite.encodeSerializableElement(descriptor, 1, SignedPrekeyPairSerializer, value.signedPrekeyPair)
            composite.encodeSerializableElement(descriptor, 2, KeyPairSerializer, value.oneTimePrekeyPair)
            composite.endStructure(descriptor)
        }

        @ImplicitReflectionSerializer
        override fun deserialize(decoder: Decoder): KeyStorage {
            val composite = decoder.beginStructure(descriptor)
            var index = composite.decodeElementIndex(descriptor)
            val identityKeyPair = composite.decodeSerializableElement(descriptor, 0, KeyPairSerializer)
            index = composite.decodeElementIndex(descriptor)
            val signedPrekeyPair = composite.decodeSerializableElement(descriptor, 1, SignedPrekeyPairSerializer)
            index = composite.decodeElementIndex(descriptor)
            val oneTimePrekeyPair = composite.decodeSerializableElement(descriptor, 2, KeyPairSerializer)
            index = composite.decodeElementIndex(descriptor)
            composite.endStructure(descriptor)

            return KeyStorage(identityKeyPair, signedPrekeyPair, oneTimePrekeyPair)
        }

        @ImplicitReflectionSerializer
        override fun patch(decoder: Decoder, old: KeyStorage): KeyStorage = deserialize(decoder)
    }

    data class KeyStorage(val identityKeyPair: KeyPair, val signedPrekeyPair: SignedPrekeyPair, val oneTimePrekeyPair: KeyPair)

    object KeyAgreementInitiationSerializer: SerializationStrategy<KeyAgreementInitiation>, DeserializationStrategy<KeyAgreementInitiation> {
        @ImplicitReflectionSerializer
        override val descriptor: SerialDescriptor = SerialDescriptor("KeyAgreementInitiation") {
            element<String>("sharedSecret")
            element<String>("associatedData")
            element<String>("ephemeralPublicKey")
        }
        @ImplicitReflectionSerializer
        override fun serialize(encoder: Encoder, value: KeyAgreementInitiation) {
            val composite = encoder.beginStructure(descriptor)
            composite.encodeSerializableElement(descriptor, 0, ByteArraySerializer, value.sharedSecret)
            composite.encodeSerializableElement(descriptor, 1, ByteArraySerializer, value.associatedData)
            composite.encodeSerializableElement(descriptor, 2, KeySerializer, value.ephemeralPublicKey)
            composite.endStructure(descriptor)
        }

        @ImplicitReflectionSerializer
        override fun deserialize(decoder: Decoder): KeyAgreementInitiation {
            val composite = decoder.beginStructure(descriptor)
            var index = composite.decodeElementIndex(descriptor)
            val sharedSecret = composite.decodeSerializableElement(descriptor, 0, ByteArraySerializer)
            index = composite.decodeElementIndex(descriptor)
            val associatedData = composite.decodeSerializableElement(descriptor, 1, ByteArraySerializer)
            index = composite.decodeElementIndex(descriptor)
            val ephemeralPublicKey = composite.decodeSerializableElement(descriptor, 2, KeySerializer)
            index = composite.decodeElementIndex(descriptor)
            composite.endStructure(descriptor)

            return KeyAgreementInitiation(sharedSecret, associatedData, ephemeralPublicKey)
        }

        @ImplicitReflectionSerializer
        override fun patch(decoder: Decoder, old: KeyAgreementInitiation): KeyAgreementInitiation = deserialize(decoder)
    }
}
