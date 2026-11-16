package org.flowseal.tgwsproxy.proxy

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.interfaces.XECPrivateKey
import java.security.interfaces.XECPublicKey
import org.junit.Assert.assertEquals
import org.junit.Test

/** RFC 7748 test vectors, and agreement with the JVM's own X25519 (which Android has only from API 33). */
class X25519Test {

    private fun mul(k: String, u: String): String =
        Bytes.toHex(X25519.scalarMult(Bytes.fromHex(k), Bytes.fromHex(u)))

    @Test
    fun rfc7748Section52Vectors() {
        assertEquals(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            mul(
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            ),
        )
        // this u-coordinate has its top bit set, which X25519 must ignore
        assertEquals(
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            mul(
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            ),
        )
    }

    @Test
    fun rfc7748Section61DiffieHellman() {
        val a = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        val b = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        val pa = Bytes.toHex(X25519.publicKey(Bytes.fromHex(a)))
        val pb = Bytes.toHex(X25519.publicKey(Bytes.fromHex(b)))
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", pa)
        assertEquals("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", pb)
        val shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        assertEquals(shared, mul(a, pb))
        assertEquals(shared, mul(b, pa))
    }

    @Test
    fun rfc7748Section52Iterations() {
        var k = ByteArray(32).also { it[0] = 9 }
        var u = k.copyOf()
        for (i in 1..1000) {
            val next = X25519.scalarMult(k, u)
            u = k
            k = next
            if (i == 1) assertEquals("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", Bytes.toHex(k))
        }
        assertEquals("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", Bytes.toHex(k))
    }

    @Test
    fun agreesWithJcaX25519() {
        val gen = KeyPairGenerator.getInstance("X25519")
        repeat(20) {
            val kp = gen.generateKeyPair()
            val scalar = (kp.private as XECPrivateKey).scalar.get()
            val u = (kp.public as XECPublicKey).u
            val ours = X25519.publicKey(scalar)
            assertEquals(u, BigInteger(1, Bytes.reversed(ours)))
        }
    }

    @Test
    fun publicKeysAreBelow2To255() {
        repeat(50) {
            val pub = X25519.publicKey(X25519.generatePrivateKey())
            assertEquals(32, pub.size)
            assertEquals(0, pub[31].toInt() and 0x80)
        }
    }
}
