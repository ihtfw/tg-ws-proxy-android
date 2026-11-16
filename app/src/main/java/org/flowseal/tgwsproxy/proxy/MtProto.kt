package org.flowseal.tgwsproxy.proxy

import org.flowseal.tgwsproxy.proxy.MtConst.DC_IDX_POS
import org.flowseal.tgwsproxy.proxy.MtConst.HANDSHAKE_LEN
import org.flowseal.tgwsproxy.proxy.MtConst.IV_LEN
import org.flowseal.tgwsproxy.proxy.MtConst.KEY_LEN
import org.flowseal.tgwsproxy.proxy.MtConst.PREKEY_LEN
import org.flowseal.tgwsproxy.proxy.MtConst.PROTO_TAG_POS
import org.flowseal.tgwsproxy.proxy.MtConst.SKIP_LEN

/** The MTProto proxy handshake (upstream tg_ws_proxy.py). */
object MtProto {

    class Handshake(
        val dc: Int,
        val isMedia: Boolean,
        val protoTag: ByteArray,
        /** Bytes 8..56 of the client's init: its prekey and IV. */
        val prekeyAndIv: ByteArray,
    )

    /**
     * Decrypts the client's 64-byte init with the proxy secret. Null when the secret is wrong
     * or the transport is not abridged, intermediate or padded intermediate.
     */
    fun tryHandshake(handshake: ByteArray, secret: ByteArray): Handshake? {
        if (handshake.size < HANDSHAKE_LEN) return null
        val prekeyAndIv = handshake.copyOfRange(SKIP_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN)
        val prekey = prekeyAndIv.copyOfRange(0, PREKEY_LEN)
        val iv = prekeyAndIv.copyOfRange(PREKEY_LEN, PREKEY_LEN + IV_LEN)
        val key = Bytes.sha256(prekey, secret)
        val decrypted = AesCtr(key, iv).update(handshake, 0, HANDSHAKE_LEN)

        val tag = decrypted.copyOfRange(PROTO_TAG_POS, PROTO_TAG_POS + 4)
        if (!tag.contentEquals(MtConst.PROTO_TAG_ABRIDGED) &&
            !tag.contentEquals(MtConst.PROTO_TAG_INTERMEDIATE) &&
            !tag.contentEquals(MtConst.PROTO_TAG_SECURE)
        ) return null

        val dcIdx = ((decrypted[DC_IDX_POS].toInt() and 0xFF) or
            (decrypted[DC_IDX_POS + 1].toInt() shl 8)).toShort().toInt()
        return Handshake(kotlin.math.abs(dcIdx), dcIdx < 0, tag, prekeyAndIv)
    }

    /** A fresh obfuscated init for the connection to Telegram, carrying [protoTag] and [dcIdx]. */
    fun generateRelayInit(protoTag: ByteArray, dcIdx: Int): ByteArray {
        val rnd: ByteArray
        while (true) {
            val r = Bytes.random(HANDSHAKE_LEN)
            if ((r[0].toInt() and 0xFF) in MtConst.RESERVED_FIRST_BYTES) continue
            if (MtConst.RESERVED_STARTS.any { Bytes.startsWith(r, it) }) continue
            if (Bytes.startsWith(r, MtConst.RESERVED_CONTINUE, 4)) continue
            rnd = r
            break
        }
        val encKey = rnd.copyOfRange(SKIP_LEN, SKIP_LEN + PREKEY_LEN)
        val encIv = rnd.copyOfRange(SKIP_LEN + PREKEY_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN)
        val encrypted = AesCtr(encKey, encIv).update(rnd)

        val tailPlain = ByteArray(8)
        System.arraycopy(protoTag, 0, tailPlain, 0, 4)
        tailPlain[4] = (dcIdx and 0xFF).toByte()
        tailPlain[5] = ((dcIdx shr 8) and 0xFF).toByte()
        System.arraycopy(Bytes.random(2), 0, tailPlain, 6, 2)

        val result = rnd.copyOf()
        for (i in 0 until 8) {
            val keystream = encrypted[56 + i].toInt() xor rnd[56 + i].toInt()
            result[PROTO_TAG_POS + i] = (tailPlain[i].toInt() xor keystream).toByte()
        }
        return result
    }

    /** The client-side keys come from the secret, the Telegram-side ones from [relayInit]. */
    fun buildCryptoCtx(clientPrekeyAndIv: ByteArray, secret: ByteArray, relayInit: ByteArray): CryptoCtx {
        val cltDecKey = Bytes.sha256(clientPrekeyAndIv.copyOfRange(0, PREKEY_LEN), secret)
        val cltDecIv = clientPrekeyAndIv.copyOfRange(PREKEY_LEN, PREKEY_LEN + IV_LEN)

        val cltEncPrekeyIv = Bytes.reversed(clientPrekeyAndIv)
        val cltEncKey = Bytes.sha256(cltEncPrekeyIv.copyOfRange(0, PREKEY_LEN), secret)
        val cltEncIv = cltEncPrekeyIv.copyOfRange(PREKEY_LEN, PREKEY_LEN + IV_LEN)

        val cltDec = AesCtr(cltDecKey, cltDecIv)
        val cltEnc = AesCtr(cltEncKey, cltEncIv)
        cltDec.update(MtConst.ZERO_64) // skip the client's init

        val relayEncKey = relayInit.copyOfRange(SKIP_LEN, SKIP_LEN + PREKEY_LEN)
        val relayEncIv = relayInit.copyOfRange(SKIP_LEN + PREKEY_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN)
        val relayDecPrekeyIv = Bytes.reversed(relayInit.copyOfRange(SKIP_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN))
        val relayDecKey = relayDecPrekeyIv.copyOfRange(0, KEY_LEN)
        val relayDecIv = relayDecPrekeyIv.copyOfRange(KEY_LEN, KEY_LEN + IV_LEN)

        val tgEnc = AesCtr(relayEncKey, relayEncIv)
        val tgDec = AesCtr(relayDecKey, relayDecIv)
        tgEnc.update(MtConst.ZERO_64) // skip our own init

        return CryptoCtx(cltDec, cltEnc, tgEnc, tgDec)
    }
}
