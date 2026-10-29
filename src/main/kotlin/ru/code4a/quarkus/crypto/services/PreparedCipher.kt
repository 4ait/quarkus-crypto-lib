package ru.code4a.quarkus.crypto.services

import ru.code4a.quarkus.crypto.ciphers.CipherChaCha20Poly1305IVMSG
import ru.code4a.quarkus.crypto.generator.UniqueBytesGenerator
import ru.code4a.quarkus.crypto.utils.PKCS7Padding

/** A fixed scope with the original padding, nonce envelope and authentication format. */
class PreparedCipher internal constructor(
  key: ByteArray,
  private val cipher: CipherChaCha20Poly1305IVMSG,
  private val nonces: UniqueBytesGenerator
) {
  private val key = key.copyOf()

  fun encrypt(data: ByteArray): ByteArray = byteArrayOf(VERSION_BYTE) + cipher.encryptWithIv(
    PKCS7Padding.addPadding(data, BLOCK_SIZE), key, nonces.getNext(12)
  )

  fun decrypt(data: ByteArray): ByteArray {
    require(data.isNotEmpty()) { "Empty cipher data" }
    val version = data[0]
    require(version == VERSION_BYTE) { "Unsupported cipher version: $version" }
    return PKCS7Padding.removePadding(cipher.decrypt(data.copyOfRange(1, data.size), key), BLOCK_SIZE)
  }

  private companion object {
    const val BLOCK_SIZE = 32
    const val VERSION_BYTE: Byte = 101
  }
}
