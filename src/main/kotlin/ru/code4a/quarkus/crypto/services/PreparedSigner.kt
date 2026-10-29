package ru.code4a.quarkus.crypto.services

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Shares only immutable key material, never a mutable Mac instance between callers. */
class PreparedSigner internal constructor(key: ByteArray) {
  private val key = SecretKeySpec(key, HMAC_ALGORITHM)

  fun sign(data: ByteArray): ByteArray = byteArrayOf(ALGORITHM_ID) + computeTag(data)

  fun verify(data: ByteArray, signature: ByteArray): Boolean =
    supportsSignature(signature) && MessageDigest.isEqual(computeTag(data), signature.copyOfRange(1, signature.size))

  private fun computeTag(data: ByteArray): ByteArray = Mac.getInstance(HMAC_ALGORITHM).run {
    init(key)
    doFinal(data)
  }

  internal companion object {
    private const val HMAC_ALGORITHM = "HmacSHA3-256"
    private const val ALGORITHM_ID: Byte = 99
    fun supportsSignature(signature: ByteArray): Boolean = signature.isNotEmpty() && signature[0] == ALGORITHM_ID
  }
}
