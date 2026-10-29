package ru.code4a.quarkus.crypto.services

import com.google.crypto.tink.DeterministicAead

/**
 * A prepared scope using the existing DeterministicCipherContextual wire format.
 * Keys and associated data remain private, and every operation returns an independent
 * result. The Tink primitive is shared without serializing all operations on a lock.
 */
class PreparedDeterministicCipher internal constructor(
  private val cipher: DeterministicAead,
  associatedData: ByteArray
) {
  private val associatedData = associatedData.copyOf()

  fun encrypt(data: ByteArray): ByteArray =
    byteArrayOf(VERSION_BYTE) + cipher.encryptDeterministically(data, associatedData)

  fun decrypt(data: ByteArray): ByteArray {
    require(data.isNotEmpty()) { "Empty cipher data" }
    val version = data[0]
    require(version == VERSION_BYTE) { "Unsupported cipher version: $version" }
    return cipher.decryptDeterministically(data.copyOfRange(1, data.size), associatedData)
  }

  private companion object {
    const val VERSION_BYTE: Byte = 100
  }
}
