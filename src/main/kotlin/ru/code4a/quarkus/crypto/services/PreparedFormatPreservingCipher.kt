package ru.code4a.quarkus.crypto.services

import javax.crypto.SecretKey
import ru.code4a.quarkus.crypto.ciphers.FF1Cipher

/** Retains a fixed key, tweak and radix; each FF1 operation uses a fresh JCA cipher. */
class PreparedFormatPreservingCipher internal constructor(
  private val key: SecretKey,
  tweak: ByteArray,
  private val radix: Int,
  private val cipher: FF1Cipher
) {
  private val tweak = tweak.copyOf()

  fun encrypt(data: ByteArray): ByteArray {
    validateFormatPreservingData(data, radix)
    return cipher.encrypt(data, key, tweak, radix)
  }

  fun decrypt(data: ByteArray): ByteArray {
    validateFormatPreservingData(data, radix)
    return cipher.decrypt(data, key, tweak, radix)
  }
}

internal fun validateFormatPreservingData(data: ByteArray, radix: Int) {
  require(data.isNotEmpty()) { "Empty FPE data" }
  require(radix in 2..65536) { "Radix must be in range [2, 65536]" }

  if (radix <= 256) {
    // 1 byte per digit: digit = 0..255
    data.forEach { b ->
      val digit = b.toInt() and 0xFF
      require(digit < radix) { "Digit out of range: $digit for radix $radix" }
    }
  } else {
    // Wide radix: 2 bytes per digit, big-endian: digit = 0..65535
    require(data.size % 2 == 0) {
      "Data must be an even number of bytes for radix > 256 (wide radix)"
    }

    var i = 0
    while (i < data.size) {
      val hi = data[i].toInt() and 0xFF
      val lo = data[i + 1].toInt() and 0xFF
      val digit = (hi shl 8) or lo  // 0..65535
      require(digit < radix) { "Digit out of range: $digit for radix $radix" }
      i += 2
    }
  }
}
