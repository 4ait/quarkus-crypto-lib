package ru.code4a.quarkus.crypto.generator

/**
 * Generator of unique byte sequences.
 *
 * Guarantee: uniqueness within the lifecycle of the generator/state.
 * Does not guarantee cryptographic strength or additional entropy
 * when increasing [countBytes].
 */
interface UniqueBytesGenerator {
  /**
   * Returns a unique byte sequence with a length of at least 12 bytes.
   *
   * @param countBytes the minimum length in bytes must be at least 12
   */
  fun getNext(countBytes: Int): ByteArray
}
