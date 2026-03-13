package ru.code4a.quarkus.crypto.ciphers

import jakarta.enterprise.context.ApplicationScoped

/**
 * CipherChaCha20Poly1305IVMSG provides utilities to perform encryption and decryption operations
 * using the ChaCha20-Poly1305 cipher algorithm. This class encapsulates functionality to handle
 * initialization vectors (IV) and salts securely, ensuring encryption integrity and confidentiality.
 */
@ApplicationScoped
class CipherChaCha20Poly1305IVMSG(
  private val cipherChaCha20Poly1305: CipherChaCha20Poly1305
) {
  companion object {
    private const val IV_LENGTH_BITS = 96
  }

  /**
   * Encrypts the provided input data using ChaCha20-Poly1305 cipher without adding salt.
   * The result contains IV concatenated with the encrypted data (input).
   *
   * @param input Input data to be encrypted as ByteArray.
   * @param key Encryption key as ByteArray.
   * @param iv Initialization vector (nonce) as ByteArray.
   * @return ByteArray containing concatenation of IV and encrypted input.
   */
  fun encryptWithIv(
    input: ByteArray,
    key: ByteArray,
    iv: ByteArray
  ): ByteArray {
    return iv +
      cipherChaCha20Poly1305.encrypt(
        input,
        key,
        iv
      )
  }

  /**
   * Decrypts data that was encrypted using 'encryptWithIv' method WITHOUT salt.
   * Extracts IV from encrypted data to perform decryption.
   *
   * @param input Encrypted data containing IV followed by ciphertext.
   * @param key Encryption key as ByteArray.
   * @param ivLengthBits Length of IV used during encryption (in bits).
   * @return Original decrypted ByteArray without IV.
   */
  fun decrypt(
    input: ByteArray,
    key: ByteArray
  ): ByteArray {
    val encryptedData = input.copyOfRange(IV_LENGTH_BITS / 8, input.size)
    val iv = input.copyOfRange(0, IV_LENGTH_BITS / 8)

    val decryptedData =
      cipherChaCha20Poly1305.decrypt(
        encryptedData,
        key,
        iv
      )

    return decryptedData
  }
}
