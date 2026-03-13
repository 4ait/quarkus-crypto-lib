package ru.code4a.quarkus.crypto.services

import jakarta.enterprise.context.ApplicationScoped
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import kotlinx.serialization.protobuf.ProtoNumber
import ru.code4a.quarkus.crypto.ciphers.CipherChaCha20Poly1305IVMSG
import ru.code4a.quarkus.crypto.generator.UniqueBytesGenerator
import ru.code4a.quarkus.crypto.utils.PKCS7Padding

@ApplicationScoped
/**
 * Context-bound encryption service that derives keys from a source string, a context value, and
 * an optional secret to isolate ciphertexts by purpose. This prevents accidental reuse of the
 * same key material across different data domains and supports stable decryptability as long as
 * the inputs remain unchanged.
 *
 * Example: use source "user_profile:v1:Z3VQk3..." and context "email" to encrypt email fields.
 */
class CipherContextual(
  private val keyDeriverContextual: KeyDeriverContextual,
  private val chaCha20Poly1305: CipherChaCha20Poly1305IVMSG,
  private val uniqueBytesGenerator: UniqueBytesGenerator
) {
  companion object {
    private const val BLOCK_SIZE = 32
    private const val VERSION_BYTE: Byte = 101
    private const val CONTEXT_SOURCE =
      "ru.foura.erpii.security.crypto.CipherContextual:1:NmE5MDQ5YWZlN2Y2NmQwYWQ3ZjJhOGM5N2JhNWQzNjgwZDg0ODY1YWVmYTZmODNjOTU4NzJhMjIwYmI3NTYyMgo="
  }

  /**
   * Encrypts binary data with a context-derived key.
   *
   * @param data plaintext bytes to encrypt; pass the exact bytes you will later decrypt.
   * @param source stable logical namespace for the data class; include a high-entropy component
   *   (at least 256 bits) and keep it identical for decryption. You can append a generated value
   *   from `openssl rand -base64 32` to the string to reach the required entropy, e.g.,
   *   `user_profile:v1:Z3VQk3...`.
   * @param context extra scope identifier encoded as UTF-8; it is combined with [source] to derive
   *   the key, so both must be identical for decryption. Use [context] to distinguish fields or
   *   records within the same [source] (e.g., "email", "device_key", "user:123"). Do not place
   *   private data here; use [secret] for sensitive material.
   * @param secret optional additional secret salt; use when you need a per-tenant or per-user
   *   secret that must match on decryption; leave empty to use only the master key.
   * @return ciphertext prefixed with a version byte; store/transmit as-is for later decryption.
   */
  fun encrypt(
    data: ByteArray,
    source: String, context: String,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    val packedContext = packContext(
      source = source,
      contextBytes = context.toByteArray(Charsets.UTF_8)
    )
    val derivedKey = keyDeriverContextual.deriveKey(
      lengthBytes = 32,
      source = CONTEXT_SOURCE,
      contextBytes = packedContext,
      secret = secret
    )
    val paddedData = PKCS7Padding.addPadding(data, BLOCK_SIZE)

    val encryptedData = chaCha20Poly1305.encryptWithIv(
      input = paddedData,
      key = derivedKey,
      iv = uniqueBytesGenerator.getNext(12)
    )
    return addVersionPrefix(encryptedData)
  }

  /**
   * Encrypts binary data with a context-derived key.
   *
   * @param data plaintext bytes to encrypt; pass the exact bytes you will later decrypt.
   * @param source stable logical namespace for the data class; include a high-entropy component
   *   (at least 256 bits) and keep it identical for decryption. You can append a generated value
   *   from `openssl rand -base64 32` to the string to reach the required entropy, e.g.,
   *   `user_profile:v1:Z3VQk3...`.
   * @param context pre-encoded context bytes; it is combined with [source] to derive the key, so
   *   the same bytes must be supplied for decryption. Use [context] to scope within the same
   *   [source] when the context is already binary. Do not place private data here; use [secret]
   *   for sensitive material.
   * @param secret optional additional secret salt; use when you need a per-tenant or per-user
   *   secret that must match on decryption; leave empty to use only the master key.
   * @return ciphertext prefixed with a version byte; store/transmit as-is for later decryption.
   */
  fun encrypt(
    data: ByteArray,
    source: String,
    context: ByteArray,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    val packedContext = packContext(source, context)
    val derivedKey = keyDeriverContextual.deriveKey(
      32,
      CONTEXT_SOURCE,
      packedContext,
      secret = secret
    )
    val paddedData = PKCS7Padding.addPadding(data, BLOCK_SIZE)

    val encryptedData = chaCha20Poly1305.encryptWithIv(
      input = paddedData,
      key = derivedKey,
      iv = uniqueBytesGenerator.getNext(12)
    )
    return addVersionPrefix(encryptedData)
  }

  /**
   * Decrypts data encrypted by [encrypt] using the same source/context/secret inputs.
   *
   * @param data ciphertext with the version prefix from [encrypt]; do not strip or modify it.
   * @param source the same stable namespace used during encryption, including the high-entropy
   *   component (at least 256 bits) such as a suffix from `openssl rand -base64 32`,
   *   e.g., `user_profile:v1:Z3VQk3...`.
   * @param context the same UTF-8 context string used during encryption; it is combined with
   *   [source] to derive the key, so changes to either will break decryption. Do not place private
   *   data here; use [secret] for sensitive material.
   * @param secret the same optional secret salt used during encryption.
   * @return decrypted plaintext bytes with PKCS7 padding removed.
   */
  fun decrypt(
    data: ByteArray,
    source: String,
    context: String,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    val packedContext = packContext(source, context.toByteArray(Charsets.UTF_8))
    val derivedKey = keyDeriverContextual.deriveKey(
      32,
      CONTEXT_SOURCE,
      packedContext,
      secret = secret
    )
    val dataWithoutVersion = stripVersionPrefix(data)
    val decryptedData = chaCha20Poly1305.decrypt(
      input = dataWithoutVersion,
      key = derivedKey
    )

    return PKCS7Padding.removePadding(decryptedData, BLOCK_SIZE)
  }

  /**
   * Decrypts data encrypted by [encrypt] using the same source/context/secret inputs.
   *
   * @param data ciphertext with the version prefix from [encrypt]; do not strip or modify it.
   * @param source the same stable namespace used during encryption, including the high-entropy
   *   component (at least 256 bits) such as a suffix from `openssl rand -base64 32`,
   *   e.g., `user_profile:v1:Z3VQk3...`.
   * @param context the same context bytes used during encryption; it is combined with [source]
   *   to derive the key, so changes to either will break decryption. Do not place private data
   *   here; use [secret] for sensitive material.
   * @param secret the same optional secret salt used during encryption.
   * @return decrypted plaintext bytes with PKCS7 padding removed.
   */
  fun decrypt(
    data: ByteArray,
    source: String,
    context: ByteArray,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    val packedContext = packContext(source, context)
    val derivedKey = keyDeriverContextual.deriveKey(
      32,
      CONTEXT_SOURCE,
      packedContext,
      secret = secret
    )
    val dataWithoutVersion = stripVersionPrefix(data)
    val decryptedData = chaCha20Poly1305.decrypt(
      input = dataWithoutVersion,
      key = derivedKey
    )

    return PKCS7Padding.removePadding(decryptedData, BLOCK_SIZE)
  }

  /**
   * Prepends the cipher version marker to allow future format changes.
   *
   * @param data raw ciphertext produced by the cipher.
   * @return ciphertext prefixed with the current version byte.
   */
  private fun addVersionPrefix(data: ByteArray): ByteArray {
    val prefixed = ByteArray(data.size + 1)
    prefixed[0] = VERSION_BYTE
    System.arraycopy(data, 0, prefixed, 1, data.size)
    return prefixed
  }

  /**
   * Validates and removes the version byte from an input ciphertext.
   *
   * @param data ciphertext that must contain the version prefix.
   * @return ciphertext without the version byte.
   */
  private fun stripVersionPrefix(data: ByteArray): ByteArray {
    require(data.isNotEmpty()) { "Empty cipher data" }
    val version = data[0]
    require(version == VERSION_BYTE) { "Unsupported cipher version: $version" }
    return data.copyOfRange(1, data.size)
  }

  /**
   * Packs the context into a stable protobuf structure for HKDF info binding.
   *
   * @param source logical namespace for the use-case; include a high-entropy component (at least
   *   256 bits) and keep stable across encrypt/decrypt, e.g., `user_profile:v1:Z3VQk3...`.
   * @param contextBytes raw context bytes; keep identical for matching decrypt.
   * @return encoded context bytes for key derivation.
   */
  @OptIn(ExperimentalSerializationApi::class)
  private fun packContext(
    source: String,
    contextBytes: ByteArray
  ): ByteArray {
    return ProtoBuf.encodeToByteArray(
      ContextContainer(
        source = source,
        contextBytes = contextBytes
      )
    )
  }

  @Serializable
  class ContextContainer(
    @ProtoNumber(1)
    val source: String,
    @ProtoNumber(2)
    val contextBytes: ByteArray
  )
}
