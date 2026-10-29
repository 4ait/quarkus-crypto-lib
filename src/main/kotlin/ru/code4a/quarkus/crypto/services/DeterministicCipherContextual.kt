package ru.code4a.quarkus.crypto.services

import com.google.crypto.tink.subtle.AesSiv
import jakarta.enterprise.context.ApplicationScoped
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import kotlinx.serialization.protobuf.ProtoNumber

@ApplicationScoped
/**
 * Deterministic encryption service that derives keys from a source string, a context value, and
 * an optional secret to produce stable ciphertexts for identical inputs. This is useful for
 * comparisons or indexing because the same plaintext under the same context maps to the same
 * ciphertext without needing to store extra metadata.
 *
 * Example: use source "user_profile:v1:Z3VQk3..." and context "email" to produce repeatable values.
 */
class DeterministicCipherContextual(
  private val keyDeriverContextual: KeyDeriverContextual
) {
  companion object {
    private const val CONTEXT_SOURCE =
      "ru.foura.erpii.security.crypto.DeterministicCipherContextual:1:MWVmMzc5YjIxMjE1ZGIyMTUyYWE5ZmRkY2M2MDE0NDUyODQxMzA5M2Y1ODUxNmYyMWJkZDVhYjM4YWU4NTYzMQo="
    private const val KEY_CONTEXT_KEY_TYPE = "KEY"
    private const val AD_CONTEXT_KEY_TYPE = "AD"
  }

  /**
   * Deterministically encrypts data so the same inputs produce the same ciphertext.
   *
   * @param data plaintext bytes to encrypt; identical inputs will yield identical outputs.
   * @param source stable logical namespace for the data class; include a high-entropy component
   *   (at least 256 bits) and keep it identical for decryption. You can append a generated value
   *   from `openssl rand -base64 32` to the string to reach the required entropy, e.g.,
   *   `user_profile:v1:Z3VQk3...`.
   * @param context UTF-8 context string that scopes the key and associated data (AD); it is
   *   combined with [source], so both must be identical for decrypt. Use [context] to distinguish
   *   fields or records within the same [source]. Do not place private data here; use [secret] for
   *   sensitive material.
   * @param secret optional additional secret salt; use when you need a per-tenant or per-user
   *   secret that must match on decryption; leave empty to use only the master key.
   * @return ciphertext prefixed with a version byte; store/transmit as-is.
   */
  fun encryptDeterministic(
    data: ByteArray,
    source: String,
    context: String,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    return prepareDeterministicCipher(source, context, secret).encrypt(data)
  }

  /**
   * Prepares the key, associated data and AES-SIV once for a fixed scope.
   * The returned instance supports concurrent encryption and decryption. It belongs
   * to this service's master key and must be recreated when that key changes.
   * Existing methods retain their wire format without an unbounded context cache.
   */
  fun prepareDeterministicCipher(
    source: String,
    context: String,
    secret: ByteArray = ByteArray(0)
  ): PreparedDeterministicCipher {
    val contextBytes = context.toByteArray(Charsets.UTF_8)
    val key = keyDeriverContextual.deriveKey(
      64, CONTEXT_SOURCE,
      packContext(source, contextBytes, KEY_CONTEXT_KEY_TYPE), secret
    )
    val associatedData = keyDeriverContextual.deriveKey(
      32, CONTEXT_SOURCE,
      packContext(source, contextBytes, AD_CONTEXT_KEY_TYPE), secret
    )
    return PreparedDeterministicCipher(AesSiv(key), associatedData)
  }

  /**
   * Decrypts data encrypted by [encryptDeterministic] using the same inputs.
   *
   * @param data ciphertext with the version prefix from [encryptDeterministic].
   * @param source the same stable namespace used during encryption, including the high-entropy
   *   component (at least 256 bits) such as a suffix from `openssl rand -base64 32`,
   *   e.g., `user_profile:v1:Z3VQk3...`.
   * @param context the same UTF-8 context string used during encryption; it is combined with
   *   [source], so changes to either will break decryption. Do not place private data here; use
   *   [secret] for sensitive material.
   * @param secret the same optional secret salt used during encryption.
   * @return decrypted plaintext bytes.
   */
  fun decryptDeterministic(
    data: ByteArray,
    source: String,
    context: String,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    return prepareDeterministicCipher(source, context, secret).decrypt(data)
  }

  /**
   * Packs the context into a stable protobuf structure for HKDF info binding.
   *
   * @param source logical namespace for the use-case; include a high-entropy component (at least
   *   256 bits) and keep stable across encrypt/decrypt, e.g., `user_profile:v1:Z3VQk3...`.
   * @param contextBytes raw context bytes; keep identical for matching decrypt.
   * @param keyType separator used to derive independent key and AD values; do not change.
   * @return encoded context bytes for key derivation.
   */
  @OptIn(ExperimentalSerializationApi::class)
  private fun packContext(source: String, contextBytes: ByteArray, keyType: String): ByteArray {
    return ProtoBuf.encodeToByteArray(
      ContextContainer(
        source = source,
        contextBytes = contextBytes,
        keyType = keyType
      )
    )
  }

  @OptIn(ExperimentalSerializationApi::class)
  @Serializable
  class ContextContainer(
    @ProtoNumber(1)
    val source: String,
    @ProtoNumber(2)
    val contextBytes: ByteArray,
    @ProtoNumber(3)
    val keyType: String
  )
}
