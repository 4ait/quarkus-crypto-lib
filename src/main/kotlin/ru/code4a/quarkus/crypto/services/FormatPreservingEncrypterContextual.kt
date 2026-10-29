package ru.code4a.quarkus.crypto.services

import jakarta.enterprise.context.ApplicationScoped
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import kotlinx.serialization.protobuf.ProtoNumber
import ru.code4a.quarkus.crypto.ciphers.FF1Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

@ApplicationScoped
/**
 * Format-preserving encryption service that derives key material from a source string, a context
 * value, and an optional secret while keeping the input digit format intact. This is useful when
 * encrypted output must keep the same length and digit alphabet, such as PINs or numeric tokens.
 *
 * Example: use source "rdp_pin:v1:Z3VQk3..." and context "pin" to encrypt a PIN without changing
 * its digit count.
 */
class FormatPreservingEncrypterContextual(
  private val keyDeriverContextual: KeyDeriverContextual,
  private val ff1Cipher: FF1Cipher
) {
  companion object {
    private const val CONTEXT_SOURCE =
      "ru.foura.erpii.security.crypto.FormatPreservingEncrypter:1:NmNjMDQyMmUyNDllMzBhNGY4ZjQwZjEzMjliYTI5MmJmN2RlZjBmZGI1NDgxMGMwNDRlZTFkYjRhYjFmNTUxMw="
    private const val KEY_CONTEXT_KEY_TYPE = "KEY"
    private const val TWEAK_CONTEXT_KEY_TYPE = "TWEAK"
  }

  /**
   * Encrypts data with format-preserving encryption using a UTF-8 context string.
   *
   * @param data digits encoded as bytes; for radix <= 256 each byte is one digit, for radix > 256
   *   data must be big-endian 2-byte digits; keep the same encoding for decrypt.
   * @param source stable logical namespace for the data class; include a high-entropy component
   *   (at least 256 bits) and keep it identical for decryption. You can append a generated value
   *   from `openssl rand -base64 32` to the string to reach the required entropy, e.g.,
   *   `user_profile:v1:Z3VQk3...`.
   * @param context UTF-8 context string that scopes key and tweak derivation; it is combined with
   *   [source], so both must be identical for decryption. Use [context] to distinguish fields or
   *   records within the same [source]. Do not place private data here; use [secret] for sensitive
   *   material.
   * @param radix base of the digits; must be in [2, 65536] and match the data encoding rules.
   * @param secret optional additional secret salt; use when you need a per-tenant or per-user
   *   secret that must match on decryption; leave empty to use only the master key.
   * @return ciphertext preserving the digit format and length of the input.
   */
  fun encrypt(
    data: ByteArray,
    source: String,
    context: String,
    radix: Int,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    val contextBytes = context.toByteArray(Charsets.UTF_8)
    return encrypt(data, source, contextBytes, radix, secret = secret)
  }

  /**
   * Encrypts data with format-preserving encryption using raw context bytes.
   *
   * @param data digits encoded as bytes; for radix <= 256 each byte is one digit, for radix > 256
   *   data must be big-endian 2-byte digits; keep the same encoding for decrypt.
   * @param source stable logical namespace for the data class; include a high-entropy component
   *   (at least 256 bits) and keep it identical for decryption. You can append a generated value
   *   from `openssl rand -base64 32` to the string to reach the required entropy, e.g.,
   *   `user_profile:v1:Z3VQk3...`.
   * @param context pre-encoded context bytes; it is combined with [source], so the same bytes must
   *   be supplied for decryption. Use [context] to scope within the same [source] when binary. Do
   *   not place private data here; use [secret] for sensitive material.
   * @param radix base of the digits; must be in [2, 65536] and match the data encoding rules.
   * @param secret optional additional secret salt; use when you need a per-tenant or per-user
   *   secret that must match on decryption; leave empty to use only the master key.
   * @return ciphertext preserving the digit format and length of the input.
   */
  fun encrypt(
    data: ByteArray,
    source: String,
    context: ByteArray,
    radix: Int,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    validateFormatPreservingData(data, radix)
    return prepareFormatPreservingCipher(source, context, radix, secret).encrypt(data)
  }

  /**
   * Decrypts data encrypted by [encrypt] using a UTF-8 context string.
   *
   * @param data ciphertext digits in the same encoding used for encryption.
   * @param source the same stable namespace used during encryption, including the high-entropy
   *   component (at least 256 bits) such as a suffix from `openssl rand -base64 32`,
   *   e.g., `user_profile:v1:Z3VQk3...`.
   * @param context the same UTF-8 context string used during encryption; it is combined with
   *   [source], so changes to either will break decryption. Do not place private data here; use
   *   [secret] for sensitive material.
   * @param radix base of the digits; must match the value used for encryption.
   * @param secret the same optional secret salt used during encryption.
   * @return plaintext digits with the same format and length as the input.
   */
  fun decrypt(
    data: ByteArray, source: String, context: String, radix: Int,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    val contextBytes = context.toByteArray(Charsets.UTF_8)
    return decrypt(data, source, contextBytes, radix, secret = secret)
  }

  /**
   * Decrypts data encrypted by [encrypt] using raw context bytes.
   *
   * @param data ciphertext digits in the same encoding used for encryption.
   * @param source the same stable namespace used during encryption, including the high-entropy
   *   component (at least 256 bits) such as a suffix from `openssl rand -base64 32`,
   *   e.g., `user_profile:v1:Z3VQk3...`.
   * @param context the same context bytes used during encryption; it is combined with [source],
   *   so changes to either will break decryption. Do not place private data here; use [secret] for
   *   sensitive material.
   * @param radix base of the digits; must match the value used for encryption.
   * @param secret the same optional secret salt used during encryption.
   * @return plaintext digits with the same format and length as the input.
   */
  fun decrypt(
    data: ByteArray, source: String, context: ByteArray, radix: Int,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    validateFormatPreservingData(data, radix)
    return prepareFormatPreservingCipher(source, context, radix, secret).decrypt(data)
  }

  /** Prepares the FF1 key and tweak for a fixed scope and radix. */
  fun prepareFormatPreservingCipher(
    source: String, context: String, radix: Int, secret: ByteArray = ByteArray(0)
  ): PreparedFormatPreservingCipher =
    prepareFormatPreservingCipher(source, context.toByteArray(Charsets.UTF_8), radix, secret)

  fun prepareFormatPreservingCipher(
    source: String, context: ByteArray, radix: Int, secret: ByteArray = ByteArray(0)
  ): PreparedFormatPreservingCipher {
    require(radix in 2..65536) { "Radix must be in range [2, 65536]" }
    return PreparedFormatPreservingCipher(
      deriveKey(source, context, secret), deriveTweak(source, context, secret), radix, ff1Cipher
    )
  }

  /**
   * Derives the FF1 AES key scoped to the given context.
   *
   * @param source stable logical namespace for the data class; include a high-entropy component
   *   (at least 256 bits) and keep stable across encrypt/decrypt, e.g., `user_profile:v1:Z3VQk3...`.
   * @param contextBytes raw context bytes; keep identical for matching decrypt.
   * @param secret optional additional secret salt; keep identical for matching decrypt.
   * @return AES key to be used by the FF1 cipher.
   */
  private fun deriveKey(
    source: String,
    contextBytes: ByteArray,
    secret: ByteArray = ByteArray(0)
  ): SecretKey {
    val keyBytes = keyDeriverContextual.deriveKey(
      32,
      CONTEXT_SOURCE,
      packContext(
        source = source,
        contextBytes = contextBytes,
        keyType = KEY_CONTEXT_KEY_TYPE
      ),
      secret = secret
    )
    return SecretKeySpec(keyBytes, "AES")
  }

  /**
   * Derives the FF1 tweak scoped to the given context.
   *
   * @param source stable logical namespace for the data class; include a high-entropy component
   *   (at least 256 bits) and keep stable across encrypt/decrypt, e.g., `user_profile:v1:Z3VQk3...`.
   * @param contextBytes raw context bytes; keep identical for matching decrypt.
   * @param secret optional additional secret salt; keep identical for matching decrypt.
   * @return tweak bytes used by the FF1 cipher.
   */
  private fun deriveTweak(
    source: String,
    contextBytes: ByteArray,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    val tweakBytes = keyDeriverContextual.deriveKey(
      16,
      CONTEXT_SOURCE,
      packContext(
        source = source,
        contextBytes = contextBytes,
        keyType = TWEAK_CONTEXT_KEY_TYPE
      ),
      secret = secret
    )
    return tweakBytes
  }

  /**
   * Packs the context into a stable protobuf structure for HKDF info binding.
   *
   * @param source logical namespace for the use-case; include a high-entropy component (at least
   *   256 bits) and keep stable across encrypt/decrypt, e.g., `user_profile:v1:Z3VQk3...`.
   * @param contextBytes raw context bytes; keep identical for matching decrypt.
   * @param keyType separator used to derive independent key and tweak values; do not change.
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
