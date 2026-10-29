package ru.code4a.quarkus.crypto.services

import jakarta.enterprise.context.ApplicationScoped
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import kotlinx.serialization.protobuf.ProtoNumber

@ApplicationScoped
/**
 * Context-bound signing service that derives HMAC keys from a source string, a context value, and
 * an optional secret to sign and verify byte arrays. This allows signatures to be scoped to a
 * specific purpose so the same data can be signed differently in different domains.
 *
 * Example: use source "user_session:v1:Z3VQk3..." and context "access_token" to sign session data.
 */
class SignerContextual(
  private val keyDeriverContextual: KeyDeriverContextual
) {
  companion object {
    private const val CONTEXT_SOURCE =
      "ru.foura.erpii.security.crypto.SignatureContextual:1:NDlhYTVlMjAyMzU4ZGMzOTcxOWRjNThkMDVhNzQ1OTg2OWFjNzYyMzMyMDdkY2UwMmY3MWQwZjMwYzNkZTczNgo="
  }

  /**
   * Signs data with an HMAC derived from the given context.
   *
   * @param data bytes to sign; must be the exact bytes verified later.
   * @param source stable logical namespace for the data class; include a high-entropy component
   *   (at least 256 bits) and keep it identical for verification. You can append a generated value
   *   from `openssl rand -base64 32` to the string to reach the required entropy, e.g.,
   *   `user_session:v1:Z3VQk3...`.
   * @param context UTF-8 context string that scopes the signing key; it is combined with [source],
   *   so both must be identical for verification. Use [context] to distinguish fields or records
   *   within the same [source]. Do not place private data here; use [secret] for sensitive material.
   * @param secret optional additional secret salt; use when you need per-tenant or per-user
   *   scoping and keep identical for verification.
   * @return signature bytes prefixed with an algorithm id; store/transmit as-is for verification.
   */
  fun sign(
    data: ByteArray,
    source: String,
    context: String,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    return prepareSigner(source, context, secret).sign(data)
  }

  /**
   * Signs data with an HMAC derived from the given context bytes.
   *
   * @param data bytes to sign; must be the exact bytes verified later.
   * @param source stable logical namespace for the data class; include a high-entropy component
   *   (at least 256 bits) and keep it identical for verification. You can append a generated value
   *   from `openssl rand -base64 32` to the string to reach the required entropy, e.g.,
   *   `user_session:v1:Z3VQk3...`.
   * @param context pre-encoded context bytes; it is combined with [source], so the same bytes must
   *   be supplied for verification. Do not place private data here; use [secret] for sensitive
   *   material.
   * @param secret optional additional secret salt; use when you need per-tenant or per-user
   *   scoping and keep identical for verification.
   * @return signature bytes prefixed with an algorithm id; store/transmit as-is for verification.
   */
  fun sign(
    data: ByteArray,
    source: String,
    context: ByteArray,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    return prepareSigner(source, context, secret).sign(data)
  }

  /**
   * Verifies a signature produced by [sign] using a UTF-8 context string.
   *
   * @param data bytes that were originally signed; must be identical.
   * @param source the same stable namespace used during signing, including the high-entropy
   *   component (at least 256 bits) such as a suffix from `openssl rand -base64 32`,
   *   e.g., `user_session:v1:Z3VQk3...`.
   * @param context the same UTF-8 context string used during signing; it is combined with
   *   [source], so changes to either will break verification. Do not place private data here; use
   *   [secret] for sensitive material.
   * @param signature signature bytes with the algorithm id prefix from [sign].
   * @param secret the same optional secret salt used during signing.
   * @return true if the signature matches; false if the prefix is invalid or verification fails.
   */
  fun isMatchSignature(
    data: ByteArray,
    source: String,
    context: String,
    signature: ByteArray,
    secret: ByteArray = ByteArray(0)
  ): Boolean {
    if (!PreparedSigner.supportsSignature(signature)) return false
    return prepareSigner(source, context, secret).verify(data, signature)
  }

  /**
   * Verifies a signature produced by [sign] using raw context bytes.
   *
   * @param data bytes that were originally signed; must be identical.
   * @param source the same stable namespace used during signing, including the high-entropy
   *   component (at least 256 bits) such as a suffix from `openssl rand -base64 32`,
   *   e.g., `user_session:v1:Z3VQk3...`.
   * @param context the same context bytes used during signing; it is combined with [source],
   *   so changes to either will break verification. Do not place private data here; use [secret]
   *   for sensitive material.
   * @param signature signature bytes with the algorithm id prefix from [sign].
   * @param secret the same optional secret salt used during signing.
   * @return true if the signature matches; false if the prefix is invalid or verification fails.
   */
  fun isMatchSignature(
    data: ByteArray,
    source: String,
    context: ByteArray,
    signature: ByteArray,
    secret: ByteArray = ByteArray(0)
  ): Boolean {
    if (!PreparedSigner.supportsSignature(signature)) return false
    return prepareSigner(source, context, secret).verify(data, signature)
  }

  /** Prepares a signing scope while retaining the existing signature format. */
  fun prepareSigner(source: String, context: String, secret: ByteArray = ByteArray(0)): PreparedSigner =
    prepareSigner(source, context.toByteArray(Charsets.UTF_8), secret)

  /** The key is derived once; each operation creates its own mutable JCA Mac instance. */
  fun prepareSigner(source: String, context: ByteArray, secret: ByteArray = ByteArray(0)): PreparedSigner =
    PreparedSigner(keyDeriverContextual.deriveKey(32, CONTEXT_SOURCE, packContext(source, context), secret))

  /**
   * Packs the context into a stable protobuf structure for HKDF info binding.
   *
   * @param source logical namespace for the use-case; include a high-entropy component (at least
   *   256 bits) and keep stable across sign/verify, e.g., `user_session:v1:Z3VQk3...`.
   * @param contextBytes raw context bytes; keep identical for matching verification.
   * @return encoded context bytes for key derivation.
   */
  @OptIn(ExperimentalSerializationApi::class)
  private fun packContext(source: String, contextBytes: ByteArray): ByteArray {
    return ProtoBuf.encodeToByteArray(
      ContextContainer(
        source = source,
        contextBytes = contextBytes
      )
    )
  }

  @OptIn(ExperimentalSerializationApi::class)
  @Serializable
  class ContextContainer(
    @ProtoNumber(1)
    val source: String,
    @ProtoNumber(2)
    val contextBytes: ByteArray
  )
}
