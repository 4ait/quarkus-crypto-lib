package ru.code4a.quarkus.crypto.services

import jakarta.annotation.PostConstruct
import jakarta.enterprise.context.ApplicationScoped
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import kotlinx.serialization.protobuf.ProtoNumber
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.eclipse.microprofile.config.inject.ConfigProperty
import java.security.MessageDigest
import java.util.*

@ApplicationScoped
/**
 * HKDF-based key derivation service that binds derived keys to a source string, a context value,
 * and an optional secret. This provides a consistent way to scope keys by purpose and prevents
 * key reuse across unrelated data domains.
 *
 * Example: use source "tokens:v1:Z3VQk3..." and context "refresh" to derive a token-specific key.
 */
class KeyDeriverContextual(
  @ConfigProperty(name = "erpii.security.base-master-key-32-bytes-base64")
  private val masterKeyBase64: String
) {
  companion object {
    private const val HKDF_PREFIX_SALT = "6474fb2aeac3d98a63b397a46906a3080a471e3b65d3411728d53d239fe02f38"
  }

  private lateinit var masterKeyBytes: ByteArray

  /**
   * Decodes and validates the configured base master key.
   */
  @PostConstruct
  protected fun init() {
    masterKeyBytes = Base64.getDecoder().decode(masterKeyBase64)

    require(masterKeyBytes.size == 32) { "Base Master Key size must be 32 bytes" }
  }

  /**
   * Derives a key for a specific context using a UTF-8 string.
   *
   * @param lengthBytes desired key length in bytes; must be positive and consistent with the
   *   consumer (e.g., 32 for AES-256, 64 for AES-SIV).
   * @param source stable logical namespace that identifies the feature or data class; include a
   *   high-entropy component (at least 256 bits) and keep it consistent across callers. You can
   *   append a generated value from `openssl rand -base64 32` to reach the required entropy,
   *   e.g., `user_profile:v1:Z3VQk3...`.
   * @param context human-readable context string (e.g., "passwords", "tokens", "user_data");
   *   it is combined with [source] to derive the key, so both must be stable. Use [context] to
   *   distinguish fields or records within the same [source]. Do not place private data here; use
   *   [secret] for sensitive material.
   * @param secret optional additional secret salt to scope keys per tenant/user; must match when
   *   deriving the same key again.
   * @return derived key bytes of length [lengthBytes].
   */
  fun deriveKey(
    lengthBytes: Int,
    source: String,
    context: String,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    val contextBytes = context.toByteArray(Charsets.UTF_8)
    return deriveKey(
      lengthBytes = lengthBytes,
      contextBytes = contextBytes,
      source = source,
      secret = secret
    )
  }

  /**
   * Derives a key from raw context bytes without converting to string.
   *
   * @param lengthBytes desired key length in bytes; must be positive and consistent with the
   *   consumer (e.g., 32 for AES-256, 64 for AES-SIV).
   * @param source stable logical namespace that identifies the feature or data class; include a
   *   high-entropy component (at least 256 bits) and keep it consistent across callers. You can
   *   append a generated value from `openssl rand -base64 32` to reach the required entropy,
   *   e.g., `user_profile:v1:Z3VQk3...`.
   * @param contextBytes raw context bytes (e.g., a stable record identifier); it is combined with
   *   [source], so both must be stable and identical for repeated derivations. Do not place
   *   private data here; use [secret] for sensitive material.
   * @param secret optional additional secret salt to scope keys per tenant/user; must match when
   *   deriving the same key again.
   * @return derived key bytes of length [lengthBytes].
   */
  @OptIn(ExperimentalSerializationApi::class)
  fun deriveKey(
    lengthBytes: Int,
    source: String,
    contextBytes: ByteArray,
    secret: ByteArray = ByteArray(0)
  ): ByteArray {
    return hkdfSha256(
      info = ProtoBuf.encodeToByteArray(
        KeyDeriveContainer(
          contextSource = source,
          contextBytes = contextBytes
        )
      ),
      secretSalt = secret,
      lengthBytes = lengthBytes
    )
  }

  @Serializable
  class KeyDeriveContainer(
    @ProtoNumber(1)
    val app: String = "ru.foura.erpii.security.crypto.KeyDeriverContextual",
    @ProtoNumber(2)
    val version: String = "6886d518462f5d9be56a655795ea6b8da90df92b480e4515173810b2db396e33",
    @ProtoNumber(3)
    val contextSource: String,
    @ProtoNumber(4)
    val contextBytes: ByteArray
  )

  /**
   * HKDF-SHA256 derivation using the configured master key and a salted prefix.
   *
   * @param info application-specific info bytes; should encode all scoping inputs and remain
   *   stable for the same derived key.
   * @param secretSalt optional additional salt; use for per-tenant or per-user scoping and keep
   *   identical across derivations that must match.
   * @param lengthBytes desired output length in bytes; must be positive and suitable for the
   *   consumer algorithm.
   * @return derived key bytes of length [lengthBytes].
   */
  fun hkdfSha256(
    info: ByteArray,
    secretSalt: ByteArray = ByteArray(0),
    lengthBytes: Int
  ): ByteArray {
    require(lengthBytes > 0) { "length must be > 0" }

    val salt =
      MessageDigest.getInstance("SHA-256")
        .digest(HKDF_PREFIX_SALT.toByteArray(Charsets.UTF_8) + secretSalt)

    val hkdf = HKDFBytesGenerator(SHA256Digest())
    hkdf.init(
      HKDFParameters(
        masterKeyBytes,
        salt,
        info
      )
    )

    return ByteArray(lengthBytes).also { out ->
      hkdf.generateBytes(out, 0, out.size)
    }
  }
}
