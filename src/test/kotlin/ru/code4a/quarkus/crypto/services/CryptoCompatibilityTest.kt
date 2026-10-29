package ru.code4a.quarkus.crypto.services

import java.security.GeneralSecurityException
import java.security.Security
import java.util.Base64
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.bouncycastle.jce.provider.BouncyCastleProvider
import ru.code4a.quarkus.crypto.ciphers.CipherChaCha20Poly1305
import ru.code4a.quarkus.crypto.ciphers.CipherChaCha20Poly1305IVMSG
import ru.code4a.quarkus.crypto.ciphers.FF1Cipher
import ru.code4a.quarkus.crypto.generator.UniqueBytesGenerator
import ru.code4a.quarkus.crypto.utils.PKCS7Padding

class CryptoCompatibilityTest {
  @Test
  fun oldAndPreparedDeterministicApisKeepAllReleasedCiphertexts() {
    val vectors = vectors("legacy-deterministic-cipher-vectors.tsv")
    assertEquals(42, vectors.size)
    for (row in vectors) {
      val service = DeterministicCipherContextual(deriver(row[0].bytes()))
      val source = row[1].text()
      val context = row[2].text()
      val input = row[4].bytes()
      val secret = row[3].bytes()
      val expected = row[5].bytes()
      val prepared = service.prepareDeterministicCipher(source, context, secret)
      assertContentEquals(expected, service.encryptDeterministic(input, source, context, secret))
      assertContentEquals(expected, prepared.encrypt(input))
      assertContentEquals(input, service.decryptDeterministic(expected, source, context, secret))
      assertContentEquals(input, prepared.decrypt(expected))
    }
  }

  @Test
  fun dependencyUpdatesKeepReleasedSignaturesChaChaHkdfAndFf1Formats() {
    Security.addProvider(BouncyCastleProvider())
    val vectors = vectors("legacy-contextual-crypto-vectors.tsv")
    assertEquals(44, vectors.size)
    for (row in vectors) {
      val kind = row[0]
      val keyDeriver = deriver(row[1].bytes())
      val source = row[2].text()
      val context = row[3].text()
      val secret = row[4].bytes()
      val input = row[5].bytes()
      val expected = row[6].bytes()
      when {
        kind == "signature" -> {
          val service = SignerContextual(keyDeriver)
          assertContentEquals(expected, service.sign(input, source, context, secret))
          assertContentEquals(expected, service.sign(input, source, context.toByteArray(), secret))
          assertTrue(service.isMatchSignature(input, source, context, expected, secret))
          assertTrue(service.isMatchSignature(input, source, context.toByteArray(), expected, secret))
          val prepared = service.prepareSigner(source, context, secret)
          assertContentEquals(expected, prepared.sign(input))
          assertTrue(prepared.verify(input, expected))
        }
        kind == "cipher" -> {
          // A fixed nonce is used only for wire-format vectors, never for production data.
          val service = contextualCipher(keyDeriver, object : UniqueBytesGenerator {
            override fun getNext(countBytes: Int) = ByteArray(countBytes) { it.toByte() }
          })
          assertContentEquals(expected, service.encrypt(input, source, context, secret))
          assertContentEquals(expected, service.encrypt(input, source, context.toByteArray(), secret))
          assertContentEquals(input, service.decrypt(expected, source, context, secret))
          assertContentEquals(input, service.decrypt(expected, source, context.toByteArray(), secret))
          val prepared = service.prepareCipher(source, context, secret)
          assertContentEquals(expected, prepared.encrypt(input))
          assertContentEquals(input, prepared.decrypt(expected))
        }
        kind == "derivation" -> {
          assertContentEquals(expected, keyDeriver.deriveKey(48, source, input, secret))
        }
        kind.startsWith("fpe:") -> {
          val radix = kind.substringAfter(':').toInt()
          val service = FormatPreservingEncrypterContextual(keyDeriver, FF1Cipher())
          assertContentEquals(expected, service.encrypt(input, source, context, radix, secret))
          assertContentEquals(expected, service.encrypt(input, source, context.toByteArray(), radix, secret))
          assertContentEquals(input, service.decrypt(expected, source, context, radix, secret))
          assertContentEquals(input, service.decrypt(expected, source, context.toByteArray(), radix, secret))
          val prepared = service.prepareFormatPreservingCipher(source, context, radix, secret)
          assertContentEquals(expected, prepared.encrypt(input))
          assertContentEquals(input, prepared.decrypt(expected))
        }
        else -> error("Unknown compatibility fixture kind: $kind")
      }
    }
  }

  @Test
  fun preparedCipherDerivesOnlyTwoKeysForAllSubsequentOperations() {
    val keys = deriver()
    val prepared = DeterministicCipherContextual(keys).prepareDeterministicCipher("nodes", "")
    assertEquals(2, keys.derivations.get())
    repeat(500) { index ->
      val input = "node:$index".toByteArray()
      assertContentEquals(input, prepared.decrypt(prepared.encrypt(input)))
    }
    assertEquals(2, keys.derivations.get())
  }

  @Test
  fun sharedPreparedCipherSupportsConcurrentEncryptionAndDecryption() {
    val service = DeterministicCipherContextual(deriver())
    val prepared = service.prepareDeterministicCipher("nodes", "workspace", byteArrayOf(1, 2))
    val inputs = List(256) { index -> ByteArray(index * 7) { (it + index).toByte() } }
    val expected = inputs.map { service.encryptDeterministic(it, "nodes", "workspace", byteArrayOf(1, 2)) }
    Executors.newFixedThreadPool(8).use { executor ->
      val tasks = inputs.indices.map { index -> Callable {
        repeat(8) {
          assertContentEquals(expected[index], prepared.encrypt(inputs[index]))
          assertContentEquals(inputs[index], prepared.decrypt(expected[index]))
        }
      } }
      executor.invokeAll(tasks).forEach { it.get(30, TimeUnit.SECONDS) }
    }
  }

  @Test
  fun preparedScopeIsIndependentOfCallerOwnedMutableArrays() {
    val secret = byteArrayOf(1, 2, 3)
    val service = DeterministicCipherContextual(deriver())
    val prepared = service.prepareDeterministicCipher("nodes", "", secret)
    val input = byteArrayOf(10, 20, 30)
    val expected = prepared.encrypt(input)
    secret.fill(0)
    assertContentEquals(expected, prepared.encrypt(input))
    val changedOutput = prepared.encrypt(input)
    changedOutput.fill(0)
    assertContentEquals(expected, prepared.encrypt(input))
    assertContentEquals(input, prepared.decrypt(expected))
  }

  @Test
  fun deterministicDecryptionRejectsChangedPayloadPrefixAndScope() {
    val service = DeterministicCipherContextual(deriver())
    val prepared = service.prepareDeterministicCipher("nodes", "workspace", byteArrayOf(42))
    val ciphertext = prepared.encrypt(byteArrayOf(1, 2, 3))
    assertFailsWith<IllegalArgumentException> { prepared.decrypt(byteArrayOf()) }
    assertFailsWith<IllegalArgumentException> { prepared.decrypt(ciphertext.copyOf().apply { this[0] = 0 }) }
    assertFailsWith<GeneralSecurityException> { prepared.decrypt(ciphertext.copyOf().apply {
      this[lastIndex] = (last().toInt() xor 1).toByte()
    }) }
    for (other in listOf(
      service.prepareDeterministicCipher("other", "workspace", byteArrayOf(42)),
      service.prepareDeterministicCipher("nodes", "other", byteArrayOf(42)),
      service.prepareDeterministicCipher("nodes", "workspace", byteArrayOf(43)),
      DeterministicCipherContextual(deriver(ByteArray(32) { 9 }))
        .prepareDeterministicCipher("nodes", "workspace", byteArrayOf(42))
    )) assertFailsWith<GeneralSecurityException> { other.decrypt(ciphertext) }
  }

  @Test
  fun contextualCipherUsesFreshNoncesAndAuthenticatesDataAndScope() {
    val counter = AtomicInteger()
    val service = contextualCipher(deriver(), object : UniqueBytesGenerator {
      override fun getNext(countBytes: Int) = ByteArray(countBytes).apply {
        this[lastIndex] = counter.incrementAndGet().toByte()
      }
    })
    val input = "\u043e\u0431\u044a\u0435\u043a\u0442".toByteArray()
    val first = service.encrypt(input, "source", "context", byteArrayOf(1))
    val second = service.encrypt(input, "source", "context", byteArrayOf(1))
    assertFalse(first.contentEquals(second))
    assertContentEquals(input, service.decrypt(first, "source", "context", byteArrayOf(1)))
    assertFails { service.decrypt(first.copyOf().apply { this[lastIndex]++ }, "source", "context", byteArrayOf(1)) }
    assertFails { service.decrypt(first, "other", "context", byteArrayOf(1)) }
    assertFails { service.decrypt(first, "source", "other", byteArrayOf(1)) }
    assertFails { service.decrypt(first, "source", "context", byteArrayOf(2)) }
    assertFailsWith<IllegalArgumentException> { service.decrypt(byteArrayOf(), "source", "context") }
    assertFailsWith<IllegalArgumentException> { service.decrypt(byteArrayOf(0), "source", "context") }
  }

  @Test
  fun signaturesRejectChangedDataScopeKeyAndMalformedSignatures() {
    val service = SignerContextual(deriver())
    val input = "\u043e\u0431\u044a\u0435\u043a\u0442".toByteArray()
    val signature = service.sign(input, "source", "context", byteArrayOf(1))
    assertFalse(service.isMatchSignature(byteArrayOf(0), "source", "context", signature, byteArrayOf(1)))
    assertFalse(service.isMatchSignature(input, "other", "context", signature, byteArrayOf(1)))
    assertFalse(service.isMatchSignature(input, "source", "other", signature, byteArrayOf(1)))
    assertFalse(service.isMatchSignature(input, "source", "context", signature, byteArrayOf(2)))
    assertFalse(SignerContextual(deriver(ByteArray(32) { 9 }))
      .isMatchSignature(input, "source", "context", signature, byteArrayOf(1)))
    for (bad in listOf(byteArrayOf(), byteArrayOf(99), signature.copyOf(10), signature.copyOf().apply { this[0] = 0 })) {
      assertFalse(service.isMatchSignature(input, "source", "context", bad, byteArrayOf(1)))
    }
  }

  @Test
  fun keyDerivationPreservesUtf8OverloadsAndSeparatesScopes() {
    val keys = deriver()
    val expected = keys.deriveKey(64, "source", "\u043a\u043e\u043d\u0442\u0435\u043a\u0441\u0442", byteArrayOf(1))
    assertContentEquals(expected, keys.deriveKey(64, "source", "\u043a\u043e\u043d\u0442\u0435\u043a\u0441\u0442".toByteArray(), byteArrayOf(1)))
    assertEquals(64, expected.size)
    assertFalse(expected.contentEquals(keys.deriveKey(64, "other", "\u043a\u043e\u043d\u0442\u0435\u043a\u0441\u0442", byteArrayOf(1))))
    assertFalse(expected.contentEquals(keys.deriveKey(64, "source", "\u0434\u0440\u0443\u0433\u043e\u0439", byteArrayOf(1))))
    assertFalse(expected.contentEquals(keys.deriveKey(64, "source", "\u043a\u043e\u043d\u0442\u0435\u043a\u0441\u0442", byteArrayOf(2))))
    assertFailsWith<IllegalArgumentException> { keys.deriveKey(0, "source", "") }
    assertFailsWith<IllegalArgumentException> { InitializedKeyDeriver("bad base64") }
    assertFailsWith<IllegalArgumentException> { deriver(ByteArray(31)) }
  }

  @Test
  fun fpeValidatesDigitEncodingAndKeepsFormat() {
    Security.addProvider(BouncyCastleProvider())
    val service = FormatPreservingEncrypterContextual(deriver(), FF1Cipher())
    val input = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7)
    val encrypted = service.encrypt(input, "source", "context", 10)
    assertEquals(input.size, encrypted.size)
    assertTrue(encrypted.all { (it.toInt() and 255) < 10 })
    assertContentEquals(input, service.decrypt(encrypted, "source", "context", 10))
    assertFailsWith<IllegalArgumentException> { service.encrypt(byteArrayOf(), "s", "c", 10) }
    assertFailsWith<IllegalArgumentException> { service.encrypt(input, "s", "c", 1) }
    assertFailsWith<IllegalArgumentException> { service.encrypt(input, "s", "c", 65537) }
    assertFailsWith<IllegalArgumentException> { service.encrypt(byteArrayOf(10, 1), "s", "c", 10) }
    assertFailsWith<IllegalArgumentException> { service.encrypt(byteArrayOf(1), "s", "c", 1000) }
    assertFailsWith<IllegalArgumentException> { service.decrypt(byteArrayOf(4, 0), "s", "c", 1000) }
  }

  @Test
  fun paddingRoundTripsBoundarySizesAndRejectsCorruption() {
    for (length in listOf(0, 1, 31, 32, 33, 64, 1024)) {
      val input = ByteArray(length) { it.toByte() }
      val padded = PKCS7Padding.addPadding(input, 32)
      assertEquals(0, padded.size % 32)
      assertContentEquals(input, PKCS7Padding.removePadding(padded, 32))
    }
    assertFailsWith<IllegalArgumentException> { PKCS7Padding.removePadding(byteArrayOf(), 32) }
    assertFailsWith<IllegalArgumentException> { PKCS7Padding.removePadding(byteArrayOf(0), 32) }
    assertFailsWith<IllegalArgumentException> { PKCS7Padding.removePadding(byteArrayOf(1, 2), 32) }
  }

  @Test
  fun preparedAuthenticatedCipherSignerAndFpeDoNotRepeatDerivation() {
    Security.addProvider(BouncyCastleProvider())
    val keys = deriver()
    val counter = java.util.concurrent.atomic.AtomicLong()
    val nonces = object : UniqueBytesGenerator {
      override fun getNext(countBytes: Int): ByteArray = java.nio.ByteBuffer.allocate(countBytes)
        .putInt(0).putLong(counter.incrementAndGet()).array()
    }
    val cipher = contextualCipher(keys, nonces).prepareCipher("source", "context")
    val signer = SignerContextual(keys).prepareSigner("source", "context")
    val fpe = FormatPreservingEncrypterContextual(keys, FF1Cipher())
      .prepareFormatPreservingCipher("source", "context", 256)
    assertEquals(4, keys.derivations.get())
    Executors.newFixedThreadPool(8).use { executor ->
      val tasks = (1..128).map { index -> Callable {
        val input = java.nio.ByteBuffer.allocate(8).putLong(index.toLong()).array()
        val encrypted = cipher.encrypt(input)
        assertContentEquals(input, cipher.decrypt(encrypted))
        assertTrue(signer.verify(input, signer.sign(input)))
        assertFalse(signer.verify(input, signer.sign(input).copyOf().apply { this[lastIndex]++ }))
        assertContentEquals(input, fpe.decrypt(fpe.encrypt(input)))
        encrypted.copyOfRange(1, 13).joinToString(",")
      } }
      val ivs = executor.invokeAll(tasks).map { it.get(30, TimeUnit.SECONDS) }
      assertEquals(128, ivs.toSet().size)
    }
    assertEquals(4, keys.derivations.get())
  }

  private fun vectors(name: String): List<List<String>> =
    checkNotNull(javaClass.getResourceAsStream("/$name")).bufferedReader().useLines { lines ->
      lines.filter { it.isNotBlank() && !it.startsWith('#') }.map { it.split('\t') }.toList()
    }

  private fun contextualCipher(keys: KeyDeriverContextual, nonces: UniqueBytesGenerator) =
    CipherContextual(keys, CipherChaCha20Poly1305IVMSG(CipherChaCha20Poly1305()), nonces)

  private fun deriver(masterKey: ByteArray = ByteArray(32) { it.toByte() }) =
    InitializedKeyDeriver(Base64.getEncoder().encodeToString(masterKey))

  private class InitializedKeyDeriver(masterKey: String) : KeyDeriverContextual(masterKey) {
    val derivations = AtomicInteger()
    init {
      super.init()
    }
    override fun deriveKey(lengthBytes: Int, source: String, contextBytes: ByteArray, secret: ByteArray): ByteArray {
      derivations.incrementAndGet()
      return super.deriveKey(lengthBytes, source, contextBytes, secret)
    }
  }

  private fun String.bytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
  private fun String.text() = Base64.getDecoder().decode(this).toString(Charsets.UTF_8)
}
