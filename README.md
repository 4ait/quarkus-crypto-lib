# Quarkus Crypto Library

Quarkus Crypto Library is a context-aware cryptography library for Quarkus applications. It provides CDI-managed services for key derivation, authenticated encryption, deterministic encryption, format-preserving encryption, and message signing.

## Features

- HKDF-SHA256 key derivation from a single 32-byte master key
- Contextual authenticated encryption for arbitrary binary payloads
- Deterministic encryption for stable ciphertexts across identical inputs
- Format-preserving encryption for digit-based values using FF1
- Contextual HMAC signing and verification
- Consistent isolation by `source`, `context`, and optional `secret`

## Installation

Add the library to your application:

```kotlin
dependencies {
  implementation("ru.code4a:quarkus-crypto:<version>")
}
```

## Configuration

The library requires a Base64-encoded 32-byte master key:

```properties
erpii.security.base-master-key-32-bytes-base64=<base64-encoded-32-byte-key>
```

Example key generation:

```bash
openssl rand -base64 32
```

## Runtime Requirements

- The library exposes CDI beans and is intended to run inside a Quarkus application.
- `CipherContextual` depends on an application-provided implementation of `UniqueBytesGenerator`.
- FF1 format-preserving encryption requires the Bouncy Castle provider to be available as `BC` at runtime.

## Cryptographic Model

All contextual services follow the same input model:

- `source` is a stable namespace for a use case and should include at least 256 bits of entropy. Example: `customer-profile:v1:base64-32-byte-random-value`.
- `context` scopes operations within the same source, such as a field name, token type, or record identifier.
- `secret` is an optional sensitive salt for per-tenant or per-user isolation.

The same `source`, `context`, and `secret` values must be supplied again for decryption, verification, or repeated key derivation.

## Choosing a Service

- `KeyDeriverContextual` derives keys for custom cryptographic workflows.
- `CipherContextual` encrypts arbitrary binary data with authenticated encryption.
- `DeterministicCipherContextual` produces repeatable ciphertext for identical inputs.
- `FormatPreservingEncrypterContextual` keeps the original digit format and length.
- `SignerContextual` signs and verifies data with a context-derived HMAC key.

## Usage

### Inject services

```kotlin
import jakarta.inject.Inject
import ru.code4a.quarkus.crypto.services.CipherContextual
import ru.code4a.quarkus.crypto.services.DeterministicCipherContextual
import ru.code4a.quarkus.crypto.services.FormatPreservingEncrypterContextual
import ru.code4a.quarkus.crypto.services.KeyDeriverContextual
import ru.code4a.quarkus.crypto.services.SignerContextual

class CryptoService {
  @Inject
  lateinit var keyDeriver: KeyDeriverContextual

  @Inject
  lateinit var cipher: CipherContextual

  @Inject
  lateinit var deterministicCipher: DeterministicCipherContextual

  @Inject
  lateinit var signer: SignerContextual

  @Inject
  lateinit var formatPreservingCipher: FormatPreservingEncrypterContextual
}
```

### Derive a scoped key

```kotlin
val key = keyDeriver.deriveKey(
  lengthBytes = 32,
  source = "tokens:v1:base64-32-byte-random-value",
  context = "refresh-token"
)
```

### Encrypt and decrypt binary data

```kotlin
val source = "customer-profile:v1:base64-32-byte-random-value"

val ciphertext = cipher.encrypt(
  data = "alice@example.com".encodeToByteArray(),
  source = source,
  context = "email"
)

val plaintext = cipher.decrypt(
  data = ciphertext,
  source = source,
  context = "email"
).decodeToString()
```

### Deterministic encryption

Use deterministic encryption when identical plaintext must produce identical ciphertext under the same scope.

```kotlin
val source = "customer-profile:v1:base64-32-byte-random-value"

val encryptedValue = deterministicCipher.encryptDeterministic(
  data = "alice@example.com".encodeToByteArray(),
  source = source,
  context = "email"
)

val decryptedValue = deterministicCipher.decryptDeterministic(
  data = encryptedValue,
  source = source,
  context = "email"
).decodeToString()
```

### Sign and verify data

```kotlin
val source = "session:v1:base64-32-byte-random-value"
val payload = "user:42".encodeToByteArray()

val signature = signer.sign(
  data = payload,
  source = source,
  context = "access-token"
)

val valid = signer.isMatchSignature(
  data = payload,
  source = source,
  context = "access-token",
  signature = signature
)
```

### Format-preserving encryption

For `radix = 10`, pass digit values `0..9`, not ASCII character codes.

```kotlin
val source = "pin:v1:base64-32-byte-random-value"
val pinDigits = byteArrayOf(1, 2, 3, 4)

val encryptedPin = formatPreservingCipher.encrypt(
  data = pinDigits,
  source = source,
  context = "pin",
  radix = 10
)

val decryptedPin = formatPreservingCipher.decrypt(
  data = encryptedPin,
  source = source,
  context = "pin",
  radix = 10
)
```

## Notes

- Encryption and signing methods return raw bytes. Encode them as Base64 or hexadecimal when storing them in text-based systems.
- Use `CipherContextual` for opaque ciphertext, `DeterministicCipherContextual` for equality checks, and `FormatPreservingEncrypterContextual` when the output must retain the original numeric format.

## License

Apache License 2.0

## Contributing

Contributions are welcome through issues and pull requests.
