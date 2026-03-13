package ru.code4a.quarkus.crypto.ciphers

import jakarta.enterprise.context.ApplicationScoped
import org.bouncycastle.jcajce.spec.FPEParameterSpec
import javax.crypto.Cipher
import javax.crypto.SecretKey

@ApplicationScoped
class FF1Cipher {
  fun encrypt(data: ByteArray, keyN: SecretKey, tweak16Bytes: ByteArray, radix: Int): ByteArray {
    val cipher = Cipher.getInstance("AES/FF1/NoPadding", "BC")
    cipher.init(Cipher.ENCRYPT_MODE, keyN, FPEParameterSpec(radix, tweak16Bytes))
    return cipher.doFinal(data)
  }

  fun decrypt(encryptedData: ByteArray, keyN: SecretKey, tweak16Bytes: ByteArray, radix: Int): ByteArray {
    val cipher = Cipher.getInstance("AES/FF1/NoPadding", "BC")
    cipher.init(Cipher.DECRYPT_MODE, keyN, FPEParameterSpec(radix, tweak16Bytes))
    return cipher.doFinal(encryptedData)
  }
}
