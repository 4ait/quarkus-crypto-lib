package ru.code4a.quarkus.crypto.utils

object PKCS7Padding {
  fun addPadding(data: ByteArray, blockSize: Int): ByteArray {
    val paddingLength = blockSize - (data.size % blockSize)
    val paddingByte = paddingLength.toByte()

    val paddedData = ByteArray(data.size + paddingLength)
    System.arraycopy(data, 0, paddedData, 0, data.size)

    for (i in data.size until paddedData.size) {
      paddedData[i] = paddingByte
    }

    return paddedData
  }

  fun removePadding(data: ByteArray, blockSize: Int): ByteArray {
    if (data.isEmpty()) {
      throw IllegalArgumentException("Cannot remove padding from empty data")
    }

    val paddingLength = data.last().toInt() and 0xFF

    if (paddingLength == 0 || paddingLength > data.size || paddingLength > blockSize) {
      throw IllegalArgumentException("Invalid padding length: $paddingLength")
    }

    for (i in data.size - paddingLength until data.size) {
      if (data[i] != paddingLength.toByte()) {
        throw IllegalArgumentException("Invalid padding detected")
      }
    }

    return data.copyOfRange(0, data.size - paddingLength)
  }
}
