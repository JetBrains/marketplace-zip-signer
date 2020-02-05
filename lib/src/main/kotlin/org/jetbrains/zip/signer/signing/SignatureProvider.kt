package org.jetbrains.zip.signer.signing

import org.jetbrains.zip.signer.metadata.SignatureAlgorithm

interface SignatureProvider {
    fun sign(dataToSign: ByteArray): ByteArray
    val signatureAlgorithm: SignatureAlgorithm
}