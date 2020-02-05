package org.jetbrains.zip.signer.verifier

interface SignatureVerifier {
    fun verify(dataToVerify: ByteArray, signature: ByteArray)
}