package org.jetbrains.zip.signer.verifier

import org.jetbrains.zip.signer.metadata.SignatureAlgorithm
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.Signature
import java.security.SignatureException
import java.security.cert.X509Certificate

class DefaultSignatureVerifier(
    certificateChain: List<X509Certificate>,
    signatureAlgorithm: SignatureAlgorithm
) : SignatureVerifier {
    private val publicKey = certificateChain[0].publicKey
    private val jcaSignatureAlgorithm = signatureAlgorithm.jcaSignatureAlgorithm

    override fun verify(dataToVerify: ByteArray, signature: ByteArray) {
        try {
            with(Signature.getInstance(jcaSignatureAlgorithm)) {
                initVerify(publicKey)
                update(dataToVerify)
                if (!verify(signature)) {
                    throw SignatureException(
                        "Failed to verify $jcaSignatureAlgorithm signature using public key from certificate"
                    )
                }
            }
        } catch (e: InvalidKeyException) {
            throw InvalidKeyException(
                "Failed to verify $jcaSignatureAlgorithm signature using public key from certificate", e
            )
        } catch (e: InvalidAlgorithmParameterException) {
            throw SignatureException(
                "Failed to verify $jcaSignatureAlgorithm signature using public key from certificate", e
            )
        } catch (e: SignatureException) {
            throw SignatureException(
                "Failed to verify $jcaSignatureAlgorithm signature using public key from certificate", e
            )
        }
    }
}