package org.jetbrains.zip.signer.signing

import org.jetbrains.zip.signer.metadata.SignatureAlgorithm
import java.security.*

class DefaultSignatureProvider(
    override val signatureAlgorithm: SignatureAlgorithm,
    private val privateKey: PrivateKey
) : SignatureProvider {
    private val jcaSignatureAlgorithm = signatureAlgorithm.jcaSignatureAlgorithm
    private val signature = Signature.getInstance(jcaSignatureAlgorithm)

    override fun sign(dataToSign: ByteArray): ByteArray {
        return try {
            with(signature) {
                initSign(privateKey)
                update(dataToSign)
                sign()
            }
        } catch (e: InvalidKeyException) {
            throw InvalidKeyException("Failed to sign using $jcaSignatureAlgorithm", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw SignatureException("Failed to sign using $jcaSignatureAlgorithm", e)
        } catch (e: SignatureException) {
            throw SignatureException("Failed to sign using $jcaSignatureAlgorithm", e)
        }
    }
}