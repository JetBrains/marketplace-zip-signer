package org.jetbrains.zip.signer.signing

import org.jetbrains.zip.signer.metadata.Digest
import org.jetbrains.zip.signer.metadata.SignatureAlgorithm
import org.jetbrains.zip.signer.metadata.SignatureData
import org.jetbrains.zip.signer.metadata.SignerBlock
import java.security.*
import java.security.cert.X509Certificate

fun generateSignerBlock(
    certificates: List<X509Certificate>,
    privateKey: PrivateKey,
    signatureAlgorithms: Collection<SignatureAlgorithm>,
    contentDigests: List<Digest>
): SignerBlock {
    if (certificates.isEmpty()) {
        throw SignatureException("No certificates configured for signer")
    }
    val publicKey = certificates.first().publicKey
    val encodedCertificates = certificates.map { it.encoded }
    val signatures = signatureAlgorithms.map { signatureAlgorithm ->
        val digest = contentDigests.find {
            it.algorithm == signatureAlgorithm.contentDigestAlgorithm
        } ?: throw RuntimeException(
            "${signatureAlgorithm.contentDigestAlgorithm} content digest not computed"
        )
        SignatureData(
            signatureAlgorithm,
            generateSignatureOverData(
                DataToSign(digest, encodedCertificates),
                privateKey,
                publicKey,
                signatureAlgorithm
            )
        )
    }

    return SignerBlock(
        encodedCertificates,
        signatures,
        publicKey.encoded
    )
}


class DataToSign(val digest: Digest, val encodedCertificates: List<ByteArray>)

fun generateSignatureOverData(
    data: DataToSign,
    privateKey: PrivateKey,
    publicKey: PublicKey,
    algorithm: SignatureAlgorithm
): ByteArray {
    val jcaSignatureAlgorithm = algorithm.jcaSignatureAlgorithm
    val signatureBytes = try {
        with(Signature.getInstance(jcaSignatureAlgorithm)) {
            initSign(privateKey)
            update(data.digest.digestBytes)
            data.encodedCertificates.forEach { update(it) }
            sign()
        }
    } catch (e: InvalidKeyException) {
        throw InvalidKeyException("Failed to sign using $jcaSignatureAlgorithm", e)
    } catch (e: InvalidAlgorithmParameterException) {
        throw SignatureException("Failed to sign using $jcaSignatureAlgorithm", e)
    } catch (e: SignatureException) {
        throw SignatureException("Failed to sign using $jcaSignatureAlgorithm", e)
    }

    try {
        with(Signature.getInstance(jcaSignatureAlgorithm)) {
            initVerify(publicKey)
            update(data.digest.digestBytes)
            data.encodedCertificates.forEach { update(it) }
            if (!verify(signatureBytes)) {
                throw SignatureException(
                    "Failed to verify generated "
                            + jcaSignatureAlgorithm
                            + " signature using public key from certificate"
                )
            }
        }
    } catch (e: InvalidKeyException) {
        throw InvalidKeyException(
            "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                    + " public key from certificate", e
        )
    } catch (e: InvalidAlgorithmParameterException) {
        throw SignatureException(
            "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                    + " public key from certificate", e
        )
    } catch (e: SignatureException) {
        throw SignatureException(
            "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                    + " public key from certificate", e
        )
    }
    return signatureBytes
}

