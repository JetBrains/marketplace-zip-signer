package org.jetbrains.zip.signer.signing

import org.jetbrains.zip.signer.metadata.*
import java.security.*
import java.security.cert.X509Certificate

fun generateSignerBlock(
    certificates: List<X509Certificate>,
    privateKey: PrivateKey,
    signatureAlgorithms: Collection<SignatureAlgorithm>,
    contentDigests: Map<ContentDigestAlgorithm, ByteArray>
): SignerBlock {
    if (certificates.isEmpty()) {
        throw SignatureException("No certificates configured for signer")
    }
    val publicKey = certificates[0].publicKey
    val dataToSign = getDataToSign(
        certificates,
        signatureAlgorithms.map { it.contentDigestAlgorithm },
        contentDigests
    )
    val signatures = signatureAlgorithms.map {
        SignatureData(
            it,
            generateSignatureOverData(
                dataToSign.toByteArray(),
                privateKey,
                publicKey,
                it
            )
        )
    }

    return SignerBlock(
        dataToSign,
        signatures,
        publicKey.encoded
    )
}

/**
 * FORMAT:
 * length-prefixed sequence of length-prefixed digests:
 *   uint32: signature algorithm ID
 *   length-prefixed bytes: digest of contents
 * length-prefixed sequence of certificates:
 *   length-prefixed bytes: X.509 certificate (ASN.1 DER encoded).
 * length-prefixed sequence of length-prefixed additional attributes:
 *   uint32: ID
 *   (length - 4) bytes: value
 */
fun getDataToSign(
    certificates: List<X509Certificate>,
    contentDigestAlgorithms: Collection<ContentDigestAlgorithm>,
    contentDigests: Map<ContentDigestAlgorithm, ByteArray>
): DataToSign {
    val encodedCertificates = certificates.map { it.encoded }
    val digests = contentDigestAlgorithms.map { contentDigestAlgorithm ->
        val contentDigest = contentDigests[contentDigestAlgorithm] ?: throw RuntimeException(
            "$contentDigestAlgorithm content digest not computed"
        )
        Digest(contentDigestAlgorithm, contentDigest)
    }
    return DataToSign(
        digests,
        encodedCertificates
    )
}

fun generateSignatureOverData(
    data: ByteArray,
    privateKey: PrivateKey,
    publicKey: PublicKey,
    algorithm: SignatureAlgorithm
): ByteArray {
    val jcaSignatureAlgorithm = algorithm.jcaSignatureAlgorithm
    val signatureBytes = try {
        with(Signature.getInstance(jcaSignatureAlgorithm)) {
            initSign(privateKey)
            update(data)
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
            update(data)
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

