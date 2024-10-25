package org.jetbrains.zip.signer

import org.hamcrest.core.IsEqual
import org.jetbrains.zip.signer.exceptions.ZipVerificationException
import org.jetbrains.zip.signer.signer.*
import org.jetbrains.zip.signer.signing.DefaultSignatureProvider
import org.jetbrains.zip.signer.signing.ZipSigner
import org.jetbrains.zip.signer.utils.CertificateChain
import org.jetbrains.zip.signer.utils.ZipUtils
import org.jetbrains.zip.signer.verifier.SuccessfulVerificationResult
import org.jetbrains.zip.signer.verifier.ZipVerifier
import org.junit.Assert
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.util.*


open class BaseTest {
    companion object {
        private val tmpDirectory: String = System.getProperty("project.tempDir") ?: "tmp"
        private const val ENTRY_NAME: String = "test.txt"
    }

    fun getResourceFile(resourceFilePath: String) = File(
        javaClass.classLoader.getResource(resourceFilePath).file
    )

    fun createZip(testFileContent: String, fileName: String) =
        ZipUtils.generateZipFile("$tmpDirectory/$fileName.zip", ENTRY_NAME, testFileContent)

    fun sign(inputZip: File, signs: List<SignerInfo>) : File {
        val inputName = inputZip.name.substring(0, inputZip.name.length - ".zip".length)
        val outputFile = File("$tmpDirectory/$inputName-output.zip")
        var prevFile = inputZip

        signs.forEachIndexed { i, (certificates, privateKey) ->
            val newFile = File("$tmpDirectory/$inputName-$i.zip")
            ZipSigner.sign(
                prevFile,
                File("$tmpDirectory/$inputName-$i.zip"),
                certificates,
                DefaultSignatureProvider(
                    PublicKeyUtils.getSuggestedSignatureAlgorithm(certificates[0].publicKey),
                    privateKey
                )
            )
            prevFile = newFile
        }
        prevFile.renameTo(outputFile)

        return outputFile
    }

    fun createZipAndSign(testFileContent: String, signs: List<SignerInfo>): File {
        val uuid = UUID.randomUUID().toString()
        val inputZip = createZip(testFileContent, uuid)
        return sign(inputZip, signs)
    }

    fun createZipAndSignWithChain(testFileContent: String, chain: CertificateChain): File {
        val uuid = UUID.randomUUID().toString()
        val inputZip = ZipUtils.generateZipFile("$tmpDirectory/$uuid.zip", ENTRY_NAME, testFileContent)
        val outputFile = File("$tmpDirectory/$uuid-output.zip")
        ZipSigner.sign(inputZip, outputFile, chain.signsChain, DefaultSignatureProvider(
            PublicKeyUtils.getSuggestedSignatureAlgorithm(chain.signCertificate.publicKey), chain.privateKey
        ))

        return outputFile
    }

    fun File.verifyZip(testFileContent: String) {
        Assert.assertTrue("Output zip archive is empty", this.length() != 0.toLong())

        val outputDirectory = File("$tmpDirectory/${this.nameWithoutExtension}")
        ZipUtils.unzipFile(this, outputDirectory)

        val entries = outputDirectory.listFiles { it -> it.name == ENTRY_NAME }
        require(entries.isNotEmpty()) { "There is no file $ENTRY_NAME in unpacked zip directory" }
        val fileContent = BufferedReader(FileInputStream(entries.first()).reader()).readText()
        Assert.assertThat("File content was corrupted", fileContent, IsEqual.equalTo(testFileContent))
    }

    fun File.isSignedBy(signs: List<SignerInfo>): Boolean {
        return when (val verificationResult = ZipVerifier.verify(this)) {
            is SuccessfulVerificationResult -> {
                signs.all { signerInfo ->
                    verificationResult.isSignedBy(signerInfo.certificates.last())
                }
            }
            else -> false
        }
    }

    fun File.isSignedBy(certificateAuthority: X509Certificate, revocationLists: List<X509CRL>? = null): Boolean {
        return when (val result = ZipVerifier.verify(this)) {
            is SuccessfulVerificationResult -> {
                val chain = result.findCertificateChain(certificateAuthority)

                Assert.assertNotNull(chain)

                val isSigned = result.isSignedBy(certificateAuthority)
                val isNotRevoked = revocationLists?.let {
                    CertificateUtils.findRevokedCertificate(chain!!, it) == null
                } ?: true

                isSigned && isNotRevoked
            }
            else -> false
        }
    }

    fun File.isSignedByAutoExtendCA(certificateAuthority: X509Certificate, revocationLists: List<X509CRL>? = null): Boolean {
        var parsed = ZipVerifier.verify(this)
        if (parsed !is SuccessfulVerificationResult) {
            return false
        }

        // mimic OpenSSL behavior: try to add CA to the chain if it's not present in the zip
        if (!parsed.certificateChains.any { it.last() == certificateAuthority }) {
            // expected 'root' cert is not found, expect single chain
            Assert.assertEquals(1, parsed.certificateChains.size)
            // extend chan with the root CA
            val extendedChain = parsed.certificateChains.first() + certificateAuthority
            parsed = SuccessfulVerificationResult(listOf(extendedChain))

            if (!CertificateUtils.isValidCertificateChain(extendedChain)) {
                throw ZipVerificationException("Cannot build a valid certificate chain")
            }
        }

        val chain = parsed.findCertificateChain(certificateAuthority)

        Assert.assertNotNull(chain)

        val isSigned = parsed.isSignedBy(certificateAuthority)
        val isNotRevoked = revocationLists?.let {
            CertificateUtils.findRevokedCertificate(chain!!, it) == null
        } ?: true

        return isSigned && isNotRevoked
    }

    fun getCACertificate() = SignerInfoLoader.loadSignerInfoFromFiles(
        getResourceFile("certificates/root_ca.key"),
        getResourceFile("certificates/root_ca.pem"),
        "testpassword".toCharArray()
    )

    fun getChain() = SignerInfoLoader.loadSignerInfoFromFiles(
        getResourceFile("certificates/sub_cert.key"),
        getResourceFile("certificates/chain.pem")
    )

    fun getInvalidChain() = SignerInfoLoader.loadSignerInfoFromFiles(
        getResourceFile("certificates/sub_cert.key"),
        getResourceFile("certificates/invalid_chain.pem")
    )

    fun getCertificate() = SignerInfoLoader.loadSignerInfoFromFiles(
        getResourceFile("certificates/sub_cert.key"),
        getResourceFile("certificates/sub_cert.crt")
    )

    fun getSHA256Certificates() = SignerInfoLoader.loadSignerInfoFromFiles(
        getResourceFile("certificates/sha256_private.key"),
        getResourceFile("certificates/sha256.crt")
    )

    fun getSHA512Certificates() = SignerInfoLoader.loadSignerInfoFromFiles(
        getResourceFile("certificates/sha512_private.key"),
        getResourceFile("certificates/sha512.crt")
    )

    fun getECDSACertificate() = SignerInfoLoader.loadSignerInfoFromFiles(
        getResourceFile("certificates/ec_key.pem"),
        getResourceFile("certificates/ecdsa_cert.pem")
    )

    fun getCertificateWithPassword() = SignerInfoLoader.loadSignerInfoFromFiles(
        getResourceFile("certificates/sub_cert.key"),
        getResourceFile("certificates/sub_cert_password.crt"),
        "testpassword".toCharArray()
    )

    fun getFromKeystore() = SignerInfoLoader.loadSignerInfoFromKeystore(
        getResourceFile("keystores/keystore.p12"),
        "testpassword".toCharArray(),
        keystoreType = "pkcs12"
    )

    fun getFromKeystoreWithMultipleEntries() = SignerInfoLoader.loadSignerInfoFromKeystore(
        getResourceFile("keystores/keystore_multiple_entries.p12"),
        "testpassword".toCharArray(),
        keystoreKeyAlias = "test",
        keystoreType = "pkcs12"
    )

    fun getFromKeystoreWithKeyPasswordAndProviderName() = SignerInfoLoader.loadSignerInfoFromKeystore(
        getResourceFile("keystores/keystore_key_password.jks"),
        "testpassword".toCharArray(),
        keystoreKeyAlias = "test",
        keyPassword = "testkeypassword".toCharArray(),
        keystoreProviderName = "SUN"
    )

    fun getPublicKey(keyName: String) = PublicKeyUtils.loadOpenSshKey(
        getResourceFile("keypairs/$keyName.pub")
    )

    fun getFromKey(keyName: String, password: String? = null) = SignerInfoLoader.loadSignerInfoFromFiles(
        getResourceFile("keypairs/$keyName"),
        privateKeyPassword = password?.toCharArray()
    )
}