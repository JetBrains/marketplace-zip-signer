package org.jetbrains.zip.signer

import com.sampullara.cli.Args
import com.sampullara.cli.Argument
import org.jetbrains.zip.signer.signer.CertificateUtils
import org.jetbrains.zip.signer.signer.PublicKeyUtils
import org.jetbrains.zip.signer.signer.SignerInfoLoader
import org.jetbrains.zip.signer.signing.DefaultSignatureProvider
import org.jetbrains.zip.signer.signing.ZipSigner
import org.jetbrains.zip.signer.verifier.InvalidSignatureResult
import org.jetbrains.zip.signer.verifier.MissingSignatureResult
import org.jetbrains.zip.signer.verifier.SuccessfulVerificationResult
import org.jetbrains.zip.signer.verifier.ZipVerifier
import java.io.File
import kotlin.system.exitProcess


@ExperimentalUnsignedTypes
object ZipSigningTool {
    @JvmStatic
    fun main(args: Array<String>) {
        if (args.isEmpty()) {
            System.err.println("Command is not specified: `sign` and `verify` commands are supported.")
            exitProcess(1)
        }
        val command = args[0]
        val restParameters = args.copyOfRange(1, args.size)
        when (command) {
            "sign" -> sign(restParameters)
            "verify" -> verify(restParameters)
            else -> {
                System.err.println("Unknown command `$command`: `sign` commands are supported.")
                exitProcess(1)
            }
        }
    }

    private fun sign(params: Array<String>) {
        val options = SigningOptions()
        Args.parseOrExit(options, params)

        val (certificates, privateKey) = if (options.keyStore != null) {
            val keyStore = options.keyStore ?: throw IllegalArgumentException("'ks' property not specified")
            val password = options.keyStorePassword ?: throw IllegalArgumentException("'ks-pass' property not specified")

            SignerInfoLoader.loadSignerInfoFromKeystore(
                file = File(keyStore),
                password = password.toCharArray(),
                keystoreKeyAlias = options.keyStoreAlias,
                keystoreType = options.keyStoreType,
                keystoreProviderName = options.keyStoreProviderName
            )
        } else if (options.privateKey != null) {
            val privateKey = options.privateKey ?: throw IllegalArgumentException("'key' property not specified")
            val privateKeyPassword = options.privateKeyPassword?.toCharArray()
            val certificate = options.certificate ?: options.certificateFile?.let { File(it).readText() }

            SignerInfoLoader.loadSignerInfoFromText(
                privateKey,
                certificate,
                privateKeyPassword
            )
        } else {
            val privateKeyFile = options.privateKeyFile ?: throw IllegalArgumentException("'key-file' property not specified")
            val privateKeyPassword = options.privateKeyPassword?.toCharArray()

            SignerInfoLoader.loadSignerInfoFromFiles(
                File(privateKeyFile),
                options.certificateFile?.let { File(it) },
                privateKeyPassword
            )
        }

        ZipSigner.sign(
            File(options.inputFilePath),
            File(options.outputFilePath),
            certificates,
            DefaultSignatureProvider(
                PublicKeyUtils.getSuggestedSignatureAlgorithm(certificates[0].publicKey), privateKey
            )
        )
    }

    private fun verify(params: Array<String>) {
        val options = VerifyOptions()
        Args.parseOrExit(options, params)
        val certificateAuthority = CertificateUtils
            .loadCertificatesFromFile(File(options.certificateFile))
            .first()
        when (val verificationResult = ZipVerifier.verify(File(options.inputFilePath))) {
            is SuccessfulVerificationResult -> if (!verificationResult.isSignedBy(certificateAuthority)) {
                exitWithError("Zip archive is not signed by provided certificate authority")
            }
            is MissingSignatureResult -> exitWithError("Provided zip archive is not signed")
            is InvalidSignatureResult -> exitWithError("Signature of zip archive is invalid")
        }
    }

    private fun exitWithError(message: String) {
        System.err.println(message)
        exitProcess(-1)
    }
}

class SigningOptions {
    @set:Argument("in", required = true, description = "Path to unsigned zip file")
    var inputFilePath: String = ""

    @set:Argument("out", required = true, description = "Path to signed zip file")
    var outputFilePath: String = ""

    @set:Argument("ks", required = false, description = "KeyStore file")
    var keyStore: String? = null

    @set:Argument("ks-pass", required = false, description = "KeyStore password")
    var keyStorePassword: String? = null

    @set:Argument("ks-key-alias", required = false, description = "KeyStore key alias")
    var keyStoreAlias: String? = null

    @set:Argument("ks-type", required = false, description = "KeyStore type")
    var keyStoreType: String? = null

    @set:Argument("ks-provider-name", required = false, description = "JCA KeyStore Provider name")
    var keyStoreProviderName: String? = null

    @set:Argument("key", required = false, description = "Private key")
    var privateKey: String? = null

    @set:Argument("key-file", required = false, description = "Private key file")
    var privateKeyFile: String? = null

    @set:Argument("key-pass", required = false, description = "Private key password")
    var privateKeyPassword: String? = null

    @set:Argument("cert", required = false, description = "Certificate")
    var certificate: String? = null

    @set:Argument("cert-file", required = false, description = "Certificate file")
    var certificateFile: String? = null
}

class VerifyOptions {
    @set:Argument("in", required = true, description = "Path to signed plugin zip/jar file")
    var inputFilePath: String = ""

    @set:Argument("cert", required = true, description = "Certificate file")
    var certificateFile: String = ""
}
