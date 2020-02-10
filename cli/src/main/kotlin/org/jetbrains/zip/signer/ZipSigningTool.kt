package org.jetbrains.zip.signer

import com.sampullara.cli.Args
import com.sampullara.cli.Argument
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jetbrains.zip.signer.algorithm.getSuggestedSignatureAlgorithms
import org.jetbrains.zip.signer.keys.loadPrivateKeyAndCertificateFromKeystore
import org.jetbrains.zip.signer.keys.loadPrivateKeyAndCertificatesFromFiles
import org.jetbrains.zip.signer.verifier.ZipVerifier
import java.io.File
import java.security.Security
import kotlin.system.exitProcess


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
        Security.addProvider(BouncyCastleProvider())

        val (privateKey, certificates) = if (options.keyStore != null) {
            val password =
                options.keyStorePassword ?: throw IllegalArgumentException("'ks-pass' property not specified")
            loadPrivateKeyAndCertificateFromKeystore(
                File(options.keyStore),
                password,
                options.keyStoreAlias
            )
        } else {
            loadPrivateKeyAndCertificatesFromFiles(
                File(options.privateKeyFile),
                options.certificateFile?.let { File(it) },
                options.privateKeyPassword?.toCharArray()
            )
        }
        val signingAlgorithms = getSuggestedSignatureAlgorithms(certificates.first().publicKey)
        ZipSigner.sign(
            File(options.inputFilePath),
            File(options.outputFilePath),
            SignerConfig(certificates, privateKey, signingAlgorithms)
        )
    }

    private fun verify(params: Array<String>) {
        val options = VerifyOptions()
        Args.parseOrExit(options, params)
        val signers = ZipVerifier.verify(File(options.inputFilePath))
        if (options.printCertificates) {
            signers.forEachIndexed { signerIndex, signer ->
                signer.certs.forEach { certificate ->
                    println("Signer #${signerIndex}")
                    println(certificate)
                }
            }
        }
    }
}

class SigningOptions {
    @set:Argument("in", required = true, description = "Path to unsigned zip file")
    var inputFilePath: String = ""
    @set:Argument("out", required = true, description = "Path to signed zip file")
    var outputFilePath: String = ""
    @set:Argument("ks", required = false, description = "Keystore file")
    var keyStore: String? = null
    @set:Argument("ks-pass", required = false, description = "Keystore password")
    var keyStorePassword: String? = null
    @set:Argument("ks-key-alias", required = false, description = "Keystore key alias")
    var keyStoreAlias: String? = null
    @set:Argument("key", required = false, description = "Private key file")
    var privateKeyFile: String? = null
    @set:Argument("key-pass", required = false, description = "Private key password")
    var privateKeyPassword: String? = null
    @set:Argument("cert", required = false, description = "Certificate file")
    var certificateFile: String? = null
}

class VerifyOptions {
    @set:Argument("in", required = true, description = "Path to signed plugin zip/jar file")
    var inputFilePath: String = ""
    @set:Argument("print-certs", required = false, description = "Set this option to print zip certificates")
    var printCertificates: Boolean = false
}