package org.jetbrains.zip.signer

import com.sampullara.cli.Args
import com.sampullara.cli.Argument
import org.jetbrains.zip.signer.signer.CertificateUtils
import org.jetbrains.zip.signer.signer.PublicKeyUtils
import org.jetbrains.zip.signer.signing.ZipSigner
import org.jetbrains.zip.signer.verifier.InvalidSignatureResult
import org.jetbrains.zip.signer.verifier.MissingSignatureResult
import org.jetbrains.zip.signer.verifier.SuccessfulVerificationResult
import org.jetbrains.zip.signer.verifier.ZipVerifier
import java.io.File
import kotlin.system.exitProcess

object GoogleCloudSignerCli {
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

        val certificates = CertificateUtils.loadCertificatesFromFile(File(options.certificateFile))

        ZipSigner.sign(
            File(options.inputFilePath),
            File(options.outputFilePath),
            certificates,
            GoogleCloudSignatureProvider(
                options.projectId,
                options.locationId,
                options.keyRingId,
                options.keyId,
                options.keyVersion,
                PublicKeyUtils.getSuggestedSignatureAlgorithm(certificates.first().publicKey)
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

    @set:Argument("project", required = true, description = "Google project")
    var projectId: String = ""

    @set:Argument("location", required = true, description = "Google location")
    var locationId: String = ""

    @set:Argument("keyRing", required = true, description = "Google key ring")
    var keyRingId: String = ""

    @set:Argument("keyId", required = true, description = "Google key id")
    var keyId: String = ""

    @set:Argument("keyVersion", required = true, description = "Google key version")
    var keyVersion: String = ""

    @set:Argument("cert", required = true, description = "Certificate file")
    var certificateFile: String = ""
}

class VerifyOptions {
    @set:Argument("in", required = true, description = "Path to signed plugin zip/jar file")
    var inputFilePath: String = ""

    @set:Argument("cert", required = true, description = "Certificate file")
    var certificateFile: String = ""
}