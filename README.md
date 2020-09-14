# Marketplace zip signer

[![official JetBrains project](https://jb.gg/badges/official.svg)][jb:confluence-on-gh]
[![Slack](https://img.shields.io/badge/Slack-%23intellij--platform-blue)][jb:slack]

Main goal of marketplace zip signer is to sign and verify 
JetBrains plugins, but it can be applied to any other zip archive. 
General concept of used zip archive signature scheme is similar 
to [APK Signature Scheme V2](https://source.android.com/security/apksigning/v2)

## Signer lib

Library is a main part of project. It is located under 
[lib](https://github.com/JetBrains/marketplace-zip-signer/tree/master/lib) directory.
If you want to sign plugin programmatically using lib use [ZipSigner](https://github.com/JetBrains/marketplace-zip-signer/blob/master/lib/src/main/kotlin/org/jetbrains/zip/signer/signing/ZipSigner.kt), 
to verify use [ZipVerifier](https://github.com/JetBrains/marketplace-zip-signer/blob/master/lib/src/main/kotlin/org/jetbrains/zip/signer/verifier/ZipVerifier.kt) 

## Command line interface

If you want to sign/verify plugin from command line you can use [CLI tool](https://github.com/JetBrains/marketplace-zip-signer/tree/master/cli).
List of available parameters can be found at [ZipSigningTool.SigningOptions](https://github.com/JetBrains/marketplace-zip-signer/blob/master/cli/src/main/kotlin/org/jetbrains/zip/signer/ZipSigningTool.kt)