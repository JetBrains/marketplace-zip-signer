package org.jetbrains.zip.signer.verifier

import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm

enum class Issue(
    /**
     * Returns the format string suitable for combining the parameters of this issue into a
     * readable string. See [java.util.Formatter] for format.
     */
    val format: String
) {
    /**
     * APK is not JAR-signed.
     */
    JAR_SIG_NO_SIGNATURES("No JAR signatures"),
    /**
     * APK does not contain any entries covered by JAR signatures.
     */
    JAR_SIG_NO_SIGNED_ZIP_ENTRIES("No JAR entries covered by JAR signatures"),
    /**
     * APK contains multiple entries with the same name.
     *
     *
     *  * Parameter 1: name (`String`)
     *
     */
    JAR_SIG_DUPLICATE_ZIP_ENTRY("Duplicate entry: %1\$s"),
    /**
     * JAR manifest contains a section with a duplicate name.
     *
     *
     *  * Parameter 1: section name (`String`)
     *
     */
    JAR_SIG_DUPLICATE_MANIFEST_SECTION("Duplicate section in META-INF/MANIFEST.MF: %1\$s"),
    /**
     * JAR manifest contains a section without a name.
     *
     *
     *  * Parameter 1: section index (1-based) (`Integer`)
     *
     */
    JAR_SIG_UNNNAMED_MANIFEST_SECTION(
        "Malformed META-INF/MANIFEST.MF: invidual section #%1\$d does not have a name"
    ),
    /**
     * JAR signature file contains a section without a name.
     *
     *
     *  * Parameter 1: signature file name (`String`)
     *  * Parameter 2: section index (1-based) (`Integer`)
     *
     */
    JAR_SIG_UNNNAMED_SIG_FILE_SECTION(
        "Malformed %1\$s: invidual section #%2\$d does not have a name"
    ),
    /** APK is missing the JAR manifest entry (META-INF/MANIFEST.MF).  */
    JAR_SIG_NO_MANIFEST("Missing META-INF/MANIFEST.MF"),
    /**
     * JAR manifest references an entry which is not there in the APK.
     *
     *
     *  * Parameter 1: entry name (`String`)
     *
     */
    JAR_SIG_MISSING_ZIP_ENTRY_REFERENCED_IN_MANIFEST(
        "%1\$s entry referenced by META-INF/MANIFEST.MF not found in the APK"
    ),
    /**
     * JAR manifest does not list a digest for the specified entry.
     *
     *
     *  * Parameter 1: entry name (`String`)
     *
     */
    JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_MANIFEST("No digest for %1\$s in META-INF/MANIFEST.MF"),
    /**
     * JAR signature does not list a digest for the specified entry.
     *
     *
     *  * Parameter 1: entry name (`String`)
     *  * Parameter 2: signature file name (`String`)
     *
     */
    JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_SIG_FILE("No digest for %1\$s in %2\$s"),
    /**
     * The specified JAR entry is not covered by JAR signature.
     *
     *
     *  * Parameter 1: entry name (`String`)
     *
     */
    JAR_SIG_ZIP_ENTRY_NOT_SIGNED("%1\$s entry not signed"),
    /**
     * JAR signature uses different set of signers to protect the two specified ZIP entries.
     *
     *
     *  * Parameter 1: first entry name (`String`)
     *  * Parameter 2: first entry signer names (`List<String>`)
     *  * Parameter 3: second entry name (`String`)
     *  * Parameter 4: second entry signer names (`List<String>`)
     *
     */
    JAR_SIG_ZIP_ENTRY_SIGNERS_MISMATCH(
        "Entries %1\$s and %3\$s are signed with different sets of signers"
                + " : <%2\$s> vs <%4\$s>"
    ),
    /**
     * Digest of the specified ZIP entry's data does not match the digest expected by the JAR
     * signature.
     *
     *
     *  * Parameter 1: entry name (`String`)
     *  * Parameter 2: digest algorithm (e.g., SHA-256) (`String`)
     *  * Parameter 3: name of the entry in which the expected digest is specified
     * (`String`)
     *  * Parameter 4: base64-encoded actual digest (`String`)
     *  * Parameter 5: base64-encoded expected digest (`String`)
     *
     */
    JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY(
        "%2\$s digest of %1\$s does not match the digest specified in %3\$s"
                + ". Expected: <%5\$s>, actual: <%4\$s>"
    ),
    /**
     * Digest of the JAR manifest main section did not verify.
     *
     *
     *  * Parameter 1: digest algorithm (e.g., SHA-256) (`String`)
     *  * Parameter 2: name of the entry in which the expected digest is specified
     * (`String`)
     *  * Parameter 3: base64-encoded actual digest (`String`)
     *  * Parameter 4: base64-encoded expected digest (`String`)
     *
     */
    JAR_SIG_MANIFEST_MAIN_SECTION_DIGEST_DID_NOT_VERIFY(
        "%1\$s digest of META-INF/MANIFEST.MF main section does not match the digest"
                + " specified in %2\$s. Expected: <%4\$s>, actual: <%3\$s>"
    ),
    /**
     * Digest of the specified JAR manifest section does not match the digest expected by the
     * JAR signature.
     *
     *
     *  * Parameter 1: section name (`String`)
     *  * Parameter 2: digest algorithm (e.g., SHA-256) (`String`)
     *  * Parameter 3: name of the signature file in which the expected digest is specified
     * (`String`)
     *  * Parameter 4: base64-encoded actual digest (`String`)
     *  * Parameter 5: base64-encoded expected digest (`String`)
     *
     */
    JAR_SIG_MANIFEST_SECTION_DIGEST_DID_NOT_VERIFY(
        "%2\$s digest of META-INF/MANIFEST.MF section for %1\$s does not match the digest"
                + " specified in %3\$s. Expected: <%5\$s>, actual: <%4\$s>"
    ),
    /**
     * JAR signature file does not contain the whole-file digest of the JAR manifest file. The
     * digest speeds up verification of JAR signature.
     *
     *
     *  * Parameter 1: name of the signature file (`String`)
     *
     */
    JAR_SIG_NO_MANIFEST_DIGEST_IN_SIG_FILE(
        "%1\$s does not specify digest of META-INF/MANIFEST.MF"
                + ". This slows down verification."
    ),
    /**
     * APK is signed using APK Signature Scheme v2 or newer, but JAR signature file does not
     * contain protections against stripping of these newer scheme signatures.
     *
     *
     *  * Parameter 1: name of the signature file (`String`)
     *
     */
    JAR_SIG_NO_APK_SIG_STRIP_PROTECTION(
        "APK is signed using APK Signature Scheme v2 but these signatures may be stripped"
                + " without being detected because %1\$s does not contain anti-stripping"
                + " protections."
    ),
    /**
     * JAR signature of the signer is missing a file/entry.
     *
     *
     *  * Parameter 1: name of the encountered file (`String`)
     *  * Parameter 2: name of the missing file (`String`)
     *
     */
    JAR_SIG_MISSING_FILE("Partial JAR signature. Found: %1\$s, missing: %2\$s"),
    /**
     * An exception was encountered while verifying JAR signature contained in a signature block
     * against the signature file.
     *
     *
     *  * Parameter 1: name of the signature block file (`String`)
     *  * Parameter 2: name of the signature file (`String`)
     *  * Parameter 3: exception (`Throwable`)
     *
     */
    JAR_SIG_VERIFY_EXCEPTION("Failed to verify JAR signature %1\$s against %2\$s: %3\$s"),
    /**
     * JAR signature contains unsupported digest algorithm.
     *
     *
     *  * Parameter 1: name of the signature block file (`String`)
     *  * Parameter 2: digest algorithm OID (`String`)
     *  * Parameter 3: signature algorithm OID (`String`)
     *  * Parameter 4: API Levels on which this combination of algorithms is not supported
     * (`String`)
     *  * Parameter 5: user-friendly variant of digest algorithm (`String`)
     *  * Parameter 6: user-friendly variant of signature algorithm (`String`)
     *
     */
    JAR_SIG_UNSUPPORTED_SIG_ALG(
        "JAR signature %1\$s uses digest algorithm %5\$s and signature algorithm %6\$s which"
                + " is not supported on API Level(s) %4\$s for which this APK is being"
                + " verified"
    ),
    /**
     * An exception was encountered while parsing JAR signature contained in a signature block.
     *
     *
     *  * Parameter 1: name of the signature block file (`String`)
     *  * Parameter 2: exception (`Throwable`)
     *
     */
    JAR_SIG_PARSE_EXCEPTION("Failed to parse JAR signature %1\$s: %2\$s"),
    /**
     * An exception was encountered while parsing a certificate contained in the JAR signature
     * block.
     *
     *
     *  * Parameter 1: name of the signature block file (`String`)
     *  * Parameter 2: exception (`Throwable`)
     *
     */
    JAR_SIG_MALFORMED_CERTIFICATE("Malformed certificate in JAR signature %1\$s: %2\$s"),
    /**
     * JAR signature contained in a signature block file did not verify against the signature
     * file.
     *
     *
     *  * Parameter 1: name of the signature block file (`String`)
     *  * Parameter 2: name of the signature file (`String`)
     *
     */
    JAR_SIG_DID_NOT_VERIFY("JAR signature %1\$s did not verify against %2\$s"),
    /**
     * JAR signature contains no verified signers.
     *
     *
     *  * Parameter 1: name of the signature block file (`String`)
     *
     */
    JAR_SIG_NO_SIGNERS("JAR signature %1\$s contains no signers"),
    /**
     * JAR signature file contains a section with a duplicate name.
     *
     *
     *  * Parameter 1: signature file name (`String`)
     *  * Parameter 1: section name (`String`)
     *
     */
    JAR_SIG_DUPLICATE_SIG_FILE_SECTION("Duplicate section in %1\$s: %2\$s"),
    /**
     * JAR signature file's main section doesn't contain the mandatory Signature-Version
     * attribute.
     *
     *
     *  * Parameter 1: signature file name (`String`)
     *
     */
    JAR_SIG_MISSING_VERSION_ATTR_IN_SIG_FILE(
        "Malformed %1\$s: missing Signature-Version attribute"
    ),
    /**
     * JAR signature file references an unknown APK signature scheme ID.
     *
     *
     *  * Parameter 1: name of the signature file (`String`)
     *  * Parameter 2: unknown APK signature scheme ID (`` Integer)
     *
     */
    JAR_SIG_UNKNOWN_APK_SIG_SCHEME_ID(
        "JAR signature %1\$s references unknown APK signature scheme ID: %2\$d"
    ),
    /**
     * JAR signature file indicates that the APK is supposed to be signed with a supported APK
     * signature scheme (in addition to the JAR signature) but no such signature was found in
     * the APK.
     *
     *
     *  * Parameter 1: name of the signature file (`String`)
     *  * Parameter 2: APK signature scheme ID (`` Integer)
     *  * Parameter 3: APK signature scheme English name (`` String)
     *
     */
    JAR_SIG_MISSING_APK_SIG_REFERENCED(
        "JAR signature %1\$s indicates the APK is signed using %3\$s but no such signature"
                + " was found. Signature stripped?"
    ),
    /**
     * JAR entry is not covered by signature and thus unauthorized modifications to its contents
     * will not be detected.
     *
     *
     *  * Parameter 1: entry name (`String`)
     *
     */
    JAR_SIG_UNPROTECTED_ZIP_ENTRY(
        "%1\$s not protected by signature. Unauthorized modifications to this JAR entry"
                + " will not be detected. Delete or move the entry outside of META-INF/."
    ),
    /**
     * APK which is both JAR-signed and signed using APK Signature Scheme v2 contains an APK
     * Signature Scheme v2 signature from this signer, but does not contain a JAR signature
     * from this signer.
     */
    JAR_SIG_MISSING("No JAR signature from this signer"),
    /**
     * APK is targeting a sandbox version which requires APK Signature Scheme v2 signature but
     * no such signature was found.
     *
     *
     *  * Parameter 1: target sandbox version (`Integer`)
     *
     */
    NO_SIG_FOR_TARGET_SANDBOX_VERSION(
        "Missing APK Signature Scheme v2 signature required for target sandbox version"
                + " %1\$d"
    ),
    /**
     * APK which is both JAR-signed and signed using APK Signature Scheme v2 contains a JAR
     * signature from this signer, but does not contain an APK Signature Scheme v2 signature
     * from this signer.
     */
    V2_SIG_MISSING("No APK Signature Scheme v2 signature from this signer"),
    /**
     * Failed to parse the list of signers contained in the APK Signature Scheme v2 signature.
     */
    V2_SIG_MALFORMED_SIGNERS("Malformed list of signers"),
    /**
     * Failed to parse this signer's signer block contained in the APK Signature Scheme v2
     * signature.
     */
    V2_SIG_MALFORMED_SIGNER("Malformed signer block"),
    /**
     * Public key embedded in the APK Signature Scheme v2 signature of this signer could not be
     * parsed.
     *
     *
     *  * Parameter 1: error details (`Throwable`)
     *
     */
    V2_SIG_MALFORMED_PUBLIC_KEY("Malformed public key: %1\$s"),
    /**
     * This APK Signature Scheme v2 signer's certificate could not be parsed.
     *
     *
     *  * Parameter 1: index (`0`-based) of the certificate in the signer's list of
     * certificates (`Integer`)
     *  * Parameter 2: sequence number (`1`-based) of the certificate in the signer's
     * list of certificates (`Integer`)
     *  * Parameter 3: error details (`Throwable`)
     *
     */
    V2_SIG_MALFORMED_CERTIFICATE("Malformed certificate"),
    /**
     * Failed to parse this signer's signature record contained in the APK Signature Scheme v2
     * signature.
     *
     *
     *  * Parameter 1: record number (first record is `1`) (`Integer`)
     *
     */
    V2_SIG_MALFORMED_SIGNATURE("Malformed APK Signature Scheme v2 signature record #%1\$d"),
    /**
     * Failed to parse this signer's digest record contained in the APK Signature Scheme v2
     * signature.
     *
     *
     *  * Parameter 1: record number (first record is `1`) (`Integer`)
     *
     */
    V2_SIG_MALFORMED_DIGEST("Malformed APK Signature Scheme v2 digest record #%1\$d"),
    /**
     * This APK Signature Scheme v2 signer contains a malformed additional attribute.
     *
     *
     *  * Parameter 1: attribute number (first attribute is `1`) `Integer`)
     *
     */
    V2_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE("Malformed additional attribute #%1\$d"),
    /**
     * APK Signature Scheme v2 signature references an unknown APK signature scheme ID.
     *
     *
     *  * Parameter 1: signer index (`Integer`)
     *  * Parameter 2: unknown APK signature scheme ID (`` Integer)
     *
     */
    V2_SIG_UNKNOWN_APK_SIG_SCHEME_ID(
        "APK Signature Scheme v2 signer: %1\$s references unknown APK signature scheme ID: "
                + "%2\$d"
    ),
    /**
     * APK Signature Scheme v2 signature indicates that the APK is supposed to be signed with a
     * supported APK signature scheme (in addition to the v2 signature) but no such signature
     * was found in the APK.
     *
     *
     *  * Parameter 1: signer index (`Integer`)
     *  * Parameter 2: APK signature scheme English name (`` String)
     *
     */
    V2_SIG_MISSING_APK_SIG_REFERENCED(
        "APK Signature Scheme v2 signature %1\$s indicates the APK is signed using %2\$s but "
                + "no such signature was found. Signature stripped?"
    ),
    /**
     * APK Signature Scheme v2 signature contains no signers.
     */
    V2_SIG_NO_SIGNERS("No signers in APK Signature Scheme v2 signature"),
    /**
     * This APK Signature Scheme v2 signer contains a signature produced using an unknown
     * algorithm.
     *
     *
     *  * Parameter 1: algorithm ID (`Integer`)
     *
     */
    V2_SIG_UNKNOWN_SIG_ALGORITHM("Unknown signature algorithm: %1$#x"),
    /**
     * This APK Signature Scheme v2 signer contains an unknown additional attribute.
     *
     *
     *  * Parameter 1: attribute ID (`Integer`)
     *
     */
    V2_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE("Unknown additional attribute: ID %1$#x"),
    /**
     * An exception was encountered while verifying APK Signature Scheme v2 signature of this
     * signer.
     *
     *
     *  * Parameter 1: signature algorithm ([SignatureAlgorithm])
     *  * Parameter 2: exception (`Throwable`)
     *
     */
    V2_SIG_VERIFY_EXCEPTION("Failed to verify %1\$s signature: %2\$s"),
    /**
     * APK Signature Scheme v2 signature over this signer's signed-data block did not verify.
     *
     *
     *  * Parameter 1: signature algorithm ([SignatureAlgorithm])
     *
     */
    V2_SIG_DID_NOT_VERIFY("%1\$s signature over signed-data did not verify"),
    /**
     * This APK Signature Scheme v2 signer offers no signatures.
     */
    V2_SIG_NO_SIGNATURES("No signatures"),
    /**
     * This APK Signature Scheme v2 signer offers signatures but none of them are supported.
     */
    V2_SIG_NO_SUPPORTED_SIGNATURES("No supported signatures"),
    /**
     * This APK Signature Scheme v2 signer offers no certificates.
     */
    V2_SIG_NO_CERTIFICATES("No certificates"),
    /**
     * This APK Signature Scheme v2 signer's public key listed in the signer's certificate does
     * not match the public key listed in the signatures record.
     *
     *
     *  * Parameter 1: hex-encoded public key from certificate (`String`)
     *  * Parameter 2: hex-encoded public key from signatures record (`String`)
     *
     */
    V2_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD(
        "Public key mismatch between certificate and signature record: <%1\$s> vs <%2\$s>"
    ),
    /**
     * This APK Signature Scheme v2 signer's signature algorithms listed in the signatures
     * record do not match the signature algorithms listed in the signatures record.
     *
     *
     *  * Parameter 1: signature algorithms from signatures record (`List<Integer>`)
     *  * Parameter 2: signature algorithms from digests record (`List<Integer>`)
     *
     */
    V2_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS(
        "Signature algorithms mismatch between signatures and digests records"
                + ": %1\$s vs %2\$s"
    ),
    /**
     * The APK's digest does not match the digest contained in the APK Signature Scheme v2
     * signature.
     *
     *
     *  * Parameter 1: content digest algorithm ([ContentDigestAlgorithm])
     *  * Parameter 2: hex-encoded expected digest of the APK (`String`)
     *  * Parameter 3: hex-encoded actual digest of the APK (`String`)
     *
     */
    V2_SIG_APK_DIGEST_DID_NOT_VERIFY(
        "APK integrity check failed. %1\$s digest mismatch."
                + " Expected: <%2\$s>, actual: <%3\$s>"
    ),
    /**
     * Failed to parse the list of signers contained in the APK Signature Scheme v3 signature.
     */
    V3_SIG_MALFORMED_SIGNERS("Malformed list of signers"),
    /**
     * Failed to parse this signer's signer block contained in the APK Signature Scheme v3
     * signature.
     */
    V3_SIG_MALFORMED_SIGNER("Malformed signer block"),
    /**
     * Public key embedded in the APK Signature Scheme v3 signature of this signer could not be
     * parsed.
     *
     *
     *  * Parameter 1: error details (`Throwable`)
     *
     */
    V3_SIG_MALFORMED_PUBLIC_KEY("Malformed public key: %1\$s"),
    /**
     * This APK Signature Scheme v3 signer's certificate could not be parsed.
     *
     *
     *  * Parameter 1: index (`0`-based) of the certificate in the signer's list of
     * certificates (`Integer`)
     *  * Parameter 2: sequence number (`1`-based) of the certificate in the signer's
     * list of certificates (`Integer`)
     *  * Parameter 3: error details (`Throwable`)
     *
     */
    V3_SIG_MALFORMED_CERTIFICATE("Malformed certificate #%2\$d: %3\$s"),
    /**
     * Failed to parse this signer's signature record contained in the APK Signature Scheme v3
     * signature.
     *
     *
     *  * Parameter 1: record number (first record is `1`) (`Integer`)
     *
     */
    V3_SIG_MALFORMED_SIGNATURE("Malformed APK Signature Scheme v3 signature record #%1\$d"),
    /**
     * Failed to parse this signer's digest record contained in the APK Signature Scheme v3
     * signature.
     *
     *
     *  * Parameter 1: record number (first record is `1`) (`Integer`)
     *
     */
    V3_SIG_MALFORMED_DIGEST("Malformed APK Signature Scheme v3 digest record #%1\$d"),
    /**
     * This APK Signature Scheme v3 signer contains a malformed additional attribute.
     *
     *
     *  * Parameter 1: attribute number (first attribute is `1`) `Integer`)
     *
     */
    V3_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE("Malformed additional attribute #%1\$d"),
    /**
     * APK Signature Scheme v3 signature contains no signers.
     */
    V3_SIG_NO_SIGNERS("No signers in APK Signature Scheme v3 signature"),
    /**
     * APK Signature Scheme v3 signature contains multiple signers (only one allowed per
     * platform version).
     */
    V3_SIG_MULTIPLE_SIGNERS(
        "Multiple APK Signature Scheme v3 signatures found for a single "
                + " platform version."
    ),
    /**
     * APK Signature Scheme v3 signature found, but multiple v1 and/or multiple v2 signers
     * found, where only one may be used with APK Signature Scheme v3
     */
    V3_SIG_MULTIPLE_PAST_SIGNERS(
        "Multiple signatures found for pre-v3 signing with an APK "
                + " Signature Scheme v3 signer.  Only one allowed."
    ),
    /**
     * APK Signature Scheme v3 signature found, but its signer doesn't match the v1/v2 signers,
     * or have them as the root of its signing certificate history
     */
    V3_SIG_PAST_SIGNERS_MISMATCH(
        "v3 signer differs from v1/v2 signer without proper signing certificate lineage."
    ),
    /**
     * This APK Signature Scheme v3 signer contains a signature produced using an unknown
     * algorithm.
     *
     *
     *  * Parameter 1: algorithm ID (`Integer`)
     *
     */
    V3_SIG_UNKNOWN_SIG_ALGORITHM("Unknown signature algorithm: %1$#x"),
    /**
     * This APK Signature Scheme v3 signer contains an unknown additional attribute.
     *
     *
     *  * Parameter 1: attribute ID (`Integer`)
     *
     */
    V3_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE("Unknown additional attribute: ID %1$#x"),
    /**
     * An exception was encountered while verifying APK Signature Scheme v3 signature of this
     * signer.
     *
     *
     *  * Parameter 1: signature algorithm ([SignatureAlgorithm])
     *  * Parameter 2: exception (`Throwable`)
     *
     */
    V3_SIG_VERIFY_EXCEPTION("Failed to verify %1\$s signature: %2\$s"),
    /**
     * The APK Signature Scheme v3 signer contained an invalid value for either min or max SDK
     * versions.
     *
     *
     *  * Parameter 1: minSdkVersion (`Integer`)
     *  * Parameter 2: maxSdkVersion (`Integer`)
     *
     */
    V3_SIG_INVALID_SDK_VERSIONS(
        "Invalid SDK Version parameter(s) encountered in APK Signature "
                + "scheme v3 signature: minSdkVersion %1\$s maxSdkVersion: %2\$s"
    ),
    /**
     * APK Signature Scheme v3 signature over this signer's signed-data block did not verify.
     *
     *
     *  * Parameter 1: signature algorithm ([SignatureAlgorithm])
     *
     */
    V3_SIG_DID_NOT_VERIFY("%1\$s signature over signed-data did not verify"),
    /**
     * This APK Signature Scheme v3 signer offers no signatures.
     */
    V3_SIG_NO_SIGNATURES("No signatures"),
    /**
     * This APK Signature Scheme v3 signer offers signatures but none of them are supported.
     */
    V3_SIG_NO_SUPPORTED_SIGNATURES("No supported signatures"),
    /**
     * This APK Signature Scheme v3 signer offers no certificates.
     */
    V3_SIG_NO_CERTIFICATES("No certificates"),
    /**
     * This APK Signature Scheme v3 signer's minSdkVersion listed in the signer's signed data
     * does not match the minSdkVersion listed in the signatures record.
     *
     *
     *  * Parameter 1: minSdkVersion in signature record (`Integer`)
     *  * Parameter 2: minSdkVersion in signed data (`Integer`)
     *
     */
    V3_MIN_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD(
        "minSdkVersion mismatch between signed data and signature record:"
                + " <%1\$s> vs <%2\$s>"
    ),
    /**
     * This APK Signature Scheme v3 signer's maxSdkVersion listed in the signer's signed data
     * does not match the maxSdkVersion listed in the signatures record.
     *
     *
     *  * Parameter 1: maxSdkVersion in signature record (`Integer`)
     *  * Parameter 2: maxSdkVersion in signed data (`Integer`)
     *
     */
    V3_MAX_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD(
        "maxSdkVersion mismatch between signed data and signature record:"
                + " <%1\$s> vs <%2\$s>"
    ),
    /**
     * This APK Signature Scheme v3 signer's public key listed in the signer's certificate does
     * not match the public key listed in the signatures record.
     *
     *
     *  * Parameter 1: hex-encoded public key from certificate (`String`)
     *  * Parameter 2: hex-encoded public key from signatures record (`String`)
     *
     */
    V3_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD(
        "Public key mismatch between certificate and signature record: <%1\$s> vs <%2\$s>"
    ),
    /**
     * This APK Signature Scheme v3 signer's signature algorithms listed in the signatures
     * record do not match the signature algorithms listed in the signatures record.
     *
     *
     *  * Parameter 1: signature algorithms from signatures record (`List<Integer>`)
     *  * Parameter 2: signature algorithms from digests record (`List<Integer>`)
     *
     */
    V3_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS(
        "Signature algorithms mismatch between signatures and digests records"
                + ": %1\$s vs %2\$s"
    ),
    /**
     * The APK's digest does not match the digest contained in the APK Signature Scheme v3
     * signature.
     *
     *
     *  * Parameter 1: content digest algorithm ([ContentDigestAlgorithm])
     *  * Parameter 2: hex-encoded expected digest of the APK (`String`)
     *  * Parameter 3: hex-encoded actual digest of the APK (`String`)
     *
     */
    V3_SIG_APK_DIGEST_DID_NOT_VERIFY(
        "APK integrity check failed. %1\$s digest mismatch."
                + " Expected: <%2\$s>, actual: <%3\$s>"
    ),
    /**
     * The signer's SigningCertificateLineage attribute containd a proof-of-rotation record with
     * signature(s) that did not verify.
     */
    V3_SIG_POR_DID_NOT_VERIFY(
        "SigningCertificateLineage attribute containd a proof-of-rotation"
                + " record with signature(s) that did not verify."
    ),
    /**
     * Failed to parse the SigningCertificateLineage structure in the APK Signature Scheme v3
     * signature's additional attributes section.
     */
    V3_SIG_MALFORMED_LINEAGE(
        "Failed to parse the SigningCertificateLineage structure in the "
                + "APK Signature Scheme v3 signature's additional attributes section."
    ),
    /**
     * The APK's signing certificate does not match the terminal node in the provided
     * proof-of-rotation structure describing the signing certificate history
     */
    V3_SIG_POR_CERT_MISMATCH(
        "APK signing certificate differs from the associated certificate found in the "
                + "signer's SigningCertificateLineage."
    ),
    /**
     * The APK Signature Scheme v3 signers encountered do not offer a continuous set of
     * supported platform versions.  Either they overlap, resulting in potentially two
     * acceptable signers for a platform version, or there are holes which would create problems
     * in the event of platform version upgrades.
     */
    V3_INCONSISTENT_SDK_VERSIONS(
        "APK Signature Scheme v3 signers supported min/max SDK "
                + "versions are not continuous."
    ),
    /**
     * The APK Signature Scheme v3 signers don't cover all requested SDK versions.
     *
     *
     *  * Parameter 1: minSdkVersion (`Integer`)
     *  * Parameter 2: maxSdkVersion (`Integer`)
     *
     */
    V3_MISSING_SDK_VERSIONS(
        "APK Signature Scheme v3 signers supported min/max SDK "
                + "versions do not cover the entire desired range.  Found min:  %1\$s max %2\$s"
    ),
    /**
     * The SigningCertificateLineages for different platform versions using APK Signature Scheme
     * v3 do not go together.  Specifically, each should be a subset of another, with the size
     * of each increasing as the platform level increases.
     */
    V3_INCONSISTENT_LINEAGES(
        "SigningCertificateLineages targeting different platform versions"
                + " using APK Signature Scheme v3 are not all a part of the same overall lineage."
    ),
    /**
     * APK Signing Block contains an unknown entry.
     *
     *
     *  * Parameter 1: entry ID (`Integer`)
     *
     */
    APK_SIG_BLOCK_UNKNOWN_ENTRY_ID("APK Signing Block contains unknown entry: ID %1$#x");

}

class IssueWithParams
/**
 * Constructs a new `IssueWithParams` of the specified type and with provided
 * parameters.
 */(
    /**
     * Returns the type of this issue.
     */
    val issue: Issue, private val mParams: Array<Any>
) {

    /**
     * Returns the parameters of this issue.
     */
    val params: Array<Any>
        get() = mParams.clone()

    /**
     * Returns a readable form of this issue.
     */
    override fun toString(): String {
        return String.format(issue.format, *mParams)
    }

}