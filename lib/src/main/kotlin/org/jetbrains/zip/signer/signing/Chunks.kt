package org.jetbrains.zip.signer.signing

import java.security.MessageDigest

fun getOffset(chunkIndex: Int, digest: MessageDigest) = 1 + 4 + chunkIndex * digest.digestLength