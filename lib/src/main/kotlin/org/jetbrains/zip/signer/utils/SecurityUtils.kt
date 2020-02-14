package org.jetbrains.zip.signer.utils

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

object SecurityUtils {
    fun addBouncyCastleProviderIfMissing() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }
}