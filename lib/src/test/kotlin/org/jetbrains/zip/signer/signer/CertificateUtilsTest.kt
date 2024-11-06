package org.jetbrains.zip.signer.signer

import junit.framework.TestCase.assertEquals
import org.jetbrains.zip.signer.BaseTest
import org.junit.Test
import java.security.cert.X509CRL

class CertificateUtilsTest : BaseTest() {

    @Test(expected = IllegalArgumentException::class)
    fun `throw an exception if no revocation lists are found`() {
        CertificateUtils.getRevocationLists(getChain().certificates)
    }
    
    @Test
    fun `return an empty list if only the CA cert is provided`() {
        assertEquals(
            emptyList<X509CRL>(),
            CertificateUtils.getRevocationLists(getCACertificate().certificates)
        )
    }
}
