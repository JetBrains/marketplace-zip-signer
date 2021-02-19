package org.jetbrains.zip.signer.signing

import org.jetbrains.zip.signer.BaseTest
import org.jetbrains.zip.signer.signer.CertificateUtils
import org.jetbrains.zip.signer.utils.CertificateChain
import org.junit.Assert
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.rules.TestName
import java.io.FileInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL

class CRLTest : BaseTest() {
  @get:Rule
  var testName = TestName()

  @get:Rule
  var expectedFailure = ExpectedException.none()!!

  /*
  * A -> B -> C
  *
  * Sign with chain of valid certs: C-B-A, verify with CRL for B and A
  * */
  @Test
  fun `sign than verify with crl`() {
    val testFileContent = testName.methodName
    val chain = getValidCertificateChain()
    val crls = listOf(getCRLForValidCert(), getRootCRL())

    createZipAndSignWithChain(testFileContent, chain).apply {
      verifyZip(testFileContent)
      Assert.assertTrue(isSignedBy(getRootCA(), crls))
    }
  }

  /*
  * A -> B -> C
  *
  * Sign with chain of valid certs: C-B-A, verify with CRL for A and B
  * */
  @Test(expected = IllegalArgumentException::class)
  fun `sign than verify with crls in wrong order`() {
    val testFileContent = testName.methodName
    val chain = getValidCertificateChain()
    val crls = listOf(getRootCRL(), getCRLForValidCert())

    createZipAndSignWithChain(testFileContent, chain).apply {
      verifyZip(testFileContent)
      Assert.assertTrue(isSignedBy(getRootCA(), crls))
    }
  }

  /*
  * A -> B -> C
  *   -> D
  * Sign with chain of valid certs: C-B-A, verify with CRL for D and A
  * */
  @Test(expected = IllegalArgumentException::class)
  fun `sign than verify with wrong crl`() {
    val testFileContent = testName.methodName
    val chain = getValidCertificateChain()
    val crls = listOf(getCRLForRevokedCert(), getRootCRL())

    createZipAndSignWithChain(testFileContent, chain).apply {
      verifyZip(testFileContent)
      Assert.assertFalse(isSignedBy(getRootCA(), crls))
    }
  }

  /*
  * A -> B*
  *
  * Sign with chain with revoked cert: B*-A, verify with CRL for A
  * */
  @Test
  fun `sign with revoked than verify with root crl`() {
    val testFileContent = testName.methodName
    val chain = getRevokedCertificateChain()
    val crls = listOf(getRootCRL())

    createZipAndSignWithChain(testFileContent, chain).apply {
      verifyZip(testFileContent)
      Assert.assertFalse(isSignedBy(getRootCA(), crls))
    }
  }

  /*
  * A -> B*
  *
  * Sign with chain with revoked cert: B*-A, verify with CRL for B*
  * */
  @Test(expected = IllegalArgumentException::class)
  fun `sign with revoked than verify with revoked (own) crl`() {

    val testFileContent = testName.methodName
    val chain = getRevokedCertificateChain()
    val crls = listOf(getCRLForRevokedCert())

    createZipAndSignWithChain(testFileContent, chain).apply {
      verifyZip(testFileContent)
      Assert.assertFalse(isSignedBy(getRootCA(), crls))
    }
  }

  /*
  * A -> B*
  *
  * Sign with chain with revoked cert: B*-A, verify without any CRL
  * */
  @Test
  fun `sign with revoked than verify without crl`() {
    val testFileContent = testName.methodName
    val chain = getRevokedCertificateChain()

    createZipAndSignWithChain(testFileContent, chain).apply {
      verifyZip(testFileContent)
      Assert.assertTrue(isSignedBy(getRootCA()))
    }
  }

  /*
  * A -> B* -> C
  *
  * Sign with chain with intermediate revoked cert: C-B*-A, verify with CRL for B* and A
  * */
  @Test
  fun `sign with valid cert signed by revoked (in root crl) than verify with crl`() {
    val testFileContent = testName.methodName
    val chain = getChainWithRevokedIntermediateCert()
    val crls = listOf(getCRLForRevokedCert(), getRootCRL())

    createZipAndSignWithChain(testFileContent, chain).apply {
      verifyZip(testFileContent)
      Assert.assertFalse(isSignedBy(getRootCA(), crls))
    }
  }

  /*
  * A -> B -> C*
  *
  * Sign with chain with revoked (revoked in B) cert: C*-B-A, verify with CRL for B and A
  * */
  @Test
  fun `sign with revoked (in intermediate crl) cert signed by valid than verify crl`() {
    val testFileContent = testName.methodName
    val chain = getRevokedChainWithValidIntermediate()
    val crls = listOf(getCRLForValidCert(), getRootCRL())

    createZipAndSignWithChain(testFileContent, chain).apply {
      verifyZip(testFileContent)
      Assert.assertFalse(isSignedBy(getRootCA(), crls))
    }
  }

  private fun getRevokedCertificateChain() = CertificateChain(
    certs = listOf(
      getResourceFile("crl/revokedChain/revoked.crt"),
      getResourceFile("crl/root/rootCA.crt"),
    ),
    privateKeyFile = getResourceFile("crl/revokedChain/revoked.key")
  )

  private fun getChainWithRevokedIntermediateCert() = CertificateChain(
    certs = listOf(
      getResourceFile("crl/revokedChain/valid_with_revoked_parent.crt"),
      getResourceFile("crl/revokedChain/revoked.crt"),
      getResourceFile("crl/root/rootCA.crt"),
    ),
    privateKeyFile = getResourceFile("crl/revokedChain/valid_with_revoked_parent.key")
  )

  private fun getRevokedChainWithValidIntermediate() = CertificateChain(
    certs = listOf(
      getResourceFile("crl/validChain/revoked_with_valid_parent.crt"),
      getResourceFile("crl/validChain/valid.crt"),
      getResourceFile("crl/root/rootCA.crt"),
    ),
    privateKeyFile = getResourceFile("crl/validChain/revoked_with_valid_parent.key")
  )

  private fun getValidCertificateChain() = CertificateChain(
    certs = listOf(
      getResourceFile("crl/validChain/valid2.crt"),
      getResourceFile("crl/validChain/valid.crt"),
      getResourceFile("crl/root/rootCA.crt"),
    ),
    privateKeyFile = getResourceFile("crl/validChain/valid2.key")
  )

  private fun getRootCA() = CertificateUtils.loadCertificatesFromFile(
    getResourceFile("crl/root/rootCA.crt"),
  ).first()

  private fun getRootCRL(): X509CRL {
    FileInputStream(getResourceFile("crl/root/root_crl.crl")).use { inStream ->
      val cf = CertificateFactory.getInstance("X.509")
      return cf.generateCRL(inStream) as X509CRL
    }
  }

  private fun getCRLForRevokedCert(): X509CRL {
    FileInputStream(getResourceFile("crl/revokedChain/revoked.crl")).use { inStream ->
      val cf = CertificateFactory.getInstance("X.509")
      return cf.generateCRL(inStream) as X509CRL
    }
  }

  private fun getCRLForValidCert(): X509CRL {
    FileInputStream(getResourceFile("crl/validChain/valid.crl")).use { inStream ->
      val cf = CertificateFactory.getInstance("X.509")
      return cf.generateCRL(inStream) as X509CRL
    }
  }
}