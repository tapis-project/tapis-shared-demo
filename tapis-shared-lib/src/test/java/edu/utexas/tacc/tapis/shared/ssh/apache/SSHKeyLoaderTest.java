package edu.utexas.tacc.tapis.shared.ssh.apache;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;

import org.testng.Assert;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

import static edu.utexas.tacc.tapis.shared.ssh.apache.SSHKeyLoader.ALG_EC;
import static edu.utexas.tacc.tapis.shared.ssh.apache.SSHKeyLoader.ALG_ED25519;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static edu.utexas.tacc.tapis.shared.ssh.apache.SSHKeyLoader.FORMAT_PKCS8;
import static edu.utexas.tacc.tapis.shared.ssh.apache.SSHKeyLoader.FORMAT_X509;
import static edu.utexas.tacc.tapis.shared.ssh.apache.SSHKeyLoader.ALG_RSA;

/**
 * Tests for methods in KeyLoader class.
 * Test loading of various keypairs from files.
 * Tests load the public and private keys from files and use them to create a java public-private KeyPair
 */
public class SSHKeyLoaderTest
{
  private static final String testUser = "testuser2"; // Not used in this test, but required value for KeyLoader
  private static final String testHost = "testhost"; // Not used in this test, but required value for KeyLoader

  @BeforeSuite
  public void setUp() { }

  @AfterSuite
  public void tearDown() { }

  /* ----------------------------------------------------------------------------------- */
  /* Test keys generated using ssh-keygen                                                */
  /* ----------------------------------------------------------------------------------- */
  /*
   * Test ssh-keygen RSA private key begins with -----BEGIN RSA PRIVATE KEY-----
   */
  @Test(groups={"unit"})
  public void testSshKeygenRSAKeyLegacy() throws Exception
  {
    runKeyTest("sshkeygen_rsa_pem.pub", "sshkeygen_rsa_pem", ALG_RSA, ALG_RSA, FORMAT_X509, FORMAT_PKCS8);
  }

  /*
   * Test ssh-keygen RSA keypair where private key begins with -----BEGIN OPENSSH PRIVATE KEY-----
   */
  @Test(groups={"unit"})
  public void testSshKeygenRSAKeyOpenSSH() throws Exception
  {
    runKeyTest("sshkeygen_rsa.pub", "sshkeygen_rsa", ALG_RSA, ALG_RSA, FORMAT_X509, FORMAT_PKCS8);
  }

  /*
   * Test ssh-keygen ED25519 keypair where private key begins with -----BEGIN OPENSSH PRIVATE KEY-----
   */
  @Test(groups={"unit"})
  public void testSshKeygenEd25519() throws Exception
  {
    runKeyTest("sshkeygen_ed25519.pub", "sshkeygen_ed25519", ALG_ED25519, ALG_ED25519, FORMAT_X509, FORMAT_PKCS8);
  }

//  /*
//   * Test ssh-keygen ECDSA keypair where private key begins with -----BEGIN OPENSSH PRIVATE KEY-----
//   */
//  @Test(groups={"unit"})
//  public void testSshKeygenEcdsa() throws Exception
//  {
//    Assert.fail("WIP");
//    runKeyTest("sshkeygen_ecdsa.pub", "sshkeygen_ecdsa", ALG_EC, ALG_EC, FORMAT_X509, FORMAT_PKCS8);
//  }
//
//  /* ----------------------------------------------------------------------------------- */
//  /* Test keys generated using openssl                                                   */
//  /* ----------------------------------------------------------------------------------- */
//  /*
//   * Test openssl RSA keypair where private key begins with -----BEGIN PRIVATE KEY-----
//   */
//  @Test(groups={"unit"})
//  public void testOpenSslRSAKey() throws Exception
//  {
//    runKeyTest("openssl_rsa.pub", "openssl_rsa", ALG_RSA, ALG_RSA, FORMAT_X509, FORMAT_PKCS8);
//  }
//
//  /*
//   * Test openssl EC keypair where private key begins with -----BEGIN EC PRIVATE KEY-----
//   */
//  @Test(groups={"unit"})
//  public void testOpenSslECKey() throws Exception
//  {
//    runKeyTest("openssl_ec.pub", "openssl_ec", ALG_EC, ALG_EC, FORMAT_X509, FORMAT_PKCS8);
//  }
//

  /* ----------------------------------------------------------------------------------- */
  /* Test keys generated using Trusted Management System (TMS)                           */
  /* ----------------------------------------------------------------------------------- */
  /*
   * Test TMS RSA keypair where private key begins with -----BEGIN OPENSSH PRIVATE KEY-----
   */
  @Test(groups={"unit"})
  public void testTmsRSA() throws Exception
  {
    runKeyTest("tms_rsa.pub", "tms_rsa", ALG_RSA, ALG_RSA, FORMAT_X509, FORMAT_PKCS8);
  }

  /*
   * Test TMS ED25519 keypair where private key begins with -----BEGIN OPENSSH PRIVATE KEY-----
   */
  @Test(groups={"unit"})
  public void testTmsEd25519() throws Exception
  {
    runKeyTest("tms_ed25519.pub", "tms_ed25519", ALG_ED25519, ALG_ED25519, FORMAT_X509, FORMAT_PKCS8);
  }

//  /*
//   * Test TMS EDCSA keypair where private key begins with -----BEGIN OPENSSH PRIVATE KEY-----
//   */
//  @Test(groups={"unit"})
//  public void testTmsEdcsa() throws Exception
//  {
//    Assert.fail("WIP");
//  }

  // ************************************************************************
  // **************************  Private Methods  ***************************
  // ************************************************************************

  /*
   * Each test very similar, just need the file names, expected key algorithms and formats
   */
  private void runKeyTest(String pubFile, String prvFile, String pubAlg, String prvAlg, String pubFormat, String prvFormat)
          throws Exception
  {
    String pubKeyStr = readKeyFromFile(pubFile);
    String prvKeyStr = readKeyFromFile(prvFile);
    // Initialize data for the key loader
    var keyLoader = new SSHKeyLoader(pubKeyStr, prvKeyStr, testUser, testHost);
    // Convert the incoming key pair into a java.security KeyPair
    // This routine attempts to detect the key type and encryption algorithm
    KeyPair keyPair = keyLoader.getKeyPair();
    // Verify keypair properties
    assertEquals(keyPair.getPublic().getAlgorithm(), pubAlg);
    assertEquals(keyPair.getPrivate().getAlgorithm(), prvAlg);
    assertEquals(keyPair.getPublic().getFormat(), pubFormat);
    assertEquals(keyPair.getPrivate().getFormat(), prvFormat);
  }

  /*
   * Read in a key from a resource file that is on the class path
   */
  private String readKeyFromFile(String fileName)
  {
    StringBuilder sb = new StringBuilder();
    String resourcePath = String.format("/edu/utexas/tacc/tapis/shared/ssh/apache/%s", fileName);
    try (InputStream inStream = getClass().getResourceAsStream(resourcePath))
    {
      assertNotNull(inStream, "InputStream was null for path: " + resourcePath);
      try (BufferedReader r = new BufferedReader(new InputStreamReader(inStream)))
      {
         String l;
         while ((l = r.readLine()) != null) sb.append(l).append("\n");
      }
    }
    catch (IOException e)
    {
      Assert.fail("IOException reading resource file: " + resourcePath + " Error: " + e.getMessage());
    }
    return sb.toString();
  }
}
