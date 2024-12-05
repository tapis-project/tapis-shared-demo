package edu.utexas.tacc.tapis.shared.ssh.apache;

import java.io.StringReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import org.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import edu.utexas.tacc.tapis.shared.exceptions.TapisSecurityException;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/** The purpose of this class is to taken raw key data from file or memory and
 * convert it to key objects used by the SSH subsystem.
 * 
 * Some of the code used by this class concerning PEM file parsing is based on code
 * from a public MasterCard repository with MIT license.
 * 
 * Source: https://github.com/Mastercard/client-encryption-java/blob/master/src/main/java/com/mastercard/developer/utils/EncryptionUtils.java
 *         https://stackoverflow.com/questions/7216969/getting-rsa-private-key-from-pem-base64-encoded-private-key-file/55339208#55339208
 *
 * Updated by scblack to support OPENSSH keys (PKCS#8) and add support for Ed25519 in addition to RSA
 * Additional sources: https://docs.chariot.io/display/CHAR2x/How+to+identify+my+Private+Key+type
 *                     https://superuser.com/questions/1515261/how-to-quickly-identify-ssh-private-key-file-formats
 *         PEM -       https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail
 * Read RSA Pkcs1 in Java - https://stackoverflow.com/questions/3243018/how-to-load-rsa-private-key-from-file
 *
 * // TODO
 * // TODO  From search on "java crypto ssh library ed25519 example"
 * // TODO  https://stackoverflow.com/questions/77460283/encoding-a-ed25519-public-key-to-ssh-format-in-java
 * // // TODO or maybe https://stackoverflow.com/questions/78279858/ssh-ed25519-string-to-public-key-in-java
 *
 * // OpenSSH private keys created on recent linux versions using ssh-keygen -t rsa -b 4096 begin with:
 * //    -----BEGIN OPENSSH PRIVATE KEY-----
 * //    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
 * // OpenSSH private keys created on recent linux versions using ssh-keygen -t ed25519 begin with:
 * //    -----BEGIN OPENSSH PRIVATE KEY-----
 * //    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
 * // OpenSSH private keys created on recent linux versions using ssh-keygen -t rsa -b 4096 -m pem begin with:
 * //    -----BEGIN RSA PRIVATE KEY-----
 * //    MIIJJwIBAAKCAgEAve9MgxjOm+QUgklmenSahsVKdkAQA0MiD2oXODVU/AEGspNf
 * // OpenSSH private keys created on recent linux versions using ssh-keygen -t ed25519 -m PEM begin with: (no change with PEM)
 * //    -----BEGIN OPENSSH PRIVATE KEY-----
 * //    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
 * // TODO Use Bouncy Castle methods to read in keys and convert to format required by java libraries.
 * //      See, e.g. https://downloads.bouncycastle.org/java/docs/bcprov-jdk15to18-javadoc/org/bouncycastle/jcajce/spec/OpenSSHPrivateKeySpec.html
 *
 * // TODO TODO REPLACE above examples with pointers to test files under resources, but keep here the linux command run to generate the keypair files.
 * // Example key pairs may be find in tapis-shared-java/tapis-shared-lib/src/test/resources/edu/utexas/tacc/tapis/shared/ssh/apache
 *  -------------------                                         ----------------    ----------
 *  Linux Command / TMS                                         Private key file    Header
 *  -------------------                                         ----------------    ----------
 * ssh-keygen -t rsa -m pem         (Legacy)                    sshkeygen_rsa_pem   -----BEGIN RSA PRIVATE KEY-----
 * ssh-keygen -t rsa                                            sshkeygen_rsa       -----BEGIN OPENSSH PRIVATE KEY-----
 * ssh-keygen -t ed25519                                        sshkeygen_ed25519   -----BEGIN OPENSSH PRIVATE KEY-----
 * ssh-keygen -t ecdsa                                          sshkeygen_ecdsa     -----BEGIN OPENSSH PRIVATE KEY-----
 * TMS rsa                                                      tms_rsa             -----BEGIN OPENSSH PRIVATE KEY-----
 * TMS ed25519                                                  tms_ed25519         -----BEGIN OPENSSH PRIVATE KEY-----
 * TMS ecdsa                                                    tms_ecdsa           -----BEGIN OPENSSH PRIVATE KEY-----
 * openssl genrsa -out ./file 2048                              openssl_rsa         -----BEGIN PRIVATE KEY-----
 * openssl ecparam -name prime256v1 -genkey -noout -out ./file  openssl_ec          -----BEGIN EC PRIVATE KEY-----
 *
 * // TODO RSA key headers
 * // https://stackoverflow.com/questions/20065304/differences-between-begin-rsa-private-key-and-begin-private-key
 * // https://web.archive.org/web/20140819203300/https://polarssl.org/kb/cryptography/asn1-key-structures-in-der-and-pem
 *
 *  TODO Extract public key from private key:
 *    https://stackoverflow.com/questions/77413281/extract-public-key-from-privatekeyinfo-with-bouncy-castle
 *
 * @author rcardone
 *
 * TODO NOTES:
 *   The provided private key must be in unencrypted PEM format starting with one of these headers
 *   "-----BEGIN RSA PRIVATE KEY-----" (RSA PKCS#1)
 *   "-----BEGIN PRIVATE KEY-----" (RSA PKCS#8)
 *   "-----BEGIN OPENSSH PRIVATE KEY-----" (OpenSSH PKCS#8)
 *
 */
public class SSHKeyLoader 
{
    /* ********************************************************************** */
    /*                               Constants                                */
    /* ********************************************************************** */
    // PEM file markers.  The first 4 are generated by openssl, the last 2 by
    // ssh-keygen.  This class only supports the openssl formats.
    public static final String ALG_RSA = "RSA";
    public static final String ALG_ED25519 = "Ed25519";
    public static final String ALG_EC = "EC";
    private static final String KEYFACTORY_ALG_DEFAULT = ALG_RSA;
    private static final String PKCS_1_PEM_RSA_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String PKCS_1_PEM_RSA_FOOTER = "-----END RSA PRIVATE KEY-----";
    private static final String PKCS_8_PEM_RSA_HEADER = "-----BEGIN PRIVATE KEY-----"; // openssl generated key
    private static final String PKCS_8_PEM_RSA_FOOTER = "-----END PRIVATE KEY-----";
    private static final String PKCS_8_PEM_EC_HEADER =  "-----BEGIN EC PRIVATE KEY-----"; // openssl generated key
    private static final String PKCS_8_PEM_EC_FOOTER =  "-----END EC PRIVATE KEY-----";
    private static final String OPENSSH_PEM_HEADER =    "-----BEGIN OPENSSH PRIVATE KEY-----";
    private static final String OPENSSH_PEM_FOOTER =    "-----END OPENSSH PRIVATE KEY-----";
    public static final String FORMAT_X509 = "X.509";
    public static final String FORMAT_PKCS8 = "PKCS#8";

    /* ********************************************************************** */
    /*                                Fields                                  */
    /* ********************************************************************** */
    // Inputs.
    private final String _privateKey;
    private final String _publicKey;
    private final String _host;
    private final String _username;


    // We will use BouncyCastle for the ssh-key processing, so make sure we register the provider.
    static { Security.addProvider(new BouncyCastleProvider()); }

    /* ********************************************************************** */
    /*                            Constructors                                */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* constructor:                                                           */
    /* ---------------------------------------------------------------------- */
    public SSHKeyLoader(String publicKey, String privateKey, String user, String host)
    {
        _publicKey  = publicKey;  
        _privateKey = privateKey;
        _username   = user;
        _host       = host;
    }
    
    /* ********************************************************************** */
    /*                            Public Methods                              */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* getKeyPair:                                                            */
    /* ---------------------------------------------------------------------- */
    public KeyPair getKeyPair() throws TapisSecurityException
    {
        // Get keypair using code specific to format as determined by private key header.
        String privateKeyDataString = _privateKey;
        if (privateKeyDataString.startsWith(PKCS_1_PEM_RSA_HEADER)) return getRSAPKCS1KeyPair();
        else if (privateKeyDataString.startsWith(OPENSSH_PEM_HEADER)) return getOpenSSHKeyPair();
////        else if (privateKeyDataString.startsWith(PKCS_8_PEM_RSA_HEADER)) return getRSAPKCS8KeyPair();
////        else if (privateKeyDataString.startsWith(PKCS_8_PEM_EC_HEADER)) return getOpenSslECKeyPair();
        throw new IllegalArgumentException("ERROR: Key format not supported. First 24 characters from key: " + privateKeyDataString.substring(0, 24));
//        var prvKey = getPrivateKey();
//        var pubKey = getPublicKey(prvKey);
//
//        // Assign key pair.
//        KeyPair keyPair = new KeyPair(pubKey, prvKey);
//        return keyPair;
    }
    public KeyPair getKeyPair_legacy()
      throws TapisSecurityException
    {
        // Get each key using their own specialized code.
        var prvKey = getPrivateKey_legacy();
        var pubKey = getRSAPKCS1PublicKey(prvKey);
        
        // Assign key pair.
        KeyPair keyPair = new KeyPair(pubKey, prvKey);
        return keyPair;
    }
    
    /* ********************************************************************** */
    /*                            Private Methods                             */
    /* ********************************************************************** */
    /*
     * PKCS#1 format (RSA)
     * Convert the provided PEM encoded private+public keys into a java.security PrivateKey+PublicKey pair
     */
    private KeyPair getRSAPKCS1KeyPair() throws TapisSecurityException
    {
        // Strip out header and footer, remaining should be base64 encoded data in RSA PKCS#1 format
        String keyDataString = _privateKey.replace(PKCS_1_PEM_RSA_HEADER, "");
        keyDataString = keyDataString.replace(PKCS_1_PEM_RSA_FOOTER, "");
        // Strip out line separator characters
        keyDataString = replaceAllCRLF(keyDataString, "").trim();
        PrivateKey privateKey = readPkcs1PrivateKey(base64Decode(keyDataString, "private"));
        PublicKey publicKey = getRSAPKCS1PublicKey(privateKey); // TODO - refactor using bouncycastle?
        return new KeyPair(publicKey, privateKey);
    }

    /*
     * PKCS#8 format OpenSSH
     * Convert the provided PEM encoded private+public keys into a java.security PrivateKey+PubliKey pair
     */
    private KeyPair getOpenSSHKeyPair() throws TapisSecurityException
    {
        PrivateKey privateKey;
        PublicKey publicKey;
        //TODO remove Strip out header and footer, remaining should be base64 encoded data in OpenSSH PKCS#8 format
//        String keyDataString = _privateKey.replace(OPENSSH_PEM_HEADER, "");
//        keyDataString = keyDataString.replace(OPENSSH_PEM_FOOTER, "");
        // Strip out line separator characters and replace with newline character.
        String prvKeyDataString = replaceAllCRLF(_privateKey, "\n").trim();
        String pubKeyDataString = replaceAllCRLF(_publicKey, "\n").trim();
        publicKey = getPublicKeyFromStr(pubKeyDataString);
        String alg = publicKey.getAlgorithm();

//TODO        PrivateKey privateKey = readPkcs1PrivateKey(base64Decode(keyDataString, "private"));
//        PublicKey publicKey = getRSAPKCS1PublicKey(privateKey); // TODO - refactor using bouncycastle?
//        return new KeyPair(publicKey, privateKey);
        // TODO: Use BouncyCastle utility to read the pem encoded data in the private key
        // The utility strips off the header/footer and decodes the body into a binary format
        var prvPemReader = new PemReader(new StringReader(prvKeyDataString));
        try {
            KeyFactory kf = KeyFactory.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
            // TODO Update to handle ecdsa type keys. Use PEMParser?
            PemObject pemObjPR = prvPemReader.readPemObject();
            byte[] content = pemObjPR.getContent();
            var privKeySpec = new PKCS8EncodedKeySpec(content);
            OpenSSHPrivateKeySpec ks = new OpenSSHPrivateKeySpec(content);
            String format = ks.getFormat();
            privateKey = kf.generatePrivate(ks);

//                KeyFactory kf;
//                if ("ASN.1".equals(format)) kf = KeyFactory.getInstance(KEYFACTORY_ALG_RSA);
//                else if ("OpenSSH".equals(format)) kf = KeyFactory.getInstance(KEYFACTORY_ALG_ED25519);
//                KeyFactory kf = KeyFactory.getInstance(KEYFACTORY_ALG_ED25519);
//TODO            privateKey = kf.generatePrivate(ks);
//            publicKey = kf.generatePublic(ks);
//            publicKey = kf.generatePublic(ksPub);
            // Remove any non-key material from the key strings.
//            byte[] pubContent = base64Decode(trimKeyMaterial(_publicKey), "public");
//            OpenSSHPublicKeySpec ksPub = new OpenSSHPublicKeySpec(pubContent);
//TODO remove            publicKey = kf.generatePublic(ksPub);

            return new KeyPair(publicKey, privateKey);

            // TODO/TBD Use PemReader or this code using PEMParser?
//            PEMParser pemParser = new PEMParser(new StringReader(prvKeyDataString));
//            var kpObj = pemParser.readObject();
//            KeyPair kp = converter.getKeyPair((PEMKeyPair) kpObj);
//            return kp;
        }
        catch (Exception e)
        {
            throw new TapisSecurityException(e.getMessage(), e);
        }
    }

    /* ---------------------------------------------------------------------- */
    /* getPrivateKey:                                                         */
    /* ---------------------------------------------------------------------- */
    private PrivateKey getPrivateKey_legacy() throws TapisSecurityException
    {
        // PKCS#1 format.
        String keyDataString = _privateKey;
        if (keyDataString.startsWith(PKCS_1_PEM_RSA_HEADER)) {
            // OpenSSL / PKCS#1 Base64 PEM encoded file
            keyDataString = keyDataString.replace(PKCS_1_PEM_RSA_HEADER, "");
            keyDataString = keyDataString.replace(PKCS_1_PEM_RSA_FOOTER, "");
            keyDataString = keyDataString.replaceAll("\n", "").trim();
            return readPkcs1PrivateKey(base64Decode(keyDataString, "private"));
        }

        // PKCS#8 format.
        if (keyDataString.startsWith(PKCS_8_PEM_RSA_HEADER)) {
            // PKCS#8 Base64 PEM encoded file
            keyDataString = keyDataString.replace(PKCS_8_PEM_RSA_HEADER, "");
            keyDataString = keyDataString.replace(PKCS_8_PEM_RSA_FOOTER, "");
            keyDataString = keyDataString.replaceAll("\n", "").trim();
            return readPkcs8PrivateKey(base64Decode(keyDataString, "private"));
        }

        // Openssh format not supported.
        if (keyDataString.startsWith(OPENSSH_PEM_HEADER)) {
            throw new IllegalArgumentException("ERROR: Keys generated using ssh-keygen that start with \""
                                               + OPENSSH_PEM_HEADER + "\" are not supported.");
        }

        // We assume it's a PKCS#8 DER encoded binary file
        return readPkcs8PrivateKey(base64Decode(keyDataString, "private"));
    }
    
    /* ---------------------------------------------------------------------- */
    /* getPublicKey:                                                          */
    /* ---------------------------------------------------------------------- */
    private PublicKey getRSAPKCS1PublicKey(PrivateKey privateKey) throws TapisSecurityException
    {
//        // TODO assume ed25519 or rsa-ssh
//        var rawPub = _publicKey.split(" ")[1];
//        try {
//            OpenSSHPublicKeySpec pubSpec = new OpenSSHPublicKeySpec(base64Decode(rawPub, "public"));
////            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(base64Decode(rawPub, "public"));
//            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(base64Decode(rawPub, "public"));
//            KeyFactory kf;
//            if ("ssh-rsa".equals(pubSpec.getType())) kf = KeyFactory.getInstance(KEYFACTORY_ALG_RSA);
//            else kf = KeyFactory.getInstance(KEYFACTORY_ALG_ED25519);
////            var kf = KeyFactory.getInstance(KEYFACTORY_ALG_ED25519);
////            PublicKey pk = kf.generatePublic(pubSpec);
//            PublicKey pk = kf.generatePublic(keySpec);
//            return pk;
//        } catch (Exception e) { throw new TapisSecurityException(e.getMessage(), e); }
//
        // Derive the public key from the private key if necessary.
        PublicKey derivedKey =  derivePublicKey(privateKey);
        if (derivedKey != null) return derivedKey;

        // Remove any non-key material from the key strings.
        String trimmedPublic = trimKeyMaterial(_publicKey);

        // Decode the key material into binary.
        byte[] publicBytes = base64Decode(trimmedPublic,  "public");

        // Make into keys.
        return makeRsaPublicKey(publicBytes);
    }
    
    /* ---------------------------------------------------------------------- */
    /* derivePublicKey:                                                       */
    /* ---------------------------------------------------------------------- */
    private PublicKey derivePublicKey(PrivateKey privateKey) 
     throws TapisSecurityException
    {
        // We only derive the public key when we have to because we won't be
        // able to parse it.  This includes cases where the public rsa key was 
        // generated with ssh-keygen and starts with "ssh-rsa". 
        if (_publicKey.startsWith("-----BEGIN ") || 
            !(privateKey instanceof RSAPrivateCrtKey))
            return null;
        
        try {
            // Safe because of previous check.
            RSAPrivateCrtKey privk = (RSAPrivateCrtKey) privateKey;

            // Get the public key spec from the private key values.
            RSAPublicKeySpec publicKeySpec = 
                new RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());

            // Generate the public key from the spec.
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new TapisSecurityException(e.getMessage(), e);
        }
    }
    
    /* ---------------------------------------------------------------------- */
    /* readPkcs1PrivateKey:                                                   */
    /* ---------------------------------------------------------------------- */
    private PrivateKey readPkcs1PrivateKey(byte[] pkcs1Bytes) 
     throws TapisSecurityException
    {
        // We can't use Java internal APIs to parse ASN.1 structures, 
        // so we build a PKCS#8 key Java can understand.
        int pkcs1Length = pkcs1Bytes.length;
        int totalLength = pkcs1Length + 22;
        byte[] pkcs8Header = new byte[] {
            0x30, (byte) 0x82, (byte) ((totalLength >> 8) & 0xff), (byte) (totalLength & 0xff), // Sequence + total length
            0x2, 0x1, 0x0, // Integer (0)
            0x30, 0xD, 0x6, 0x9, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0xD, 0x1, 0x1, 0x1, 0x5, 0x0, // Sequence: 1.2.840.113549.1.1.1, NULL
            0x4, (byte) 0x82, (byte) ((pkcs1Length >> 8) & 0xff), (byte) (pkcs1Length & 0xff) // Octet string + length
        };
        byte[] pkcs8bytes = join(pkcs8Header, pkcs1Bytes);
        return readPkcs8PrivateKey(pkcs8bytes);
    }

    /* ---------------------------------------------------------------------- */
    /* readPkcs8PrivateKey:                                                   */
    /* ---------------------------------------------------------------------- */
    private PrivateKey readPkcs8PrivateKey(byte[] pkcs8Bytes)
            throws TapisSecurityException
    {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
            return keyFactory.generatePrivate(keySpec);
        }
        catch (Exception e) {throw new TapisSecurityException(e.getMessage(), e);}
    }

    /* ---------------------------------------------------------------------- */
    /* join:                                                                  */
    /* ---------------------------------------------------------------------- */
    private byte[] join(byte[] byteArray1, byte[] byteArray2)
    {
        byte[] bytes = new byte[byteArray1.length + byteArray2.length];
        System.arraycopy(byteArray1, 0, bytes, 0, byteArray1.length);
        System.arraycopy(byteArray2, 0, bytes, byteArray1.length, byteArray2.length);
        return bytes;
    }
    
    /* ---------------------------------------------------------------------- */
    /* trimKeyMaterial:                                                       */
    /* ---------------------------------------------------------------------- */
    /** Extract the key material from the encoded format and remove all newline
     * characters.
     * 
     * @param encodedKey the key in PEM or other encodings.
     * @return trimmed string
     */
    private String trimKeyMaterial(String encodedKey)
    {
        // Remove prologue and epilogue if they exist.  For example, public
        // keys stored in PEM format have a prologue and epilogue (see
        // https://tools.ietf.org/html/rfc1421 for the specification):
        //
        //      "-----BEGIN PUBLIC KEY-----\n"
        //      "\n-----END PUBLIC KEY-----"
        //
        // In general, different messages can appear after the BEGIN and END text,
        // so stripping out the prologue and epilogue requires some care.  The  
        // approach below handles only unix-style line endings.  
        // 
        // Check for unix style prologue.
        int index = encodedKey.indexOf("-\n");
        if (index > 0) encodedKey = encodedKey.substring(index + 2);
        
        // Check for unix style epilogue.
        index = encodedKey.lastIndexOf("\n-");
        if (index > 0) encodedKey = encodedKey.substring(0, index);
        
        return encodedKey.replaceAll("\n", "").trim();
    }

    /* ---------------------------------------------------------------------- */
    /* base64Decode:                                                          */
    /* ---------------------------------------------------------------------- */
    private byte[] base64Decode(String base64, String keyDesc)
     throws TapisSecurityException
    {
        // Try to decode the key.
        try {return Base64.getDecoder().decode(base64);}
        catch (Exception e) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_SSH_KEY_DECODE",
                                         _username, _host, keyDesc);
            throw new TapisSecurityException(msg, e);
        }
    }
    
    /* ---------------------------------------------------------------------- */
    /* makeRsaPublicKey:                                                      */
    /* ---------------------------------------------------------------------- */
    private RSAPublicKey makeRsaPublicKey(byte[] bytes)
     throws TapisSecurityException
    {
        Object obj = null;
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            obj = keyFactory.generatePublic(keySpec);
        }
        catch (Exception e) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_SSH_KEY_CREATE", 
                                         _username, _host, "public",
                                         e.getMessage());
            throw new TapisSecurityException(msg, e);
        }
        
        return (RSAPublicKey) obj;
    }

    /*
     * Use BouncyCastle ot derive the public key from the private key.
     * NOTE: This should work on TMS and ssh-keygen keys, but not yet openssl generated keys.
     * Based on this example:
     *   https://stackoverflow.com/questions/77413281/extract-public-key-from-privatekeyinfo-with-bouncy-castle
     */
    private PublicKey getPublicKeyFromStr(String pubKeyStr) throws TapisSecurityException
    {
        if (StringUtils.isBlank(pubKeyStr))
        {
            throw new TapisSecurityException("ERROR Empty public key string");
        }
        PublicKey pubKey;
        // String should have 2 or 3 whitespace separated parts, e.g.
        //    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAA...MHcDDMBqoeI/k= scblack@tacc
        //    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG...22U5qZ2uKeNC3E scblack@tacc
        //    ssh-ed25519 AAAAC3NzaC1lZDI1NT...c9JcO+Lks
        //    ecdsa-sha2-nistp521 AAAAE2VjZHNhLX...0x+zI5l576gVw==
        //
        // Split into parts based on whitespace and validate number of parts
        String[] keyParts = pubKeyStr.split("\\s+");
        if (keyParts.length > 3 || keyParts.length < 2)
        {
            String msg = String.format("ERROR Invalid number of key parts for public key. Number: %d Key: %s", keyParts.length, pubKeyStr);
            throw new TapisSecurityException(msg);
        }
        // Decode key data
        byte[] decodedKey = base64Decode(keyParts[1], "public");
        var pubKeySpec = new OpenSSHPublicKeySpec(decodedKey);

        KeyFactory kf;
        try
        {
            // Get relevant key factory
            if (keyParts[0].equals("ssh-rsa")) kf = KeyFactory.getInstance(ALG_RSA);
            else if (keyParts[0].equals("ssh-ed25519")) kf = KeyFactory.getInstance(ALG_ED25519);
            else if (keyParts[0].startsWith("ecdsa")) kf = KeyFactory.getInstance(ALG_EC, "BC");
            else
            {
                String msg = String.format("ERROR Invalid key algorithm for public key. Algorithm: %s Key: %s", keyParts[0], pubKeyStr);
                throw new TapisSecurityException(msg);
            }
            // Generate the public key
            pubKey = kf.generatePublic(pubKeySpec);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e)
        {
            throw new TapisSecurityException(e.getMessage(), e);
        }
        return pubKey;
    }

    /*
     * Strip out line separator characters of various combinations and replace with specified string.
     * Generally specified string will be the empty string or the linefeed character "\n".
     * Used to better handle various cut/paste operations that can result in a key string containing
     *   binary newline and carriage-return characters or character strings containing backslashes.
     * Replace: "\r\n", "\n", "\\r\\n", "\\n" with given string
     */
    private static String replaceAllCRLF(String keyStr, String replacementStr)
    {
        String retStr = keyStr.replaceAll("\r\n",replacementStr);
        retStr = retStr.replaceAll("\n",replacementStr);
        retStr = retStr.replaceAll("\\r\\n",replacementStr);
        retStr = retStr.replaceAll("\\n",replacementStr);
        return retStr;
    }
}
