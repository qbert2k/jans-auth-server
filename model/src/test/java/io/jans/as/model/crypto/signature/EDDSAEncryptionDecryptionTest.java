/**
 * 
 */
package io.jans.as.model.crypto.signature;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.script.ScriptException;

import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.testng.Assert;
import org.testng.annotations.Test;

import io.jans.as.model.crypto.Certificate;
import io.jans.as.model.crypto.KeyFactory;
import io.jans.as.model.jws.EDDSASigner;
import io.jans.as.model.util.Base64Util;

/**
 * @author SMan
 *
 */
public class EDDSAEncryptionDecryptionTest {

    private static String DEF_CERTIFICATE_OWN = "CN=Test CA Certificate";
    private static String DEF_INPUT = "Hello World!";
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void someTest() throws ScriptException, NoSuchMethodException {
        System.out.println("++++++++++++++++++++++++++");
        System.out.println("someTest...");
        System.out.println("++++++++++++++++++++++++++");
        Assert.assertTrue(true);
    }

    @Test
    public void eddsa25519EncodingTest() throws ScriptException, NoSuchMethodException, InvalidParameterException,
            InvalidKeyException, CertificateEncodingException, NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, SignatureException, IOException, InvalidKeySpecException {

        KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> keyFactory = new EDDSAKeyFactory(SignatureAlgorithm.ED25519,
                DEF_CERTIFICATE_OWN);
        EDDSAPrivateKey eddsaPrivateKey = keyFactory.getPrivateKey();
        EDDSAPublicKey eddsaPublicKey = keyFactory.getPublicKey();
        Certificate certificate = keyFactory.getCertificate();

        byte[] privKeyDecoded = eddsaPrivateKey.getPrivateKeyDecoded();
        byte[] pubKeyDecoded = eddsaPublicKey.getPublicKeyDecoded();

        PKCS8EncodedKeySpec privateKeySpec = eddsaPrivateKey.getPrivateKeySpec();
        java.security.KeyFactory keyFactoryJava = java.security.KeyFactory
                .getInstance(SignatureAlgorithm.ED25519.getName());
        BCEdDSAPrivateKey bcEdDSAPrivateKey = (BCEdDSAPrivateKey) keyFactoryJava.generatePrivate(privateKeySpec);

        String bcEdDSAPrivateKeyDecoded = bcEdDSAPrivateKey.toString();

        Assert.assertTrue(true);
    }

    @Test
    public void eddsa488EncodingTest() throws ScriptException, NoSuchMethodException {
        Assert.assertTrue(true);
    }

}
