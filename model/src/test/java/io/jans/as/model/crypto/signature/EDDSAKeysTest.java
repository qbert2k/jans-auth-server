/**
 * 
 */
package io.jans.as.model.crypto.signature;

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
import java.security.spec.X509EncodedKeySpec;

import javax.script.ScriptException;

import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.Assert;
import org.testng.annotations.Test;

import io.jans.as.model.crypto.KeyFactory;

/**
 * 
 *
 * @author Sergey Manoylo
 * @version August 03, 2021
 */
public class EDDSAKeysTest {

    private static String DEF_CERTIFICATE_OWN = "CN=Test CA Certificate";
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    @Test
    public void eddsaKeys25519Test() throws InvalidParameterException, InvalidKeyException, CertificateEncodingException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, SignatureException {
        
        KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> keyFactory1 = new EDDSAKeyFactory(SignatureAlgorithm.ED25519,
                DEF_CERTIFICATE_OWN);
        
        KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> keyFactory2 = new EDDSAKeyFactory(SignatureAlgorithm.ED25519,
                DEF_CERTIFICATE_OWN);
        
        EDDSAPrivateKey privateKey1 = keyFactory1.getPrivateKey();
        EDDSAPublicKey publicKey1 = keyFactory1.getPublicKey();
        
        EDDSAPrivateKey privateKey2 = keyFactory2.getPrivateKey();
        EDDSAPublicKey publicKey2 = keyFactory2.getPublicKey();
        
        EDDSAPrivateKey privateKey1Clone = new EDDSAPrivateKey(privateKey1);
        EDDSAPublicKey publicKey1Clone =  new EDDSAPublicKey(publicKey1);
        
        Assert.assertTrue(privateKey1.equals(privateKey1Clone));        
        Assert.assertTrue(publicKey1.equals(publicKey1Clone));        

        Assert.assertFalse(privateKey1.equals(privateKey2));        
        Assert.assertFalse(publicKey1.equals(publicKey2));        
    }
    
    @Test
    public void eddsaKeys448Test() throws InvalidParameterException, InvalidKeyException, CertificateEncodingException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, SignatureException {
        
        KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> keyFactory1 = new EDDSAKeyFactory(SignatureAlgorithm.ED448,
                DEF_CERTIFICATE_OWN);
        
        KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> keyFactory2 = new EDDSAKeyFactory(SignatureAlgorithm.ED448,
                DEF_CERTIFICATE_OWN);
        
        EDDSAPrivateKey privateKey1 = keyFactory1.getPrivateKey();
        EDDSAPublicKey publicKey1 = keyFactory1.getPublicKey();
        
        EDDSAPrivateKey privateKey2 = keyFactory2.getPrivateKey();
        EDDSAPublicKey publicKey2 = keyFactory2.getPublicKey();
        
        EDDSAPrivateKey privateKey1Clone = new EDDSAPrivateKey(privateKey1);
        EDDSAPublicKey publicKey1Clone =  new EDDSAPublicKey(publicKey1);
        
        Assert.assertTrue(privateKey1.equals(privateKey1Clone));        
        Assert.assertTrue(publicKey1.equals(publicKey1Clone));        

        Assert.assertFalse(privateKey1.equals(privateKey2));        
        Assert.assertFalse(publicKey1.equals(publicKey2));        
    }    

    @Test
    public void eddsa25519EncodingTest() throws ScriptException, NoSuchMethodException, InvalidParameterException,
            InvalidKeyException, CertificateEncodingException, NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, SignatureException, IOException, InvalidKeySpecException {

        KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> keyFactory = new EDDSAKeyFactory(SignatureAlgorithm.ED25519,
                DEF_CERTIFICATE_OWN);

        EDDSAPrivateKey eddsaPrivateKey = keyFactory.getPrivateKey();
        EDDSAPublicKey eddsaPublicKey = keyFactory.getPublicKey();

        PKCS8EncodedKeySpec privateKeySpec = eddsaPrivateKey.getPrivateKeySpec();
        X509EncodedKeySpec publicKeySpec = eddsaPublicKey.getPublicKeySpec();
        
        java.security.KeyFactory keyFactoryJava = java.security.KeyFactory
                .getInstance(SignatureAlgorithm.ED25519.getName());
        BCEdDSAPrivateKey bcEdDSAPrivateKey = (BCEdDSAPrivateKey) keyFactoryJava.generatePrivate(privateKeySpec);
        BCEdDSAPublicKey bcEdDSAPublicKey = (BCEdDSAPublicKey) keyFactoryJava.generatePublic(publicKeySpec);
        
        EDDSAPrivateKey eddsaPrivateKeyNew = new EDDSAPrivateKey(SignatureAlgorithm.ED25519, bcEdDSAPrivateKey.getEncoded(), bcEdDSAPrivateKey.getPublicKey().getEncoded());
        EDDSAPublicKey eddsaPublicKeyNew = new EDDSAPublicKey(SignatureAlgorithm.ED25519, bcEdDSAPublicKey.getEncoded());
        
        Assert.assertTrue(eddsaPrivateKey.equals(eddsaPrivateKeyNew));
        Assert.assertTrue(eddsaPublicKey.equals(eddsaPublicKeyNew));
    }

    @Test
    public void eddsa488EncodingTest() throws ScriptException, NoSuchMethodException, InvalidParameterException,
            InvalidKeyException, CertificateEncodingException, NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, SignatureException, IOException, InvalidKeySpecException {

        KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> keyFactory = new EDDSAKeyFactory(SignatureAlgorithm.ED448,
                DEF_CERTIFICATE_OWN);

        EDDSAPrivateKey eddsaPrivateKey = keyFactory.getPrivateKey();
        EDDSAPublicKey eddsaPublicKey = keyFactory.getPublicKey();

        PKCS8EncodedKeySpec privateKeySpec = eddsaPrivateKey.getPrivateKeySpec();
        X509EncodedKeySpec publicKeySpec = eddsaPublicKey.getPublicKeySpec();
        
        java.security.KeyFactory keyFactoryJava = java.security.KeyFactory
                .getInstance(SignatureAlgorithm.ED448.getName());
        BCEdDSAPrivateKey bcEdDSAPrivateKey = (BCEdDSAPrivateKey) keyFactoryJava.generatePrivate(privateKeySpec);
        BCEdDSAPublicKey bcEdDSAPublicKey = (BCEdDSAPublicKey) keyFactoryJava.generatePublic(publicKeySpec);
        
        EDDSAPrivateKey eddsaPrivateKeyNew = new EDDSAPrivateKey(SignatureAlgorithm.ED448, bcEdDSAPrivateKey.getEncoded(), bcEdDSAPrivateKey.getPublicKey().getEncoded());
        EDDSAPublicKey eddsaPublicKeyNew = new EDDSAPublicKey(SignatureAlgorithm.ED448, bcEdDSAPublicKey.getEncoded());
        
        Assert.assertTrue(eddsaPrivateKey.equals(eddsaPrivateKeyNew));
        Assert.assertTrue(eddsaPublicKey.equals(eddsaPublicKeyNew));
    }
}

