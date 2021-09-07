/**
 * 
 */
package io.jans.as.server.comp;

import static org.testng.Assert.assertTrue;
import static io.jans.as.model.jwk.JWKParameter.JSON_WEB_KEY_SET;
import static org.testng.Assert.assertNotNull;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONObject;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.model.crypto.AuthCryptoProvider;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jwk.JSONWebKey;
import io.jans.as.model.jwk.JSONWebKeySet;
import io.jans.as.model.jwt.Jwt;
import io.jans.as.model.jwt.JwtVerifyer;
import io.jans.as.model.util.JwtUtil;
import io.jans.as.server.BaseTest;
import io.jans.as.server.model.token.JwtSigner;

/**
 * @author Sergey Manoylo
 * @version September 7, 2021 
 *
 */
public class JwtSignerVerifyerTest extends BaseTest {
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    private JSONWebKeySet jwks = new JSONWebKeySet();    

    @Parameters({ "jwksFile" })    
    @BeforeTest
    public void initTestSuite(final String jwksFile) throws IOException {

        String jwksStr = null;
        
        try (FileInputStream fis = new FileInputStream(jwksFile)) {
            byte [] data = new byte[fis.available()];
            fis.read(data);
            jwksStr = new String(data); 
        } catch (FileNotFoundException e) {
            throw e;
        } catch (IOException e) {
            throw e;
        }
        
        assertNotNull(jwksStr);
        
        JSONObject jwksJObj = JwtUtil.fromJson(jwksStr);

        List<JSONWebKey> keyArrayList = new ArrayList<JSONWebKey>();
        
        JSONArray jwksJKeys = jwksJObj.getJSONArray(JSON_WEB_KEY_SET);
        
        for(int i = 0; i < jwksJKeys.length(); i++) {
            JSONObject jsonObj = jwksJKeys.getJSONObject(i);
            JSONWebKey jsonWebKey = JSONWebKey.fromJSONObject(jsonObj);
            keyArrayList.add(jsonWebKey);
            
        }
        
        assertTrue(keyArrayList.size() > 0);
        
        jwks.setKeys(keyArrayList);                
    }
    
    @Parameters({ "userSecret", "dnName", "keyStoreFile", "keyStoreSecret"})
    @Test
    public void signerVerifyerTest(final String userSecret, final String dnName, final String keyStoreFile, final String keyStoreSecret) throws Exception {
        
        showTitle("signerVerifyerTest");
        
        for(SignatureAlgorithm signatureAlgorithm : SignatureAlgorithm.values()) {
            if(SignatureAlgorithm.NONE.equals(signatureAlgorithm)) {
                continue;
            }
            try {
                AppConfiguration appConfiguration = new AppConfiguration();
                AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
                
                JwtSigner jwtSigner = null;
                if(AlgorithmFamily.HMAC.equals(signatureAlgorithm.getFamily())) {
                    jwtSigner = new JwtSigner(appConfiguration, jwks, signatureAlgorithm, dnName, userSecret);
                } else {
                    jwtSigner = new JwtSigner(appConfiguration, jwks, signatureAlgorithm, dnName);                    
                }                
                
                jwtSigner.setCryptoProvider(cryptoProvider);
                
                Jwt jwt = jwtSigner.newJwt();
                jwt.getClaims().setSubjectIdentifier("testing");
                jwt.getClaims().setIssuer("https:devgluu.saminet.local");
                jwt = jwtSigner.sign();
                
                JwtVerifyer jwtVerifyer = new JwtVerifyer(cryptoProvider, jwks.toJSONObject());
                
                if(AlgorithmFamily.HMAC.equals(signatureAlgorithm.getFamily())) {
                    assertTrue(jwtVerifyer.verifyJwt(jwt, userSecret));
                } else {
                    assertTrue(jwtVerifyer.verifyJwt(jwt));                    
                }

            } catch (Exception e) {
                System.out.println("Error (signerVerifyerTest) : " + " signatureAlgorithm = " + 
                        signatureAlgorithm + " message: " + e.getMessage());
                assertTrue(false);
            }
        }                
    }    

}
