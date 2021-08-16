/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.server.comp;

import static io.jans.eleven.model.GenerateKeyResponseParam.KEY_ID;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.UUID;

import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.json.JSONObject;
import org.testng.annotations.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.ECDSA;

import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.model.crypto.AbstractCryptoProvider;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jwk.Algorithm;
import io.jans.as.model.jwk.Use;
import io.jans.as.model.util.Base64Util;
import io.jans.as.model.util.Util;
import io.jans.as.server.ConfigurableTest;
import io.jans.as.server.model.config.ConfigurationFactory;

/**
 * @author Javier Rojas Blum
 * @version February 12, 2019
 */
public class CryptoProviderTest extends ConfigurableTest {

	@Inject
	private ConfigurationFactory configurationFactory;

	@Inject
	private AbstractCryptoProvider cryptoProvider;
	
//	@Inject
//    private AuthCryptoProvider cryptoProvider;	

	private final String SIGNING_INPUT = "Signing Input";
	private final String SHARED_SECRET = "secret";

	private static Long expirationTime;
	private static String hs256Signature;
	private static String hs384Signature;
	private static String hs512Signature;
	private static String rs256Key;
	private static String rs256Signature;
	private static String rs384Key;
	private static String rs384Signature;
	private static String rs512Key;
	private static String rs512Signature;
	private static String es256Key;
	private static String es256Signature;
    private static String es256KKey;
    private static String es256KSignature;
	private static String es384Key;
	private static String es384Signature;
	private static String es512Key;
	private static String es512Signature;

    private static String ed25519Key;
    private static String ed25519Signature;

    private static String ed448Key;
    private static String ed448Signature;
    
	@Test
	public void configuration() {
		try {
			AppConfiguration appConfiguration = configurationFactory.getAppConfiguration();
			assertNotNull(appConfiguration);

			assertNotNull(cryptoProvider);

			GregorianCalendar calendar = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
//			calendar.add(GregorianCalendar.MINUTE, 5);
			calendar.add(GregorianCalendar.MINUTE, 3000);
			expirationTime = calendar.getTimeInMillis();
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"configuration"})
	public void testSignHS256() {
		try {
			hs256Signature = cryptoProvider.sign(SIGNING_INPUT, null, SHARED_SECRET, SignatureAlgorithm.HS256);
			assertNotNull(hs256Signature);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testSignHS256"})
	public void testVerifyHS256() {
		try {
			boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, hs256Signature, null, null,
					SHARED_SECRET, SignatureAlgorithm.HS256);
			assertTrue(signatureVerified);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"configuration"})
	public void testSignHS384() {
		try {
			hs384Signature = cryptoProvider.sign(SIGNING_INPUT, null, SHARED_SECRET, SignatureAlgorithm.HS384);
			assertNotNull(hs384Signature);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testSignHS384"})
	public void testVerifyHS384() {
		try {
			boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, hs384Signature, null, null,
					SHARED_SECRET, SignatureAlgorithm.HS384);
			assertTrue(signatureVerified);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"configuration"})
	public void testSignHS512() {
		try {
			hs512Signature = cryptoProvider.sign(SIGNING_INPUT, null, SHARED_SECRET, SignatureAlgorithm.HS512);
			assertNotNull(hs512Signature);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testSignHS512"})
	public void testVerifyHS512() {
		try {
			boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, hs512Signature, null, null,
					SHARED_SECRET, SignatureAlgorithm.HS512);
			assertTrue(signatureVerified);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"configuration"})
	public void testGenerateKeyRS256() {
		try {
			JSONObject response = cryptoProvider.generateKey(Algorithm.RS256, expirationTime);
			rs256Key = response.optString(KEY_ID);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testGenerateKeyRS256"})
	public void testSignRS256() {
		try {
			rs256Signature = cryptoProvider.sign(SIGNING_INPUT, rs256Key, null, SignatureAlgorithm.RS256);
			assertNotNull(rs256Signature);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testSignRS256"})
	public void testVerifyRS256() {
		try {
			boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, rs256Signature, rs256Key, null,
					null, SignatureAlgorithm.RS256);
			assertTrue(signatureVerified);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testVerifyRS256"})
	public void testDeleteKeyRS256() {
		try {
			cryptoProvider.deleteKey(rs256Key);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"configuration"})
	public void testGenerateKeyRS384() {
		try {
			JSONObject response = cryptoProvider.generateKey(Algorithm.RS384, expirationTime);
			rs384Key = response.optString(KEY_ID);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testGenerateKeyRS384"})
	public void testSignRS384() {
		try {
			rs384Signature = cryptoProvider.sign(SIGNING_INPUT, rs384Key, null, SignatureAlgorithm.RS384);
			assertNotNull(rs384Signature);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testSignRS384"})
	public void testVerifyRS384() {
		try {
			boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, rs384Signature, rs384Key, null,
					null, SignatureAlgorithm.RS384);
			assertTrue(signatureVerified);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testVerifyRS384"})
	public void testDeleteKeyRS384() {
		try {
			cryptoProvider.deleteKey(rs384Key);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"configuration"})
	public void testGenerateKeyRS512() {
		try {
			JSONObject response = cryptoProvider.generateKey(Algorithm.RS512, expirationTime);
			rs512Key = response.optString(KEY_ID);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testGenerateKeyRS512"})
	public void testSignRS512() {
		try {
			rs512Signature = cryptoProvider.sign(SIGNING_INPUT, rs512Key, null, SignatureAlgorithm.RS512);
			assertNotNull(rs512Signature);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testSignRS512"})
	public void testVerifyRS512() {
		try {
			boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, rs512Signature, rs512Key, null,
					null, SignatureAlgorithm.RS512);
			assertTrue(signatureVerified);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testVerifyRS512"})
	public void testDeleteKeyRS512() {
		try {
			cryptoProvider.deleteKey(rs512Key);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"configuration"})
	public void testGenerateKeyES256() {
		try {
			JSONObject response = cryptoProvider.generateKey(Algorithm.ES256, expirationTime);
			es256Key = response.optString(KEY_ID);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}
	
    @Test(dependsOnMethods = {"testSignES256"})
    public void testCheckES256Keys() {
        try {
            // check if key is the point of the secp256r1
            
            PrivateKey privateKey = cryptoProvider.getPrivateKey(es256Key);
            PublicKey publicKey = cryptoProvider.getPublicKey(es256Key);            
            
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(Algorithm.ES256.getParamName());
            
            Signature signer = Signature.getInstance(signatureAlgorithm.getAlgorithm(), "BC");            
            signer.initSign(privateKey);
            signer.update(SIGNING_INPUT.getBytes(Util.UTF8_STRING_ENCODING));

            byte[] signature = signer.sign();

            signer.initVerify(publicKey);
            signer.update(SIGNING_INPUT.getBytes(Util.UTF8_STRING_ENCODING));
            boolean result = signer.verify(signature);
            
            assertTrue(result);            
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }    	

	@Test(dependsOnMethods = {"testGenerateKeyES256"})
	public void testSignES256() {
		try {
			es256Signature = cryptoProvider.sign(SIGNING_INPUT, es256Key, null, SignatureAlgorithm.ES256);
			assertNotNull(es256Signature);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testSignES256"})
	public void testVerifyES256() {
		try {
			boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, es256Signature, es256Key, null,
					null, SignatureAlgorithm.ES256);
			assertTrue(signatureVerified);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

    @Test(dependsOnMethods = {"configuration"})
    public void testGenerateKeyES256K() {
        try {
            JSONObject response = cryptoProvider.generateKey(Algorithm.ES256K, expirationTime);
            es256KKey = response.optString(KEY_ID);
         } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }
    
    @Test(dependsOnMethods = {"testSignES256K"})
    public void testCheckES256KKeys() {
        try {
            // check if key is the point of the secp256k1
            
            PrivateKey privateKey = cryptoProvider.getPrivateKey(es256KKey);
            PublicKey publicKey = cryptoProvider.getPublicKey(es256KKey);            
            
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(Algorithm.ES256K.getParamName());
            
            Signature signer = Signature.getInstance(signatureAlgorithm.getAlgorithm(), "BC");            
            signer.initSign(privateKey);
            signer.update(SIGNING_INPUT.getBytes(Util.UTF8_STRING_ENCODING));

            byte[] signature = signer.sign();

            signer.initVerify(publicKey);
            signer.update(SIGNING_INPUT.getBytes(Util.UTF8_STRING_ENCODING));
            boolean result = signer.verify(signature);
            
            assertTrue(result);            
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }        

    @Test(dependsOnMethods = {"testGenerateKeyES256K"})
    public void testSignES256K() {
        try {
            es256KSignature = cryptoProvider.sign(SIGNING_INPUT, es256KKey, null, SignatureAlgorithm.ES256K);
            assertNotNull(es256KSignature);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Test(dependsOnMethods = {"testSignES256K"})
    public void testVerifyES256K() {
        try {
            boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, es256KSignature, es256KKey, null,
                    null, SignatureAlgorithm.ES256K);
            assertTrue(signatureVerified);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }	

	@Test(dependsOnMethods = {"testVerifyES256"})
	public void testDeleteKeyES256() {
		try {
			cryptoProvider.deleteKey(es256Key);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"configuration"})
	public void testGenerateKeyES384() {
		try {
			JSONObject response = cryptoProvider.generateKey(Algorithm.ES384, expirationTime);
			es384Key = response.optString(KEY_ID);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testGenerateKeyES384"})
	public void testSignES384() {
		try {
			es384Signature = cryptoProvider.sign(SIGNING_INPUT, es384Key, null, SignatureAlgorithm.ES384);
			assertNotNull(es384Signature);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testSignES384"})
	public void testVerifyES384() {
		try {
			boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, es384Signature, es384Key, null,
					null, SignatureAlgorithm.ES384);
			assertTrue(signatureVerified);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testVerifyES384"})
	public void testDeleteKeyES384() {
		try {
			cryptoProvider.deleteKey(es384Key);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"configuration"})
	public void testGenerateKeyES512() {
		try {
			JSONObject response = cryptoProvider.generateKey(Algorithm.ES512, expirationTime);
			es512Key = response.optString(KEY_ID);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testGenerateKeyES512"})
	public void testSignES512() {
		try {
			es512Signature = cryptoProvider.sign(SIGNING_INPUT, es512Key, null, SignatureAlgorithm.ES512);
			assertNotNull(es512Signature);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testSignES512"})
	public void testVerifyES512() {
		try {
			boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, es512Signature, es512Key, null,
					null, SignatureAlgorithm.ES512);
			assertTrue(signatureVerified);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}

	@Test(dependsOnMethods = {"testVerifyES512"})
	public void testDeleteKeyES512() {
		try {
			cryptoProvider.deleteKey(es512Key);
		} catch (Exception e) {
			fail(e.getMessage(), e);
		}
	}
	
	
	
	

    @Test(dependsOnMethods = {"configuration"})
    public void testGenerateKeyED25519() {
        
        Algorithm algorithm = Algorithm.ED25519;
//        Algorithm algorithm = Algorithm.ES256;
        
        String keyStoreFile = "./conf/keystore.1.jks";
        String keyStoreSecret = "secret";    
        Use use = Use.SIGNATURE;
        String signingInput = "Some Message";
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(algorithm.getParamName());
        
        String dnName ="CN=Jans Auth CA Certificates";
        
        try {
//            KeyStore keyStore = KeyStore.getInstance("JKS");
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            File f = new File(keyStoreFile);
            if (!f.exists()) {
                keyStore.load(null, keyStoreSecret.toCharArray());
                FileOutputStream fos = new FileOutputStream(keyStoreFile);
                keyStore.store(fos, keyStoreSecret.toCharArray());
                fos.close();
            }
            InputStream is = new FileInputStream(keyStoreFile);
            keyStore.load(is, keyStoreSecret.toCharArray());
           
/*            
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(signatureAlgorithm.getCurve().getAlias());            
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
            keyGen.initialize(ecSpec, new SecureRandom());
*/
            EdDSAParameterSpec edSpec = new EdDSAParameterSpec(signatureAlgorithm.getName());
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(signatureAlgorithm.getName(), "BC");
//            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EDDSA", "BC");            
            keyGen.initialize(edSpec, new SecureRandom());

            // Generate the key
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey pk = keyPair.getPrivate();

            // Java API requires a certificate chain
            X509Certificate cert = generateV3Certificate(keyPair, dnName, signatureAlgorithm.getAlgorithm(), expirationTime);
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = cert;

            String alias = UUID.randomUUID().toString() + getKidSuffix(use, algorithm);
            keyStore.setKeyEntry(alias, pk, keyStoreSecret.toCharArray(), chain);
            
            FileOutputStream fos = new FileOutputStream(keyStoreFile);
            keyStore.store(fos, keyStoreSecret.toCharArray());
            fos.close();
            
/*            
            //KeyStore keyStore1 = KeyStore.getInstance("JKS");
            KeyStore keyStore1 = KeyStore.getInstance("PKCS12");
            f = new File(keyStoreFile);
            if (!f.exists()) {
                keyStore1.load(null, keyStoreSecret.toCharArray());
                fos = new FileOutputStream(keyStoreFile);
                keyStore1.store(fos, keyStoreSecret.toCharArray());
                fos.close();
            }
            is = new FileInputStream(keyStoreFile);
            keyStore1.load(is, keyStoreSecret.toCharArray());
*/            
            
//            Entry entry = keyStore.getEntry(alias, new KeyStore.PasswordProtection(keyStoreSecret.toCharArray()));
            
            Key key = keyStore.getKey(alias, keyStoreSecret.toCharArray());
            PrivateKey privateKey = (PrivateKey) key;

            Signature signer = Signature.getInstance(signatureAlgorithm.getAlgorithm(), "BC");
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes());

            byte[] signature = signer.sign();

//            return Base64Util.base64urlencode(signature);        
            
            fos = new FileOutputStream(keyStoreFile);
            keyStore.store(fos, keyStoreSecret.toCharArray());
            fos.close();
            
            PublicKey publicKey = null;

            java.security.cert.Certificate certificate = keyStore.getCertificate(alias);
            publicKey = certificate.getPublicKey();
            
            Signature verifier = Signature.getInstance(signatureAlgorithm.getAlgorithm(), "BC");
            verifier.initVerify(publicKey);
            verifier.update(signingInput.getBytes());
            
            boolean verifyRes = verifier.verify(signature);
            
            verifyRes = verifyRes;
            
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }    
        
        try {
//            JSONObject response = cryptoProvider.generateKey(Algorithm.ED25519, expirationTime);
//            ed25519Key = response.optString(KEY_ID);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }
    
    public X509Certificate generateV3Certificate(KeyPair keyPair, String issuer, String signatureAlgorithm, Long expirationTime) throws CertIOException, OperatorCreationException, CertificateException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Signers name
        X500Name issuerName = new X500Name(issuer);

        // Subjects name - the same as we are self signed.
        X500Name subjectName = new X500Name(issuer);

        // Serial
        BigInteger serial = new BigInteger(256, new SecureRandom());

        // Not before
        Date notBefore = new Date(System.currentTimeMillis() - 10000);
        Date notAfter = new Date(expirationTime);

        // Create the certificate - version 3
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, notBefore, notAfter, subjectName, publicKey);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);

        ASN1ObjectIdentifier extendedKeyUsage = new ASN1ObjectIdentifier("2.5.29.37").intern();
        builder.addExtension(extendedKeyUsage, false, new DERSequence(purposes));

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(privateKey);
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);

        return cert;
    }
    
    private static String getKidSuffix(Use use, Algorithm algorithm) {
        return "_" + use.getParamName().toLowerCase() + "_" + algorithm.getParamName().toLowerCase();
    }

//    @Test(dependsOnMethods = {"testGenerateKeyED25519"})
    public void testSignED25519() {
        try {
            ed25519Signature = cryptoProvider.sign(SIGNING_INPUT, ed25519Key, null, SignatureAlgorithm.ED25519);
            assertNotNull(ed25519Signature);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

//    @Test(dependsOnMethods = {"testSignED25519"})
    public void testVerifyED25519() {
        try {
            boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, ed25519Signature, ed25519Key, null,
                    null, SignatureAlgorithm.ED25519);
            assertTrue(signatureVerified);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

//    @Test(dependsOnMethods = {"testVerifyED25519"})
    public void testDeleteKeyED25519() {
        try {
            cryptoProvider.deleteKey(ed25519Key);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }	
	

    

//    @Test(dependsOnMethods = {"configuration"})
    public void testGenerateKeyED448() {
        try {
            JSONObject response = cryptoProvider.generateKey(Algorithm.ED448, expirationTime);
            ed448Key = response.optString(KEY_ID);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

//   @Test(dependsOnMethods = {"testGenerateKeyED448"})
    public void testSignED448() {
        try {
            ed448Signature = cryptoProvider.sign(SIGNING_INPUT, ed448Key, null, SignatureAlgorithm.ED448);
            assertNotNull(ed448Signature);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

//    @Test(dependsOnMethods = {"testSignED448"})
    public void testVerifyED448() {
        try {
            boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, ed448Signature, ed448Key, null,
                    null, SignatureAlgorithm.ED448);
            assertTrue(signatureVerified);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

//    @Test(dependsOnMethods = {"testVerifyED448"})
    public void testDeleteKeyED448() {
        try {
            cryptoProvider.deleteKey(ed448Key);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }   
    
    
    
	
	
	
}
