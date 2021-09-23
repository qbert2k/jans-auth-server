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

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import javax.inject.Inject;

import org.json.JSONArray;
import org.json.JSONObject;
import org.testng.annotations.Test;

import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.model.crypto.AbstractCryptoProvider;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jwk.Algorithm;
import io.jans.as.model.jwk.JWKParameter;
import io.jans.as.server.ConfigurableTest;
import io.jans.as.server.model.config.ConfigurationFactory;

/**
 * @author Javier Rojas Blum
 * @author Sergey Manoylo
 * @version September 13, 2021
 */
public class CryptoProviderTest extends ConfigurableTest {

	@Inject
	private ConfigurationFactory configurationFactory;

	@Inject
	private AbstractCryptoProvider cryptoProvider;

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
    private static JSONObject ed25519Jwks;

    private static String ed448Key;
    private static String ed448Signature;
    private static JSONObject ed448Jwks;

	@Test
	public void configuration() {
		try {
			AppConfiguration appConfiguration = configurationFactory.getAppConfiguration();
			assertNotNull(appConfiguration);

			assertNotNull(cryptoProvider);

			GregorianCalendar calendar = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
			calendar.add(GregorianCalendar.MINUTE, 5);
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
            signer.update(SIGNING_INPUT.getBytes(StandardCharsets.UTF_8));

            byte[] signature = signer.sign();

            signer.initVerify(publicKey);
            signer.update(SIGNING_INPUT.getBytes(StandardCharsets.UTF_8));
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
            signer.update(SIGNING_INPUT.getBytes(StandardCharsets.UTF_8));

            byte[] signature = signer.sign();

            signer.initVerify(publicKey);
            signer.update(SIGNING_INPUT.getBytes(StandardCharsets.UTF_8));
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
        try {
            JSONObject response = cryptoProvider.generateKey(Algorithm.ED25519, expirationTime);
            ed25519Key = response.optString(KEY_ID);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Test(dependsOnMethods = {"testGenerateKeyED25519"})
    public void testSignED25519() {
        try {
            ed25519Signature = cryptoProvider.sign(SIGNING_INPUT, ed25519Key, null, SignatureAlgorithm.ED25519);
            assertNotNull(ed25519Signature);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Test(dependsOnMethods = {"testSignED25519"})
    public void testVerifyED25519() {
        try {
            boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, ed25519Signature, ed25519Key, null,
                    null, SignatureAlgorithm.ED25519);
            assertTrue(signatureVerified);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Test(dependsOnMethods = {"testSignED25519"})
    public void testVerifyED25519Jwks() {
        try {
            boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, ed25519Signature, ed25519Key, ed25519Jwks,
                    null, SignatureAlgorithm.ED25519);
            assertTrue(signatureVerified);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }    

    @Test(dependsOnMethods = {"testVerifyED25519"})
    public void testDeleteKeyED25519() {
        try {
            cryptoProvider.deleteKey(ed25519Key);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }	
    
    @Test(dependsOnMethods = {"configuration"})
    public void testGenerateKeyED448() {
        try {
            JSONObject response = cryptoProvider.generateKey(Algorithm.ED448, expirationTime);
            ed448Key = response.optString(KEY_ID);
            
            JSONArray keys = new JSONArray();
            keys.put(response); 
            
            ed448Jwks = new JSONObject();
            ed448Jwks.put(JWKParameter.JSON_WEB_KEY_SET, keys);

            System.out.println("ed448Jwks.toString() = " + ed448Jwks.toString());
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Test(dependsOnMethods = {"testGenerateKeyED448"})
    public void testSignED448() {
        try {
            ed448Signature = cryptoProvider.sign(SIGNING_INPUT, ed448Key, null, SignatureAlgorithm.ED448);
            assertNotNull(ed448Signature);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Test(dependsOnMethods = {"testSignED448"})
    public void testVerifyED448() {
        try {
            boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, ed448Signature, ed448Key, null,
                    null, SignatureAlgorithm.ED448);
            assertTrue(signatureVerified);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }
    
    @Test(dependsOnMethods = {"testSignED448"})
    public void testVerifyED448Jwks() {
        try {
            boolean signatureVerified = cryptoProvider.verifySignature(SIGNING_INPUT, ed448Signature, ed448Key, ed448Jwks,
                    null, SignatureAlgorithm.ED448);
            assertTrue(signatureVerified);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }    

    @Test(dependsOnMethods = {"testVerifyED448"})
    public void testDeleteKeyED448() {
        try {
            cryptoProvider.deleteKey(ed448Key);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }   
	
}
