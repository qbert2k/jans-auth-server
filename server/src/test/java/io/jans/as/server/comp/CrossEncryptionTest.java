/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.server.comp;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.codec.Charsets;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.PublicJsonWebKey;
import org.json.JSONException;
import org.json.JSONObject;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.model.crypto.AbstractCryptoProvider;
import io.jans.as.model.crypto.Certificate;
import io.jans.as.model.crypto.Key;
import io.jans.as.model.crypto.KeyFactory;
import io.jans.as.model.crypto.encryption.BlockEncryptionAlgorithm;
import io.jans.as.model.crypto.encryption.KeyEncryptionAlgorithm;
import io.jans.as.model.crypto.signature.RSAKeyFactory;
import io.jans.as.model.crypto.signature.RSAPublicKey;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.exception.InvalidJweException;
import io.jans.as.model.exception.InvalidJwtException;
import io.jans.as.model.jwe.Jwe;
import io.jans.as.model.jwe.JweDecrypterImpl;
import io.jans.as.model.jwe.JweEncrypterImpl;
import io.jans.as.model.jwk.Algorithm;
import io.jans.as.model.jwk.JSONWebKey;
import io.jans.as.model.jwk.JSONWebKeySet;
import io.jans.as.model.jwk.Use;
import io.jans.as.model.jws.RSASigner;
import io.jans.as.model.jwt.Jwt;
import io.jans.as.model.jwt.JwtType;
import io.jans.as.model.util.Base64Util;
import io.jans.as.server.model.token.JwtSigner;

public class CrossEncryptionTest {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	// final String encryptedJweProducedByGluu = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00iLCJraWQiOiIyIn0.M9YXhzGlMBxJRFjpIZ3ybfNODALPz_08WADIpWSLHOoCBdwqPWQ3fwDf-uaiw7wyTTf9piuKVUOeYHnPE6C_EmS9gj5fmckHBCHcNxZanobT0QXZdy-64wb4GK3ar66lPPFnJMVLLCqZfUjB1gHxmAcwrVJQTUPO0ogk2nZCujp4mOuJ0QnOQmJ0R1rHTjbYmKBDySIavmkXosoJaLZI4N1CltCKj66P_XKYLfgAE0yevuwtNxkkRc2EGMyPpZ8pVjBL5TPQF3b5AyAstUvB4l6o90JZQLzvAdHJyGuCW1zwzGPBtVBVYvb2vBBAuj7EPKDU9UQDuDoklwj5Hwc6wg.qBM-41MJ46_eUv4I.mak_e28_onSOODjdH06wWuA0MfJMTGConWSekPIArQoFKAgcxVRvg-JNqjaBFaG4ck8cp0ViAke_Cbfl4AyN-gAFI2pqEMiXkoEB193SyD6Yev0P1zKTJORWS6tpznYAGYgIPh_rWyWPFSdT1WPB7Qgzarf-JNYrNe5H_P8JRrArWyCEJx4w6_WLcGnM1EQQPkThoYC4utS47W0OHf2SNr-PRUhCeoEIuoMaQUmjYq386BjCWhQEoQCZNftUjUXZBq8MepW92v1spNLCb7NTEJ1p3s45KIVwPt5qnXI6-ouQE4_KFXVNe5-SSfyzrEf1jxTyerNqlU5bIZ0v4aPS6i3bXSSHIfgyvrFCzDPq9x-5B98OI0sVDKxzzp7UWjqEjjmuQbdN4eGZUtSGYcWNFI29vl4Pr8HvqMjnQaaEtGZeX_nJG27xzlwlD1pI_rjO_QMAQpfbNuxLm5-HhB0fZOngjNAnOhipyY_tTMMtiWLmoJUuicwTTSpERC_9ny8tnsiyCOEJEyeZFEzh52jfox_WHLVkIrjCUCYtTwCvuYdtu4Sgl-WPCa2y-4uF7u2DcIKdIRRMdjgE1RNUAp-W2ui8PDrIaSVxkWbuLQJ2oXEyWN8gFHEZPko-n80IjGG8Si3Qh1kum_vO9Ub7AiIm0pk65ph_CQH0BSVSLwN-e4iAd1C6h_J2O-aGEKWKrvvRC31ApCr5RkOdaKTAYVGUKQSMBdqucq47JbBynP7dqE0Kxl3miBo_dyYXCim9Gw.DSoXCEJ7-uT7Xv7eb3g-7A";
	private final String encryptedJweProducedByGluu = "eyJraWQiOiIxIiwidHlwIjoiSldUIiwiZW5jIjoiQTEyOEdDTSIsImFsZyI6IlJTQS1PQUVQIn0.bnWzspu4G40jEAkOjV-yRsXnHhgy7MgHxDKHc_ePWqCji-rNfeViybYV62jSCGRWsRB1sGiLuiE35z8aag4dr1gIbYARfNB7t9kaBcZCfZ-jwaGUYn-XfCDg98U4VVv1P77R8Gu-OcU53vBM_pPCzOm75IelWf_W8wFK4DB6i9P8CDFVlsDSWslMfqsMZLj9lE0KV_10c2ovELzcTu-GPC-rMUglFSHIt8Povi7bFf-kiWxFd1kT0NdrnHmKUVqIRNv5fsAtbY5B7jx5-EQ_IjhdaoK0QwfaqF0Vz4qVOO7y1PSXdDXyvrLwSY8rrTjzaLbXCnLc9oLeiIP-aR3HuA.YB2_esWvrHdJh1jt.P56SeJfBlBDm73YVQsEH_8ZtBgwQpnpX0hKY7v2ufFuqAlP2BeR2Ku-3rgIhFHPOAhqRuZ-YOROwIUVfC9ceG0tI63W_Xf0.FyuoL4LlnBvPEnmCJ5H8pw";

	private final String senderJwkJson = "{\"kty\":\"RSA\",\"d\":\"iSx-zxihgOITpEhz6WwGiiCZjxx597wqblhSYgFWa_bL9esLY3FT_Kq9sdvGPiI8QmObRxPZuTi4n3BVKYUWcfjVz3swq7VmESxnJJZE-vMI9NTaZ-CT2b4I-c3qwAsejhWagJf899I3MRtPOnyxMimyOw4_5YYvXjBkXkCMfCsbj5TBR3RbtMrUYzDMXsVT1EJ_7H76DPBFJx5JptsEAA17VMtqwvWhRutnPyQOftDGPxD-1aGgpteKOUCv7Lx-mFX-zV6nnPB8vmgTgaMqCbCFKSZI567p714gzWBkwnNdRHleX8wos8yZAGbdwGqqUz5x3iKKdn3c7U9TTU7DAQ\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"1\",\"alg\":\"RS256\",\"n\":\"i6tdK2fREwykTUU-qkYkiSHgg9B31-8EjVCbH0iyrewY9s7_WYPT7I3argjcmiDkufnVfGGW0FadtO3br-Qgk_N2e9LqGMtjUoGMZKFS3fJhqjnLYDi_E5l2FYU_ilw4EXPsZJY0CaM7BxjwUBoCjopYrgvtdxA9G6gpGoAH4LopAkgX-gkawVLpB4NpLvA09FLF2OlYZL7aaybvM2Lz_IXEPa-LSOwLum80Et-_A1-YMx_Z767Iwl1pGTpgZ87jrDD1vEdMdiLcWFG3UIYAAIxtg6X23cvQVLMaXKpyV0USDCWRJrZYxEDgZngbDRj3Sd2-LnixPkMWAfo_D9lBVQ\"}";
	private final String recipientJwkJson = "{\"kty\":\"RSA\",\"d\":\"jAFM0c4oXxh5YcEujZRVY5LNUzkm0OZf8OUZ31DockQE07BwSAsi4_y6vursS4Z74EurjYlfPx7WoZZokTLyBReVvG8XQZ-AQ5smU9gXQrsiVdU2kOp17oYnOP3OKc0HtvlfTPKdz0DhoA--wAsPFCL2ei4Qly_J3IQTF9ffJJMEyzgabcV1xqrk8NEK5XfEHOdNHzzg-doRe4lCsDcEfIppCIxPHTozhYpwH0_OrssAX1OwX5Jx6-5pXc_BIBrymIkjfwlPYBC32f0iD6VTntJfIngMOdeu0t6krOaWlbfmf6RdoM5sugT-j3mYnd3w4c2eFW23Z9sPCrQvDNlTcQ\",\"e\":\"AQAB\",\"use\":\"enc\",\"kid\":\"2\",\"alg\":\"RS256\",\"n\":\"oaPsFKHgVnK0d04rjN5GgZFqCh9HwYkLMdDQDIgkM3x4sxTpctS5NJQK7iKWNxPTtULdzrY6NLqtrNWmIrJFC6f2h4q5p46Kmc8vdhm_Ph_jpYfsXWTdsHAoee6iJPMoie7rBGoscr3y2DdNlyxAO_jHLUkaaSAqDQrH_f4zVTO0XKisJu8DxKoh2U8myOow_kxx4PUxEdlH6XclpxYT5lIZijOZ8wehFad_BAJ2iZM40JDoqOgspUF1Jyq7FjOoMQabYYwDMyfs2rEALcTU1UsvLeWbl95T3mdAw64Ux3uFCZzHdXF4IDr7xH4NrEVT7SMAlwNoaRfmFbtL-WoISw\"}";
	
	public static final String PAYLOAD = "{\"iss\":\"https:devgluu.saminet.local\",\"sub\":\"testing\"}";
	
	private final String rsa1JwkJson = "{ \"kty\":\"RSA\", \"d\":\"BSOr_bbK0THvHyqE8CaPE-f26VBUFRqry47VW0MWtZyU7tGWoBNJi-hB4kxDskw7HitOpdx2zXDhQq6rg6Yv1Wn4WTHSFtQ1_vEJaCOunN1SejrhfEz1eFrADuCyOUXflrUduhymvWGltIgd000kib3QvwvsIft597wqfW5kDds_JgnTILnk-UkKdVx58SGhkgkcUI8uo9BSN5MMGgqEUHY_orqMa-oVWy5VsOAMU22m2ZuPhEZa4uOH4xCRkRtid7LlgzWCOncAAhM4trspKM60Zntq1m6D7ir_bDD1qxpEWYOvEH1UhvUcQw8UKYxGZ3VwscSBlTxQ15mNiDi-wQ\", \"e\":\"AQAB\", \"use\":\"enc\", \"use\":\"sig\", \"kid\":\"1\", \"alg\":\"RS256\", \"n\":\"ALPsdlfm6QYerQFRhL2-QOJUn-a70JsuElspspyBXRZUllhpxSaNWZlouT0DAf3NUmEm8wgVbJF1-exMVaaF8kUrdGYKS5N1uDnZwc1G8MIt29YQ6xoLLqzihJlD-syYL6tPYCr97a4AbA8EssrMjynk_WIBh18gRESq-I9vyvlYyjRfZ9ey185ERGpMfm0d4Mouttl2nc3VRfuuLIstQ4ylKvMjnWtuAvBdwF7jJSIalDUjxIA9kkg6dH2e0ZNyDlN8-14VkeAaC73f-va0kBrD9bPIUSuaaIkmgN0lKwR_xH1Y7vG2xs45R1d_cVTSo-yXhPgKLphPXflPkMMXBs0\" }";	
	private final String rsa2JwkJson = "{ \"kty\":\"RSA\", \"d\":\"BCS_6xY0EZQ9jcusklPvP97Ydvo7I7kdb3na3b7HPzxRsfP2NJluz3noPydH7RtY2H1osEy4TJVHZRHtH00DjUAB-dk1KGkNNpGBl51uNZgQ9L0hbz_EvSdXQoNNaCOXhXjeOoM3P_keH4ztJMpLIvI5E4SDVA7zuze24HVNOijIR0NwulhtcdblmkbsKVU0lCvDK2eJnVF-rSEk4Vor4w-bA4hzEMof79W26VsdQVGs9Yc6p1zWiefe9dTo_hIploXTxgF4D_8na1vyHZu5xrtBqK87DDAq9RK70uC3OPVE2lGSjnlP-MeTsbW_fFKK_BV9-0dAloTM85-D_aOhgQ\", \"e\":\"AQAB\", \"use\":\"enc\", \"use\":\"sig\", \"kid\":\"1\", \"alg\":\"RS256\", \"n\":\"AM4kBzkoQcWAWYd-YxwVCQfr2siOZz8DVZ70iUAPevM4JgMsFFHO6eSsg1DAFIuEyMcsy7ucGaVb-sGNYanfY2tx25EzoPZS-KvMukIkXudPAXO1ii3WR_PWXR8So-hbI_a_bHJJ7fa-VaLLiSSvJMZ7mXjLb4cuFKHV6cAI4M1aX-SvR3Y-VvJBSLIwuW7AVtaVgiO24YIlbegfNnx2iHxu-ZWcl5fdbgrLfWRVD29udwCQqiCosMBL6Yfvax-_H4Q9-ir6sna5eJSLCPWuBiwdOqE6Y3eZQxVoY2CCVlVjWY8UXQra8RPMcwAvdOCbpNPuY4Wq7b1T18l-e79xtA8\" }";;
	
	private final String encryptedRsa2JweProducedByGluu = "eyJraWQiOiIxIiwidHlwIjoiSldUIiwiZW5jIjoiQTEyOENCQytIUzI1NiIsImFsZyI6IlJTQTFfNSJ9.jzdQDZMZJEBb1v-N2DcSg1k0j8wPMGLhWRhIsFvEpS5A7JyKfEY2fkptWDStB_sEl4uZKODuN6WCmNO6ESetYJq0a2BIS_M5MurXPXLEXZey96PJK1h9EWl-Mi-HgEYGS_56EFag3n-87JEPbyG-v65sk7Z6sHm4ti0azf5WPUqskhBEe1YgdgPaZKfLq-hWJ11teFt3vD-xxYNXOmbrGV3RrV-BEtzh69O87Ik_kkhCsc_Jlul2AxXDBJAhJhy_2bVPuXS1WUoEJ6UuWEj-us20OS2H2BuTU8Xh7k9TtHbsx_XF7qe7Syey3A1ET_7T-r922OZJDmHoJlCrEqp3rQ.0UKKw6CuiHOFMHbcENGo4w.7RYTtNPmdCFcsu2yDzjMggMUBe1eUgPLmz84O6QACAJjT4wJ8vTHZwMSUvJoCEv9yQYoMSy5cHXO2JiLGQ3U0CTIAiuF_viMbQPudADJENQ.poaAuMG83LFk2oCREptmamh6uQvbiy2WCqB6WSKzdWk";	

	private final String ecJwkJson = "{ \"kty\":\"EC\", \"crv\":\"P-256\", \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", \"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\", \"use\":\"enc\", \"kid\":\"3\" }";

	private final String aes128JwkJson = "{ \"kty\":\"oct\", \"alg\":\"A128KW\", \"k\":\"bcDF5_XQSpDPnGXR6RyDhg\" }";
	private final String aes192JwkJson = "{ \"kty\":\"oct\", \"alg\":\"A192KW\", \"k\":\"bcDF5_XQSpDPnGXR6RyDhsgXfmbScFAt\" }";
	private final String aes256JwkJson = "{ \"kty\":\"oct\", \"alg\":\"A256KW\", \"k\":\"bcDF5_XQSpDPnGXR6RyDhsgXfmbScFAtw3Kpqkrudq0\" }";
	private final String aes384JwkJson = "{ \"kty\":\"oct\", \"alg\":\"A384KW\", \"k\":\"bcDF5_XQSpDPnGXR6RyDhsgXfmbScFAtw3Kpqkrudq2M3T9YqsQdtoZrl1Yfn8JK\" }";
	private final String aes512JwkJson = "{ \"kty\":\"oct\", \"alg\":\"A512KW\", \"k\":\"bcDF5_XQSpDPnGXR6RyDhsgXfmbScFAtw3Kpqkrudq2M3T9YqsQdtoZrl1Yfn8JKzk8EeKHaHZY9Qj49CFIf8g\" }";

	private final String aes128GCMKJwkJson = "{ \"kty\":\"oct\", \"alg\":\"A128GCMKW\", \"k\":\"bcDF5_XQSpDPnGXR6RyDhg\" }";
	private final String aes192GCMKJwkJson = "{ \"kty\":\"oct\", \"alg\":\"A192GCMKW\", \"k\":\"bcDF5_XQSpDPnGXR6RyDhsgXfmbScFAt\" }";
	private final String aes256GCMKJwkJson = "{ \"kty\":\"oct\", \"alg\":\"A256GCMKW\", \"k\":\"bcDF5_XQSpDPnGXR6RyDhsgXfmbScFAtw3Kpqkrudq0\" }";
	private final String aes384GCMKJwkJson = "{ \"kty\":\"oct\", \"alg\":\"A384GCMKW\", \"k\":\"bcDF5_XQSpDPnGXR6RyDhsgXfmbScFAtw3Kpqkrudq2M3T9YqsQdtoZrl1Yfn8JK\" }";
	private final String aes512GCMKJwkJson = "{ \"kty\":\"oct\", \"alg\":\"A512GCMKW\", \"k\":\"bcDF5_XQSpDPnGXR6RyDhsgXfmbScFAtw3Kpqkrudq2M3T9YqsQdtoZrl1Yfn8JKzk8EeKHaHZY9Qj49CFIf8g\" }";
	
	private final String passwordValue = "password";
	
	/**
	 * 
	 * @author SMan
	 *
	 */
	private static class KeyEncryptionAlgorithmSuite {

		public KeyEncryptionAlgorithm keyEncrAlg;  
		public String keyData1;
		public String keyData2;
		public String encData2;		
		public BlockEncryptionAlgorithm[] blockEncryptionAlgorithms;

		/**
		 * 
		 * @param keyEncrAlg
		 * @param keyData1
		 * @param keyData2
		 * @param encData2
		 * @param blockEncryptionAlgorithms
		 */
		public KeyEncryptionAlgorithmSuite(KeyEncryptionAlgorithm keyEncrAlg, String keyData1, String keyData2, String encData2, BlockEncryptionAlgorithm[] blockEncryptionAlgorithms) {
			this.keyEncrAlg = keyEncrAlg; 
			this.keyData1 = keyData1;
			this.keyData2 = keyData2;
			this.encData2 = encData2;
			this.blockEncryptionAlgorithms = blockEncryptionAlgorithms;
		}
	}
	
	BlockEncryptionAlgorithm[] blockEncryptionAlgorithms = {
			BlockEncryptionAlgorithm.A128CBC_PLUS_HS256,
			BlockEncryptionAlgorithm.A256CBC_PLUS_HS512,
			BlockEncryptionAlgorithm.A128CBC_HS256,
			BlockEncryptionAlgorithm.A192CBC_HS384,
			BlockEncryptionAlgorithm.A256CBC_HS512,
			BlockEncryptionAlgorithm.A128GCM,
			BlockEncryptionAlgorithm.A192GCM,
			BlockEncryptionAlgorithm.A256GCM,
	};
	
	BlockEncryptionAlgorithm[] blockEncryptionAlgorithms_ECDH_ES = {
			BlockEncryptionAlgorithm.A128CBC_HS256,
			BlockEncryptionAlgorithm.A192CBC_HS384,
			BlockEncryptionAlgorithm.A256CBC_HS512,
			BlockEncryptionAlgorithm.A128GCM,
			BlockEncryptionAlgorithm.A192GCM,
			BlockEncryptionAlgorithm.A256GCM,
	};	
	
	KeyEncryptionAlgorithmSuite[] keyEnrAlgorithmsRSA = {
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.RSA1_5, rsa1JwkJson, rsa2JwkJson, encryptedRsa2JweProducedByGluu,  null),
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.RSA_OAEP, rsa1JwkJson, rsa2JwkJson, encryptedRsa2JweProducedByGluu, null),
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.RSA_OAEP_256, rsa1JwkJson, rsa2JwkJson, encryptedRsa2JweProducedByGluu, null),
	};

	KeyEncryptionAlgorithmSuite[] keyEnrAlgorithmsECDH = {
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.ECDH_ES, ecJwkJson, null, null, blockEncryptionAlgorithms_ECDH_ES),
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW, ecJwkJson, null, null, null),
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.ECDH_ES_PLUS_A192KW, ecJwkJson, null, null, null),
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.ECDH_ES_PLUS_A256KW, ecJwkJson, null, null, null)			
	};	

	KeyEncryptionAlgorithmSuite[] keyEnrAlgorithmsAES = {
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.A128KW, aes128JwkJson, null, null, null),
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.A192KW, aes192JwkJson, null, null, null),
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.A256KW, aes256JwkJson, null, null, null),
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.A128GCMKW, aes128GCMKJwkJson, null, null, null),
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.A192GCMKW, aes192GCMKJwkJson, null, null, null),			
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.A256GCMKW, aes256GCMKJwkJson, null, null, null)
	};

	KeyEncryptionAlgorithmSuite[] keyEnrAlgorithmsPassw = {
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.PBES2_HS256_PLUS_A128KW, passwordValue, null, null, null),
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.PBES2_HS384_PLUS_A192KW, passwordValue, null, null, null),
			new KeyEncryptionAlgorithmSuite (KeyEncryptionAlgorithm.PBES2_HS512_PLUS_A256KW, passwordValue, null, null, null)
	};

//	@Test
    public void getKeys() {
    	
		try {
	    	int keyLength;
	    	final String passwMessage = "Some Password";
	    	MessageDigest sha512;
			sha512 = MessageDigest.getInstance("SHA-512");
			
	    	byte[] sha512Array = sha512.digest(passwMessage.getBytes());
	    	
	    	keyLength = 128 / 8;
	    	byte[] sha512Array_16 = Arrays.copyOf(sha512Array, keyLength);

	    	keyLength = 192 / 8;
	    	byte[] sha512Array_24 = Arrays.copyOf(sha512Array, keyLength);
	    	
	    	keyLength = 256 / 8;
	    	byte[] sha512Array_32 = Arrays.copyOf(sha512Array, keyLength);
	    	
	    	keyLength = 384 / 8;
	    	byte[] sha512Array_48 = Arrays.copyOf(sha512Array, keyLength);
	    	
	    	keyLength = 512 / 8;
	    	byte[] sha512Array_64 = Arrays.copyOf(sha512Array, keyLength);
	    	
	    	String sha512Str_16 = Base64Util.base64urlencode(sha512Array_16);
	    	String sha512Str_24 = Base64Util.base64urlencode(sha512Array_24);	    	
	    	String sha512Str_32 = Base64Util.base64urlencode(sha512Array_32);
	    	String sha512Str_48 = Base64Util.base64urlencode(sha512Array_48);	    	
	    	String sha512Str_64 = Base64Util.base64urlencode(sha512Array_64);	    	
	    	
	        System.out.println("sha512Str_16 = " + sha512Str_16);
	        System.out.println("sha512Str_24 = " + sha512Str_24);
	        System.out.println("sha512Str_32 = " + sha512Str_32);	        
	        System.out.println("sha512Str_48 = " + sha512Str_48);	        
	        System.out.println("sha512Str_64 = " + sha512Str_64);	        
	    	
	        byte[] sha512Array_16_dec = Base64Util.base64urldecode(sha512Str_16);
	        byte[] sha512Array_24_dec = Base64Util.base64urldecode(sha512Str_24);	        
	        byte[] sha512Array_32_dec = Base64Util.base64urldecode(sha512Str_32);
	        byte[] sha512Array_48_dec = Base64Util.base64urldecode(sha512Str_48);	        
	        byte[] sha512Array_64_dec = Base64Util.base64urldecode(sha512Str_64);	        
	        
	        assertTrue(Arrays.equals(sha512Array_16, sha512Array_16_dec));
	        assertTrue(Arrays.equals(sha512Array_24, sha512Array_24_dec));
	        assertTrue(Arrays.equals(sha512Array_32, sha512Array_32_dec));
	        assertTrue(Arrays.equals(sha512Array_48, sha512Array_48_dec));	        
	        assertTrue(Arrays.equals(sha512Array_64, sha512Array_64_dec));
	        
/*	        
	        import io.jans.as.model.crypto.signature.ECDSAKeyFactory;
	        import io.jans.as.model.crypto.signature.ECDSAPrivateKey;
	        import io.jans.as.model.crypto.signature.ECDSAPublicKey;
	        import io.jans.as.model.crypto.signature.EDDSAKeyFactory;
	        import io.jans.as.model.crypto.signature.EDDSAPrivateKey;
	        import io.jans.as.model.crypto.signature.EDDSAPublicKey;
	        import io.jans.as.model.crypto.signature.RSAKeyFactory;
	        import io.jans.as.model.crypto.signature.RSAPrivateKey;
	        import io.jans.as.model.crypto.signature.RSAPublicKey;
*/	        	        
	        
	        io.jans.as.model.crypto.KeyFactory<io.jans.as.model.crypto.signature.RSAPrivateKey, 
	        io.jans.as.model.crypto.signature.RSAPublicKey> keyFactory = new io.jans.as.model.crypto.signature.RSAKeyFactory(SignatureAlgorithm.RS256,
	        		"CN=Test CA Certificate");

			Key<io.jans.as.model.crypto.signature.RSAPrivateKey, io.jans.as.model.crypto.signature.RSAPublicKey> key = keyFactory.getKey();

			io.jans.as.model.crypto.signature.RSAPrivateKey privateKey = key.getPrivateKey();
			io.jans.as.model.crypto.signature.RSAPublicKey publicKey = key.getPublicKey();
			io.jans.as.model.crypto.Certificate certificate = key.getCertificate();

			BigInteger dPriv = privateKey.getPrivateExponent();
			BigInteger nPriv = privateKey.getModulus();
			
			String dPrivStr = Base64Util.base64urlencode(dPriv.toByteArray());
			String nPrivStr = Base64Util.base64urlencode(nPriv.toByteArray());

			BigInteger dPub = publicKey.getPublicExponent();
			BigInteger nPub = publicKey.getModulus();
			
			String dPubStr = Base64Util.base64urlencode(dPub.toByteArray());
			String nPubStr = Base64Util.base64urlencode(nPub.toByteArray());
			
	        System.out.println("dPrivStr = " + dPrivStr);
	        System.out.println("nPrivStr = " + nPrivStr);
	        
	        System.out.println("dPubStr = " + dPubStr);
	        System.out.println("nPubStr = " + nPubStr);
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidParameterException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
    	
        assertTrue(true);
    }
	

	@Test
	public void encryptWithNimbus_decryptByAll() {
		final String jwt = encryptWithNimbusJoseJwt();

		assertTrue(testDecryptNimbusJoseJwt(jwt));
		assertTrue(testDecryptWithJose4J(jwt));
		assertTrue(testDecryptWithGluuDecrypter_RSA_OAEP(jwt));
	}

	@Test
	public void encryptWithGluu_RSA_OAEP_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_RSA_OAEP();
		System.out.println("Gluu encrypted (RSA_OAEP) : " + jwt);

		assertTrue(testDecryptNimbusJoseJwt(jwt));
		assertTrue(testDecryptWithJose4J(jwt));
		assertTrue(testDecryptWithGluuDecrypter_RSA_OAEP(jwt));
	}

	@Test
	public void encryptWithGluu_RSA_OAEP_256_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_RSA_OAEP_256();
		System.out.println("Gluu encrypted (RSA_OAEP_256): " + jwt);

		assertTrue(testDecryptWithGluuDecrypter_RSA_OAEP_256(jwt));
	}

	@Test
	public void encryptWithGluu_RSA_OAEP_256_HS512_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_RSA_OAEP_256_HS512();
		System.out.println("Gluu encrypted (RSA_OAEP_256_HS512): " + jwt);

		assertTrue(testDecryptWithGluuDecrypter_RSA_OAEP_256_HS512(jwt));
	}

	@Test
	public void encryptWithGluu_RSA1_5_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_RSA1_5();
		System.out.println("Gluu encrypted (RSA1_5): " + jwt);

		assertTrue(testDecryptWithGluuDecrypter_RSA1_5(jwt));
	}

	@Test
	public void encryptWithGluu_ECDH_ES_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_ECDH_ES();
		System.out.println("Gluu encrypted (ECDH_E): " + jwt);

		assertTrue(testDecryptWithGluuDecrypter_ECDH_ES(jwt));
	}

	@Test
	public void encryptWithGluu_A128KW_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_A128KW();
		System.out.println("Gluu encrypted (A128KW): " + jwt);

		assertTrue(testDecryptWithGluuDecrypter_A128KW(jwt));
	}

	@Test
	public void encryptWithGluu_A192KW_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_A192KW();
		System.out.println("Gluu encrypted (A192KW): " + jwt);

		assertTrue(testDecryptWithGluuDecrypter_A192KW(jwt));
	}

	@Test
	public void encryptWithGluu_A256KW_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_A256KW();
		System.out.println("Gluu encrypted (A256KW): " + jwt);

		assertTrue(testDecryptWithGluuDecrypter_A256KW(jwt));
	}

	@Test
	public void encryptWithGluu_A128GCMKW_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_A128GCMKW();
		System.out.println("Gluu encrypted (A128GCMKW): " + jwt);
		
		assertTrue(testDecryptWithGluuDecrypter_A128GCMKW(jwt));
	}

	@Test
	public void encryptWithGluu_A192GCMKW_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_A192GCMKW();
		System.out.println("Gluu encrypted (A192GCMKW): " + jwt);
		
		assertTrue(testDecryptWithGluuDecrypter_A192GCMKW(jwt));
	}

	@Test
	public void encryptWithGluu_A256GCMKW_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_A256GCMKW();
		System.out.println("Gluu encrypted (A192GCMKW): " + jwt);
		
		assertTrue(testDecryptWithGluuDecrypter_A256GCMKW(jwt));
	}

	@Test
	public void encryptWithGluu_A256GCMKW_A256CBC_PLUS_HS512_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_A256GCMKW_A256CBC_PLUS_HS512();
		System.out.println("Gluu encrypted (A256GCMKW_A256CBC_PLUS_HS512): " + jwt);
		
		assertTrue(testDecryptWithGluuDecrypter_A256GCMKW_A256CBC_PLUS_HS512(jwt));
	}

	@Test
	public void encryptWithGluu_PBES2_HS256_PLUS_A128KW_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_PBES2_HS256_PLUS_A128KW();
		System.out.println("Gluu encrypted (PBES2_HS256_PLUS_A128KW): " + jwt);
		
		assertTrue(testDecryptWithGluuDecrypter_PBES2_HS256_PLUS_A128KW(jwt));
	}

	@Test
	public void encryptWithGluu_PBES2_HS384_PLUS_A192KW_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_PBES2_HS384_PLUS_A192KW();
		System.out.println("Gluu encrypted (PBES2_HS384_PLUS_A192KW): " + jwt);
		
		assertTrue(testDecryptWithGluuDecrypter_PBES2_HS384_PLUS_A192KW(jwt));
	}

	@Test
	public void encryptWithGluu_PBES2_HS512_PLUS_A256KW_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_PBES2_HS512_PLUS_A256KW();
		System.out.println("Gluu encrypted (PBES2_HS512_PLUS_A256KW): " + jwt);
		
		assertTrue(testDecryptWithGluuDecrypter_PBES2_HS512_PLUS_A256KW(jwt));
	}

	@Test
	public void encryptWithGluu_Direct_128GCM_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_Direct_128GCM();
		System.out.println("Gluu encrypted (Direct_128GCM): " + jwt);
		
		assertTrue(testDecryptWithGluuDecrypter_Direct_128GCM(jwt));		
		return;
	}

	@Test
	public void encryptWithGluu_Direct_192GCM_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_Direct_192GCM();
		System.out.println("Gluu encrypted (Direct_192CM): " + jwt);
		
		assertTrue(testDecryptWithGluuDecrypter_Direct_192GCM(jwt));			
		return;
	}

	@Test
	public void encryptWithGluu_Direct_256GCM_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_Direct_256GCM();
		System.out.println("Gluu encrypted (Direct_256CM): " + jwt);

		assertTrue(testDecryptWithGluuDecrypter_Direct_256GCM(jwt));		
		return;
	}

	@Test
	public void encryptWithGluu_Direct_A128CBC_HS256_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_Direct_A128CBC_HS256();
		System.out.println("Gluu encrypted (Direct_A128CBC_HS256): " + jwt);
		
		assertTrue(testDecryptWithGluuDecrypter_Direct_A128CBC_HS256(jwt));		
		return;		
	}

	@Test
	public void encryptWithGluu_Direct_A192CBC_HS384_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_Direct_A192CBC_HS384();
		System.out.println("Gluu encrypted (Direct_A192CBC_HS384): " + jwt);
		
		assertTrue(testDecryptWithGluuDecrypter_Direct_A192CBC_HS384(jwt));		
		return;			
	}

	@Test
	public void encryptWithGluu_Direct_A256CBC_HS512_decryptByAll() {
		final String jwt = encryptWithGluuJweEncrypter_Direct_A256CBC_HS512();
		System.out.println("Gluu encrypted (Direct_A256CBC_HS512): " + jwt);
		
		assertTrue(testDecryptWithGluuDecrypter_Direct_A256CBC_HS512(jwt));		
		return;			
	}

	@Test
	public void testNimbusJoseJwt_first() {

		// jwe produced by gluu 3.1.2 in development environment
		assertTrue(testDecryptNimbusJoseJwt(encryptedJweProducedByGluu));
	}

	@Test
	public void testNimbusJoseJwt_second() {

		// jwe produced by Gluu JweEncrypter
		assertTrue(testDecryptNimbusJoseJwt(encryptWithGluuJweEncrypter_RSA_OAEP()));
	}

	@Test
	public void testNimbusJoseJwt_third() {

		// jwe produced by Nimbus Jose+JWT
		assertTrue(testDecryptNimbusJoseJwt(encryptWithNimbusJoseJwt()));
	}

	@Test
	public void testNimbusJose4J_first() {

		// jwe produced by gluu 3.1.2 in development environment
		assertTrue(testDecryptWithJose4J(encryptedJweProducedByGluu));
	}

	@Test
	public void testNimbusJose4J_second() {

		// jwe produced by Gluu JweEncrypter
		assertTrue(testDecryptWithJose4J(encryptWithGluuJweEncrypter_RSA_OAEP()));
	}

	@Test
	public void testNimbusJose4J_third() {

		// jwe produced by Nimbus Jose+JWT
		assertTrue(testDecryptWithJose4J(encryptWithNimbusJoseJwt()));
	}

	@Test
	public void testGluuJweDecrypter_first() {
		String str = encryptWithNimbusJoseJwt();
		System.out.println(str);
		System.out.println(encryptedJweProducedByGluu);

		// jwe produced by gluu 3.1.2 in development environment
		assertTrue(testDecryptWithGluuDecrypter_RSA_OAEP(encryptedJweProducedByGluu));
	}

	@Test
	public void testGluuJweDecrypter_second() {

		// jwe produced by Gluu JweEncrypter
		assertTrue(testDecryptWithGluuDecrypter_RSA_OAEP(encryptWithGluuJweEncrypter_RSA_OAEP()));
	}

	@Test
	public void testGluuJweDecrypter_third() {

		// jwe produced by Nimbus Jose+JWT
		assertTrue(testDecryptWithGluuDecrypter_RSA_OAEP(encryptWithNimbusJoseJwt()));
	}
	
	@Test
	public void encryptWithGluu_RSA_decryptByAll() {
		for(KeyEncryptionAlgorithmSuite keyEncrAlgorithmRSA : keyEnrAlgorithmsRSA) {
			for(BlockEncryptionAlgorithm blckEncrAlgorithm: blockEncryptionAlgorithms) {			
				System.out.println("Gluu encrypted (encryptWithGluu_RSA_decryptByAll):  blckEncrAlgorithm = " + blckEncrAlgorithm);				
				System.out.println("Gluu encrypted (encryptWithGluu_RSA_decryptByAll):  keyEncrAlgorithmRSA.keyEncrAlg = " + keyEncrAlgorithmRSA.keyEncrAlg);				
				System.out.println("Gluu encrypted (encryptWithGluu_RSA_decryptByAll):  keyEncrAlgorithmRSA.keyData1 = " + keyEncrAlgorithmRSA.keyData1);				
				System.out.println("Gluu encrypted (encryptWithGluu_RSA_decryptByAll):  keyEncrAlgorithmRSA.keyData2 = " + keyEncrAlgorithmRSA.keyData2);
				System.out.println("Gluu encrypted (encryptWithGluu_RSA_decryptByAll):  keyEncrAlgorithmRSA.encData2 = " + keyEncrAlgorithmRSA.encData2);				
				try {
					RSAKey rsaPublicKey = (RSAKey) (JWK.parse(keyEncrAlgorithmRSA.keyData1));

					BlockEncryptionAlgorithm blockEncryptionAlgorithm = blckEncrAlgorithm;
					KeyEncryptionAlgorithm keyEncryptionAlgorithm = keyEncrAlgorithmRSA.keyEncrAlg;
					Jwe jwe = new Jwe();
					jwe.getHeader().setType(JwtType.JWT);
					jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
					jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
					jwe.getClaims().setIssuer("https:devgluu.saminet.local");
					jwe.getClaims().setSubjectIdentifier("testing");
					jwe.getHeader().setKeyId("1");

					JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
							rsaPublicKey.toPublicKey());
					jwe = encrypter.encrypt(jwe);
					System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
					System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
					System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
					System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
					System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
					final String jweStr = jwe.toString();
					
					RSAPrivateKey rsaPrivateKey = ((RSAKey) JWK.parse(keyEncrAlgorithmRSA.keyData1)).toRSAPrivateKey();

					JweDecrypterImpl decrypter = new JweDecrypterImpl(rsaPrivateKey);

					decrypter.setKeyEncryptionAlgorithm(keyEncryptionAlgorithm);
					decrypter.setBlockEncryptionAlgorithm(blockEncryptionAlgorithm);
					final String decryptedPayload = decrypter.decrypt(jweStr).getClaims().toJsonString().toString();
					
					assertTrue(isJsonEqual(decryptedPayload, PAYLOAD));
					
					try {
						final String decryptedPayloadWrong = decrypter.decrypt(keyEncrAlgorithmRSA.encData2).getClaims().toJsonString().toString();
						assertFalse(isJsonEqual(decryptedPayloadWrong, PAYLOAD));
						assertTrue(false);
					} catch (io.jans.as.model.exception.InvalidJweException e) {
						assertTrue(true);					
					}						
					
					RSAPrivateKey rsaPrivateKeyWrong = ((RSAKey) JWK.parse(keyEncrAlgorithmRSA.keyData2)).toRSAPrivateKey();
					
					decrypter = new JweDecrypterImpl(rsaPrivateKeyWrong);

					decrypter.setKeyEncryptionAlgorithm(keyEncryptionAlgorithm);
					decrypter.setBlockEncryptionAlgorithm(blockEncryptionAlgorithm);
					
					try {
						String decryptedPayloadWrong = decrypter.decrypt(jweStr).getClaims().toJsonString().toString();
						assertFalse(isJsonEqual(decryptedPayloadWrong, PAYLOAD));
						assertTrue(false);
					} catch (io.jans.as.model.exception.InvalidJweException e) {
						assertTrue(true);					
					}
					
					String decryptedPayloadWrong = decrypter.decrypt(keyEncrAlgorithmRSA.encData2).getClaims().toJsonString().toString();
					assertTrue(isJsonEqual(decryptedPayloadWrong, PAYLOAD));

				} catch (Exception e) {
					System.out.println("Error (encryptWithGluu_RSA_decryptByAll) : " +
							" blckEncrAlgorithm = " + blckEncrAlgorithm +
							" keyEnrAlgorithmRSA.keyEncrAlg = " + keyEncrAlgorithmRSA.keyEncrAlg + 
							" keyEnrAlgorithmRSA.keyData1 = " + keyEncrAlgorithmRSA.keyData1 +
							" message: " + e.getMessage());
					assertTrue(false);					
				}
			}
		}
	}	
	
	@Test
	public void encryptWithGluu_ECDH_decryptByAll() {
		for(KeyEncryptionAlgorithmSuite keyEnrAlgorithmECDH : keyEnrAlgorithmsECDH) {
			BlockEncryptionAlgorithm[] blckEncrAlgorithms;		
			if(keyEnrAlgorithmECDH.blockEncryptionAlgorithms != null) {
				blckEncrAlgorithms = keyEnrAlgorithmECDH.blockEncryptionAlgorithms;
			}
			else {
				blckEncrAlgorithms = blockEncryptionAlgorithms;				
			}
			for(BlockEncryptionAlgorithm blckEncrAlgorithm: blckEncrAlgorithms) {		
				System.out.println("Gluu encrypted (encryptWithGluu_ECDH_decryptByAll):  blckEncrAlgorithm = " + blckEncrAlgorithm);				
				System.out.println("Gluu encrypted (encryptWithGluu_ECDH_decryptByAll):  keyEnrAlgorithmECDH.keyEncrAlg = " + keyEnrAlgorithmECDH.keyEncrAlg);				
				System.out.println("Gluu encrypted (encryptWithGluu_ECDH_decryptByAll):  keyEnrAlgorithmECDH.keyData1 = " + keyEnrAlgorithmECDH.keyData1);				
				System.out.println("Gluu encrypted (encryptWithGluu_ECDH_decryptByAll):  keyEnrAlgorithmECDH.keyData2 = " + keyEnrAlgorithmECDH.keyData2);				
				try {
					ECKey ecPublicKey = (ECKey) (JWK.parse(keyEnrAlgorithmECDH.keyData1));

					BlockEncryptionAlgorithm blockEncryptionAlgorithm = blckEncrAlgorithm;
					KeyEncryptionAlgorithm keyEncryptionAlgorithm = keyEnrAlgorithmECDH.keyEncrAlg;
					Jwe jwe = new Jwe();
					jwe.getHeader().setType(JwtType.JWT);
					jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
					jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
					jwe.getClaims().setIssuer("https:devgluu.saminet.local");
					jwe.getClaims().setSubjectIdentifier("testing");
					jwe.getHeader().setKeyId("1");

					JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
							ecPublicKey);
					jwe = encrypter.encrypt(jwe);
					System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
					System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
					System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
					System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
					System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
					final String jweStr = jwe.toString();
					
					ECPrivateKey ecPrivateKey = ((ECKey) JWK.parse(keyEnrAlgorithmECDH.keyData1)).toECPrivateKey();					

					JweDecrypterImpl decrypter = new JweDecrypterImpl(ecPrivateKey);

					decrypter.setKeyEncryptionAlgorithm(keyEncryptionAlgorithm);
					decrypter.setBlockEncryptionAlgorithm(blockEncryptionAlgorithm);
					final String decryptedPayload = decrypter.decrypt(jweStr).getClaims().toJsonString().toString();
					
					assertTrue(isJsonEqual(decryptedPayload, PAYLOAD));
				} catch (Exception e) {
					String message = "Error (encryptWithGluu_ECDH_decryptByAll) : " +
							" blckEncrAlgorithm = " + blckEncrAlgorithm +
							" keyEnrAlgorithmECDH.keyEncrAlg = " + keyEnrAlgorithmECDH.keyEncrAlg + 
							" keyEnrAlgorithmECDH.keyData1 = " + keyEnrAlgorithmECDH.keyData1 +
							" message: " + e.getMessage();
					System.out.println(message);
					assertTrue(false, message);
				}
			}
		}
	}
	
	@Test
	public void encryptWithGluu_AES_decryptByAll() throws ParseException, JOSEException, InvalidJweException, InvalidJwtException, IOException {
		for(KeyEncryptionAlgorithmSuite keyEnrAlgorithmAES : keyEnrAlgorithmsAES) {
			for(BlockEncryptionAlgorithm blckEncrAlgorithm: blockEncryptionAlgorithms) {		
				System.out.println("Gluu encrypted (encryptWithGluu_AES_decryptByAll):  blckEncrAlgorithm = " + blckEncrAlgorithm);				
				System.out.println("Gluu encrypted (encryptWithGluu_AES_decryptByAll):  keyEnrAlgorithmAES.keyEncrAlg = " + keyEnrAlgorithmAES.keyEncrAlg);				
				System.out.println("Gluu encrypted (encryptWithGluu_AES_decryptByAll):  keyEnrAlgorithmAES.keyData1 = " + keyEnrAlgorithmAES.keyData1);
				System.out.println("Gluu encrypted (encryptWithGluu_AES_decryptByAll):  keyEnrAlgorithmAES.keyData2 = " + keyEnrAlgorithmAES.keyData2);
				try {
					OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(keyEnrAlgorithmAES.keyData1));
	
					BlockEncryptionAlgorithm blockEncryptionAlgorithm = blckEncrAlgorithm;
					KeyEncryptionAlgorithm keyEncryptionAlgorithm = keyEnrAlgorithmAES.keyEncrAlg;
					Jwe jwe = new Jwe();
					jwe.getHeader().setType(JwtType.JWT);
					jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
					jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
					jwe.getClaims().setIssuer("https:devgluu.saminet.local");
					jwe.getClaims().setSubjectIdentifier("testing");
					jwe.getHeader().setKeyId("1");
	
					JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
							aesKey.toByteArray());
					jwe = encrypter.encrypt(jwe);
					System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
					System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
					System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
					System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
					System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
					final String jweStr = jwe.toString();
					
					aesKey = (OctetSequenceKey) (JWK.parse(keyEnrAlgorithmAES.keyData1));
	
					JweDecrypterImpl decrypter = new JweDecrypterImpl(aesKey.toByteArray());
	
					decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.A128KW);
					decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);
					final String decryptedPayload = decrypter.decrypt(jweStr).getClaims().toJsonString().toString();
					System.out.println("Gluu decrypt A128KW succeed: " + decryptedPayload);					
					
					assertTrue(isJsonEqual(decryptedPayload, PAYLOAD));
				} catch (Exception e) {
					String message = "Error (encryptWithGluu_AES_decryptByAll) : " +
							" blckEncrAlgorithm = " + blckEncrAlgorithm +
							" keyEnrAlgorithmAES.keyEncrAlg = " + keyEnrAlgorithmAES.keyEncrAlg + 
							" keyEnrAlgorithmAES.keyData1 = " + keyEnrAlgorithmAES.keyData1 +
							" message: " + e.getMessage();
					System.out.println(message);
					assertTrue(false, message);
				}				
			}
		}
	}
	
	@Test
	public void encryptWithGluu_Password_decryptByAll() {
		for(KeyEncryptionAlgorithmSuite keyEnrAlgorithmPassw : keyEnrAlgorithmsPassw) {
			for(BlockEncryptionAlgorithm blckEncrAlgorithm: blockEncryptionAlgorithms) {		
				System.out.println("Gluu encrypted (encryptWithGluu_Password_decryptByAll):  blckEncrAlgorithm = " + blckEncrAlgorithm);				
				System.out.println("Gluu encrypted (encryptWithGluu_Password_decryptByAll):  keyEnrAlgorithmAES.keyEncrAlg = " + keyEnrAlgorithmPassw.keyEncrAlg);				
				System.out.println("Gluu encrypted (encryptWithGluu_Password_decryptByAll):  keyEnrAlgorithmAES.keyData1 = " + keyEnrAlgorithmPassw.keyData1);
				System.out.println("Gluu encrypted (encryptWithGluu_Password_decryptByAll):  keyEnrAlgorithmAES.keyData2 = " + keyEnrAlgorithmPassw.keyData2);
				try {

					BlockEncryptionAlgorithm blockEncryptionAlgorithm = blckEncrAlgorithm;
					KeyEncryptionAlgorithm keyEncryptionAlgorithm = keyEnrAlgorithmPassw.keyEncrAlg;
					
					Jwe jwe = new Jwe();
					jwe.getHeader().setType(JwtType.JWT);
					jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
					jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
					jwe.getClaims().setIssuer("https:devgluu.saminet.local");
					jwe.getClaims().setSubjectIdentifier("testing");
					jwe.getHeader().setKeyId("1");

					JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm, keyEnrAlgorithmPassw.keyData1);
					jwe = encrypter.encrypt(jwe);
					System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
					System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
					System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
					System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
					System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
					final String jweStr = jwe.toString();
					
					JweDecrypterImpl decrypter = new JweDecrypterImpl(keyEnrAlgorithmPassw.keyData1);					

					decrypter.setKeyEncryptionAlgorithm(keyEncryptionAlgorithm);
					decrypter.setBlockEncryptionAlgorithm(blockEncryptionAlgorithm);
					final String decryptedPayload = decrypter.decrypt(jweStr).getClaims().toJsonString().toString();
					
					assertTrue(isJsonEqual(decryptedPayload, PAYLOAD));
				} catch (Exception e) {
					String message = "Error (encryptWithGluu_Password_decryptByAll) : " +
							" blckEncrAlgorithm = " + blckEncrAlgorithm +
							" keyEnrAlgorithmPassw.keyEncrAlg = " + keyEnrAlgorithmPassw.keyEncrAlg + 
							" keyEnrAlgorithmPassw.keyData1 = " + keyEnrAlgorithmPassw.keyData1 +
							" message: " + e.getMessage();
					System.out.println(message);
					assertTrue(false, message);
				}
			}
		}
	}	

	private String encryptWithGluuJweEncrypter_RSA_OAEP() {
		try {
			RSAKey recipientPublicJWK = (RSAKey) (JWK.parse(recipientJwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.RSA_OAEP;
			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					recipientPublicJWK.toPublicKey());
			jwe = encrypter.encrypt(jwe);
			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();
		} catch (Exception e) {
			System.out.println("Error encryption with Gluu JweEncrypter: " + e.getMessage());
		}
		return null;
	}

	private String encryptWithGluuJweEncrypter_RSA_OAEP_256() {
		try {
			RSAKey recipientPublicJWK = (RSAKey) (JWK.parse(recipientJwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A256GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.RSA_OAEP_256;
			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					recipientPublicJWK.toPublicKey());
			jwe = encrypter.encrypt(jwe);
			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();
		} catch (Exception e) {
			System.out.println("Error encryption with Gluu JweEncrypter: " + e.getMessage());
		}
		return null;		
	}

	private String encryptWithGluuJweEncrypter_RSA_OAEP_256_HS512() {
		try {
			RSAKey recipientPublicJWK = (RSAKey) (JWK.parse(recipientJwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A256CBC_PLUS_HS512;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.RSA_OAEP_256;
			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					recipientPublicJWK.toPublicKey());
			jwe = encrypter.encrypt(jwe);
			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();
		} catch (Exception e) {
			System.out.println("Error encryption with Gluu JweEncrypter: " + e.getMessage());
		}
		return null;		
	}

	private String encryptWithGluuJweEncrypter_RSA1_5() {
		try {
			RSAKey recipientPublicJWK = (RSAKey) (JWK.parse(recipientJwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.RSA1_5;
			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					recipientPublicJWK.toPublicKey());
			jwe = encrypter.encrypt(jwe);
			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();
		} catch (Exception e) {
			System.out.println("Error encryption with Gluu JweEncrypter: " + e.getMessage());
		}
		return null;		
	}

	private String encryptWithGluuJweEncrypter_ECDH_ES() {
		try {
			ECKey recipientPublicJWK = (ECKey) (JWK.parse(ecJwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.ECDH_ES;
			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					recipientPublicJWK);
			jwe = encrypter.encrypt(jwe);
			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();
		} catch (Exception e) {
			System.out.println("Error encryption with Gluu JweEncrypter: " + e.getMessage());
		}
		return null;		
	}

	private String encryptWithNimbusJoseJwt() {
		try {
			RSAKey senderJWK = (RSAKey) JWK.parse(senderJwkJson);

			RSAKey recipientPublicJWK = (RSAKey) (JWK.parse(recipientJwkJson));

			// Create JWT
//			SignedJWT signedJWT = new SignedJWT(
//			    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(senderJWK.getKeyID()).build(),
//			    new JWTClaimsSet.Builder()
//			        .subject("testi")
//			        .issuer("https:devgluu.saminet.local")
//			        .build());

			// Sign the JWT
			// signedJWT.sign(new RSASSASigner(senderJWK));

			// Create JWE object with signed JWT as payload
			// JWEObject jweObject = new JWEObject(
			// new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM)
			// .contentType("JWT") // required to indicate nested JWT
			// .build(),
			// new Payload(signedJWT));

			@SuppressWarnings("deprecation")
			JWEObject jweObject = new JWEObject(
					new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM).type(JOSEObjectType.JWT)
							.keyID(senderJWK.getKeyID()).build(),
					new Payload(Base64Util.base64urlencode(PAYLOAD.getBytes(Charsets.UTF_8))));

			// Encrypt with the recipient's public key
			RSAEncrypter encrypter = new RSAEncrypter(recipientPublicJWK);
			jweObject.encrypt(encrypter);

			// System.out.println("Header: " + jweObject.getHeader());
			// System.out.println("Encrypted Key: " + jweObject.getEncryptedKey());
			// System.out.println("Cipher Text: " + jweObject.getCipherText());
			// System.out.println("IV: " + jweObject.getIV());
			// System.out.println("Auth Tag: " + jweObject.getAuthTag());

			// Serialise to JWE compact form
			return jweObject.serialize();
		} catch (Exception e) {
			System.out.println("Error encryption with Nimbus: " + e.getMessage());
		}
		return null;		
	}

	private String encryptWithGluuJweEncrypter_A128KW() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes128JwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.A128KW;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();

		} catch (Exception e) {
			System.out.println("Error encryption with GluuJweEncrypter_A128KW: " + e.getMessage());
		}
		return null;
	}

	private String encryptWithGluuJweEncrypter_A192KW() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes192JwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.A192KW;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();

		} catch (Exception e) {
			System.out.println("Error encryption with GluuJweEncrypter_A192KW: " + e.getMessage());
		}
		return null;
	}

	private String encryptWithGluuJweEncrypter_A256KW() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes256JwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.A256KW;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();

		} catch (Exception e) {
			System.out.println("Error encryption with GluuJweEncrypter_A256KW: " + e.getMessage());
		}
		return null;
	}

	private String encryptWithGluuJweEncrypter_A128GCMKW() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes128GCMKJwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.A128GCMKW;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();

		} catch (Exception e) {
			System.out.println("Error encryption with GluuJweEncrypter_A128GCMKW: " + e.getMessage());
		}
		return null;
	}

	private String encryptWithGluuJweEncrypter_A192GCMKW() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes192GCMKJwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.A192GCMKW;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();

		} catch (Exception e) {
			System.out.println("Error encryption with GluuJweEncrypter_A192GCMKW: " + e.getMessage());
		}
		return null;
	}

	private String encryptWithGluuJweEncrypter_A256GCMKW() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes256GCMKJwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.A256GCMKW;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();

		} catch (Exception e) {
			System.out.println("Error encryption with GluuJweEncrypter_A256GCMKW: " + e.getMessage());
		}
		return null;
	}

	private String encryptWithGluuJweEncrypter_A256GCMKW_A256CBC_PLUS_HS512() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes256GCMKJwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A256CBC_PLUS_HS512;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.A256GCMKW;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();

		} catch (Exception e) {
			System.out
					.println("Error encryption with GluuJweEncrypter_A256GCMKW_A256CBC_PLUS_HS512: " + e.getMessage());
		}
		return null;
	}

	private String encryptWithGluuJweEncrypter_PBES2_HS256_PLUS_A128KW() {
		try {
			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.PBES2_HS256_PLUS_A128KW;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm, passwordValue);
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();

		} catch (Exception e) {
			System.out.println("Error encryption with GluuJweEncrypter_PBES2_HS256_PLUS_A128KW: " + e.getMessage());
		}
		return null;
	}

	private String encryptWithGluuJweEncrypter_PBES2_HS384_PLUS_A192KW() {
		try {
			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128CBC_PLUS_HS256;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.PBES2_HS384_PLUS_A192KW;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm, passwordValue);
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();

		} catch (Exception e) {
			System.out.println("Error encryption with GluuJweEncrypter_PBES2_HS384_PLUS_A192KW: " + e.getMessage());
		}
		return null;
	}

	private String encryptWithGluuJweEncrypter_PBES2_HS512_PLUS_A256KW() {
		try {
			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A256CBC_PLUS_HS512;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.PBES2_HS512_PLUS_A256KW;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm, passwordValue);
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());
			return jwe.toString();

		} catch (Exception e) {
			System.out.println("Error encryption with GluuJweEncrypter_PBES2_HS512_PLUS_A256KW: " + e.getMessage());
		}
		return null;
	}

	private String encryptWithGluuJweEncrypter_Direct_128GCM() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes128JwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.DIR;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());

			return jwe.toString();
		} catch (Exception e) {
			System.out.println("Error encryption with Direct_128GCM: " + e.getMessage());
		}
		return null;
	}
	
	private String encryptWithGluuJweEncrypter_Direct_192GCM() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes192JwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A192GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.DIR;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());

	        return jwe.toString();            

		} catch (Exception e) {
			System.out.println("Error encryption with Direct_192GCM: " + e.getMessage());
		}
		return null;
	}
	
	private String encryptWithGluuJweEncrypter_Direct_256GCM() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes256JwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A256GCM;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.DIR;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());

	        return jwe.toString();            

		} catch (Exception e) {
			System.out.println("Error encryption with Direct_256GCM: " + e.getMessage());
		}
		return null;
	}
	
	private String encryptWithGluuJweEncrypter_Direct_A128CBC_HS256() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes256JwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128CBC_HS256;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.DIR;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());

			return jwe.toString();
		} catch (Exception e) {
			System.out.println("Error encryption with Direct_A128CBC_HS256: " + e.getMessage());
		}
		return null;
	}
	
	private String encryptWithGluuJweEncrypter_Direct_A192CBC_HS384() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes384JwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A192CBC_HS384;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.DIR;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());

			return jwe.toString();

		} catch (Exception e) {
			System.out.println("Error encryption with Direct_A192CBC_HS384: " + e.getMessage());
		}
		return null;
	}
	
	private String encryptWithGluuJweEncrypter_Direct_A256CBC_HS512() {
		try {
			OctetSequenceKey aesKey = (OctetSequenceKey) (JWK.parse(aes512JwkJson));

			BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A256CBC_HS512;
			KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.DIR;

			Jwe jwe = new Jwe();
			jwe.getHeader().setType(JwtType.JWT);
			jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
			jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
			jwe.getClaims().setIssuer("https:devgluu.saminet.local");
			jwe.getClaims().setSubjectIdentifier("testing");
			jwe.getHeader().setKeyId("1");

			JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
					aesKey.toByteArray());
			jwe = encrypter.encrypt(jwe);

			System.out.println("EncodedHeader: " + jwe.getEncodedHeader());
			System.out.println("EncodedEncryptedKey: " + jwe.getEncodedEncryptedKey());
			System.out.println("EncodedInitializationVector: " + jwe.getEncodedInitializationVector());
			System.out.println("EncodedCiphertext: " + jwe.getEncodedCiphertext());
			System.out.println("EncodedIntegrityValue: " + jwe.getEncodedIntegrityValue());

			return jwe.toString();
		} catch (Exception e) {
			System.out.println("Error encryption with Direct_A256CBC_HS512: " + e.getMessage());
			assertTrue(false);
		}
		return null;		
	}		

	private boolean testDecryptNimbusJoseJwt(String jwe) {
		try {
			EncryptedJWT encryptedJwt = EncryptedJWT.parse(jwe);
			// EncryptedJWT encryptedJwt = EncryptedJWT.parse(encryptWithGluu());
			// EncryptedJWT encryptedJwt = EncryptedJWT.parse(encryptWithNimbus());

			JWK jwk = JWK.parse(recipientJwkJson);
			RSAPrivateKey rsaPrivateKey = ((RSAKey) jwk).toRSAPrivateKey();

			JWEDecrypter decrypter = new RSADecrypter(rsaPrivateKey);
			decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

			encryptedJwt.decrypt(decrypter);
			final String decryptedPayload = new String(
					Base64Util.base64urldecode(encryptedJwt.getPayload().toString()));
			System.out.println("Nimbusds decrypt JoseJwt succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Nimbusds decrypt JoseJwt failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private static boolean isJsonEqual(String json1, String json2) throws IOException {
		ObjectMapper mapper = new ObjectMapper();
		JsonNode tree1 = mapper.readTree(json1);
		JsonNode tree2 = mapper.readTree(json2);
		return tree1.equals(tree2);
	}

	private boolean testDecryptWithJose4J(String jwe) {
		try {

			PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(recipientJwkJson);

			JsonWebEncryption receiverJwe = new JsonWebEncryption();

			AlgorithmConstraints algConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
					KeyManagementAlgorithmIdentifiers.RSA_OAEP);
			receiverJwe.setAlgorithmConstraints(algConstraints);
			AlgorithmConstraints encConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
					ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);
			receiverJwe.setContentEncryptionAlgorithmConstraints(encConstraints);

			receiverJwe.setKey(jwk.getPrivateKey());

			receiverJwe.setCompactSerialization(jwe);
			final String decryptedPayload = new String(Base64Util.base64urldecode(receiverJwe.getPlaintextString()));
			System.out.println("Jose4j decrypt Jose4J succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Jose4j decrypt Jose4J failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_RSA_OAEP(String jwe) {
		try {
			JWK jwk = JWK.parse(recipientJwkJson);
			RSAPrivateKey rsaPrivateKey = ((RSAKey) jwk).toRSAPrivateKey();

			JweDecrypterImpl decrypter = new JweDecrypterImpl(rsaPrivateKey);

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt RSA_OAEP succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt RSA_OAEP failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_RSA_OAEP_256(String jwe) {
		try {
			JWK jwk = JWK.parse(recipientJwkJson);
			RSAPrivateKey rsaPrivateKey = ((RSAKey) jwk).toRSAPrivateKey();

			JweDecrypterImpl decrypter = new JweDecrypterImpl(rsaPrivateKey);

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP_256);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A256GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt RSA_OAEP_256 succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt RSA_OAEP_256 failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_RSA_OAEP_256_HS512(String jwe) {
		try {
			JWK jwk = JWK.parse(recipientJwkJson);
			RSAPrivateKey rsaPrivateKey = ((RSAKey) jwk).toRSAPrivateKey();

			JweDecrypterImpl decrypter = new JweDecrypterImpl(rsaPrivateKey);

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP_256);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt RSA_OAEP_256_HS512 succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt RSA_OAEP_256_HS512 failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_RSA1_5(String jwe) {
		try {
			JWK jwk = JWK.parse(recipientJwkJson);
			RSAPrivateKey rsaPrivateKey = ((RSAKey) jwk).toRSAPrivateKey();

			JweDecrypterImpl decrypter = new JweDecrypterImpl(rsaPrivateKey);

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.RSA1_5);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt RSA1_5 succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt RSA1_5 failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_ECDH_ES(String jwe) {
		try {
			JWK jwk = JWK.parse(ecJwkJson);
			ECPrivateKey ecPrivateKey = ((ECKey) jwk).toECPrivateKey();

			JweDecrypterImpl decrypter = new JweDecrypterImpl(ecPrivateKey);

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.ECDH_ES);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt ECDH_ES succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt ECDH_ES failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_A128KW(String jwe) {
		try {
			JWK jwk = JWK.parse(aes128JwkJson);
			OctetSequenceKey aesKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aesKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.A128KW);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt A128KW succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt A128KW failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_A192KW(String jwe) {
		try {
			JWK jwk = JWK.parse(aes192JwkJson);
			OctetSequenceKey aesKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aesKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.A192KW);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt A192KW succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt A192KW failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_A256KW(String jwe) {
		try {
			JWK jwk = JWK.parse(aes256JwkJson);
			OctetSequenceKey aesKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aesKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.A256KW);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt A256KW succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt A256KW failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_A128GCMKW(String jwe) {
		try {
			JWK jwk = JWK.parse(aes128GCMKJwkJson);
			OctetSequenceKey aesKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aesKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.A128GCMKW);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt A128GCMKW succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt A128GCMKW failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_A192GCMKW(String jwe) {
		try {
			JWK jwk = JWK.parse(aes192GCMKJwkJson);
			OctetSequenceKey aesKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aesKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.A192GCMKW);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt A192GCMKW succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt A192GCMKW failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_A256GCMKW(String jwe) {
		try {
			JWK jwk = JWK.parse(aes256GCMKJwkJson);
			OctetSequenceKey aesKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aesKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.A256GCMKW);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt A256GCMKW succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt A256GCMKW failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_A256GCMKW_A256CBC_PLUS_HS512(String jwe) {
		try {
			JWK jwk = JWK.parse(aes256GCMKJwkJson);
			OctetSequenceKey aesKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aesKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.A256GCMKW);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt A256GCMKW succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt A256GCMKW failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_PBES2_HS256_PLUS_A128KW(String jwe) {

		try {
			JweDecrypterImpl decrypter = new JweDecrypterImpl("password");

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.PBES2_HS256_PLUS_A128KW);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt PBES2_HS256_PLUS_A128KW succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt PBES2_HS256_PLUS_A128KW failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_PBES2_HS384_PLUS_A192KW(String jwe) {
		try {
			JweDecrypterImpl decrypter = new JweDecrypterImpl("password");

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.PBES2_HS384_PLUS_A192KW);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128CBC_PLUS_HS256);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt PBES2_HS384_PLUS_A192KW succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt PBES2_HS384_PLUS_A192KW failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}

	private boolean testDecryptWithGluuDecrypter_PBES2_HS512_PLUS_A256KW(String jwe) {
		try {
			JweDecrypterImpl decrypter = new JweDecrypterImpl("password");

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.PBES2_HS512_PLUS_A256KW);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt PBES2_HS384_PLUS_A256K succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt PBES2_HS512_PLUS_A256KW failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}
	
	private boolean testDecryptWithGluuDecrypter_Direct_128GCM(String jwe) {
		try {
			JWK jwk = JWK.parse(aes128JwkJson);
			OctetSequenceKey aesKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aesKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.DIR);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt Direct_128GCM succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);
		} catch (Exception e) {
			System.out.println("Gluu decrypt Direct_128GCM failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}	
	
	private boolean testDecryptWithGluuDecrypter_Direct_192GCM(String jwe) {
		try {
			JWK jwk = JWK.parse(aes192JwkJson);
			OctetSequenceKey aesKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aesKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.DIR);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A192GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt Direct_192GCM succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);
		} catch (Exception e) {
			System.out.println("Gluu decrypt Direct_192GCM failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}
	
	private boolean testDecryptWithGluuDecrypter_Direct_256GCM(String jwe) {
		try {
			JWK jwk = JWK.parse(aes256JwkJson);
			OctetSequenceKey aesKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aesKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.DIR);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A256GCM);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt Direct_256GCM succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);
		} catch (Exception e) {
			System.out.println("Gluu decrypt Direct_256GCM failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}
	
	private boolean testDecryptWithGluuDecrypter_Direct_A128CBC_HS256(String jwe) {
		try {
			JWK jwk = JWK.parse(aes256JwkJson);
			OctetSequenceKey aes128KWKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aes128KWKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.DIR);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128CBC_HS256);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt Direct_A128CBC_HS256 succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt Direct_A128CBC_HS256 failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;		
	}
	
	private boolean testDecryptWithGluuDecrypter_Direct_A192CBC_HS384(String jwe) {
		try {
			JWK jwk = JWK.parse(aes384JwkJson);
			OctetSequenceKey aes128KWKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aes128KWKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.DIR);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A192CBC_HS384);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt Direct_A192CBC_HS384 succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);			
		} catch (Exception e) {
			System.out.println("Gluu decrypt Direct_A192CBC_HS384 failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;		
	}
	
	private boolean testDecryptWithGluuDecrypter_Direct_A256CBC_HS512(String jwe) {
		try {
			JWK jwk = JWK.parse(aes512JwkJson);
			OctetSequenceKey aes128KWKey = (OctetSequenceKey) jwk;

			JweDecrypterImpl decrypter = new JweDecrypterImpl(aes128KWKey.toByteArray());

			decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.DIR);
			decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A256CBC_HS512);
			final String decryptedPayload = decrypter.decrypt(jwe).getClaims().toJsonString().toString();
			System.out.println("Gluu decrypt Direct_A256CBC_HS512 succeed: " + decryptedPayload);
			return isJsonEqual(decryptedPayload, PAYLOAD);					
		} catch (Exception e) {
			System.out.println("Gluu decrypt Direct_A256CBC_HS512 failed: " + e.getMessage());
			e.printStackTrace();
		}
		return false;
	}	

	@Test
	public void nestedJWT() throws Exception {

		RSAKey senderJWK = (RSAKey) JWK.parse(senderJwkJson);

		RSAKey recipientPublicJWK = (RSAKey) (JWK.parse(recipientJwkJson));

		// Create JWT
		SignedJWT signedJWT = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(senderJWK.getKeyID()).build(),
				new JWTClaimsSet.Builder().subject("testing").issuer("https:devgluu.saminet.local").build());

		signedJWT.sign(new RSASSASigner(senderJWK));

		JWEObject jweObject = new JWEObject(
				new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM).contentType("JWT") // required to
																											// indicate
																											// nested
																											// JWT
						.build(),
				new Payload(signedJWT));

		// Encrypt with the recipient's public key
		RSAEncrypter encrypter = new RSAEncrypter(recipientPublicJWK);
		jweObject.encrypt(encrypter);

		final String jweString = jweObject.serialize();

		decryptAndValidateSignatureWithGluu(jweString);
		decryptAndValidateSignatureWithNimbus(jweString);
	}

	@Test
	public void nestedJWTProducedByGluu() throws Exception {
		AppConfiguration appConfiguration = new AppConfiguration();

		List<JSONWebKey> keyArrayList = new ArrayList<JSONWebKey>();
		keyArrayList.add(getSenderWebKey());

		JSONWebKeySet keySet = new JSONWebKeySet();
		keySet.setKeys(keyArrayList);

		final JwtSigner jwtSigner = new JwtSigner(appConfiguration, keySet, SignatureAlgorithm.RS256, "audience", null,
				new AbstractCryptoProvider() {
					@Override
					public JSONObject generateKey(Algorithm algorithm, Long expirationTime, Use use) throws Exception {
						return null;
					}

					@Override
					public boolean containsKey(String keyId) {
						return false;
					}

					@Override
					public String sign(String signingInput, String keyId, String sharedSecret,
							SignatureAlgorithm signatureAlgorithm) throws Exception {
						RSAPrivateKey privateKey = ((RSAKey) JWK.parse(senderJwkJson)).toRSAPrivateKey();

						Signature signature = Signature.getInstance(signatureAlgorithm.getAlgorithm(), "BC");
						signature.initSign(privateKey);
						signature.update(signingInput.getBytes());

						return Base64Util.base64urlencode(signature.sign());
					}

					@Override
					public boolean verifySignature(String signingInput, String encodedSignature, String keyId,
							JSONObject jwks, String sharedSecret, SignatureAlgorithm signatureAlgorithm)
							throws Exception {
						return false;
					}

					@Override
					public boolean deleteKey(String keyId) throws Exception {
						return false;
					}

					@Override
					public PrivateKey getPrivateKey(String keyId) throws Exception {
						throw new UnsupportedOperationException("Method not implemented.");
					}
				});
		Jwt jwt = jwtSigner.newJwt();
		jwt.getClaims().setSubjectIdentifier("testing");
		jwt.getClaims().setIssuer("https:devgluu.saminet.local");
		jwt = jwtSigner.sign();

		RSAKey recipientPublicJWK = (RSAKey) (JWK.parse(recipientJwkJson));

		BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.A128GCM;
		KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.RSA_OAEP;
		Jwe jwe = new Jwe();
		jwe.getHeader().setType(JwtType.JWT);
		jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
		jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
		jwe.getHeader().setKeyId("1");
		jwe.setSignedJWTPayload(jwt);

		JweEncrypterImpl encrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
				recipientPublicJWK.toPublicKey());
		String jweString = encrypter.encrypt(jwe).toString();

		decryptAndValidateSignatureWithGluu(jweString);
		decryptAndValidateSignatureWithNimbus(jweString);
	}

	private JSONWebKey getSenderWebKey() throws JSONException {
		return JSONWebKey.fromJSONObject(new JSONObject(senderJwkJson));
	}

	private RSAPublicKey getSenderPublicKey() {
		return RSAKeyFactory.valueOf(getSenderWebKey()).getPublicKey();
	}

	private void decryptAndValidateSignatureWithGluu(String jweString)
			throws ParseException, JOSEException, InvalidJweException, JSONException, InvalidJwtException {
		JWK jwk = JWK.parse(recipientJwkJson);
		RSAPrivateKey rsaPrivateKey = ((RSAKey) jwk).toRSAPrivateKey();

		JweDecrypterImpl decrypter = new JweDecrypterImpl(rsaPrivateKey);

		decrypter.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP);
		decrypter.setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.A128GCM);

		final Jwe jwe = decrypter.decrypt(jweString);
		assertEquals(JwtType.JWT, jwe.getHeader().getContentType());

		final Jwt jwt = jwe.getSignedJWTPayload();

		final RSAPublicKey senderPublicKey = RSAKeyFactory.valueOf(getSenderWebKey()).getPublicKey();
		Assert.assertTrue(new RSASigner(SignatureAlgorithm.RS256, senderPublicKey).validate(jwt));

		System.out.println(
				"Gluu decrypt and nested jwt signature verification succeed: " + jwt.getClaims().toJsonString());
	}

	private void decryptAndValidateSignatureWithNimbus(String jweString) throws ParseException, JOSEException {
		JWK jwk = JWK.parse(recipientJwkJson);
		RSAPrivateKey rsaPrivateKey = ((RSAKey) jwk).toRSAPrivateKey();

		JWEObject jweObject = JWEObject.parse(jweString);

		jweObject.decrypt(new RSADecrypter(rsaPrivateKey));
		SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

		assertNotNull("Payload not a signed JWT", signedJWT);

		RSAKey senderJWK = (RSAKey) JWK.parse(senderJwkJson);
		assertTrue(signedJWT.verify(new RSASSAVerifier(senderJWK)));

		assertEquals("testing", signedJWT.getJWTClaimsSet().getSubject());
		System.out.println("Nimbus decrypt and nested jwt signature verification succeed: "
				+ signedJWT.getJWTClaimsSet().toJSONObject());
	}
}