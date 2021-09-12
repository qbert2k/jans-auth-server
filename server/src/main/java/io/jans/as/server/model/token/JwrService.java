/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.server.model.token;

import com.google.common.base.Function;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import io.jans.as.common.model.registration.Client;
import io.jans.as.model.config.WebKeysConfiguration;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.model.crypto.AbstractCryptoProvider;
import io.jans.as.model.crypto.encryption.BlockEncryptionAlgorithm;
import io.jans.as.model.crypto.encryption.KeyEncryptionAlgorithm;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.exception.InvalidJweException;
import io.jans.as.model.jwe.Jwe;
import io.jans.as.model.jwe.JweEncrypter;
import io.jans.as.model.jwe.JweEncrypterImpl;
import io.jans.as.model.jwk.Algorithm;
import io.jans.as.model.jwk.JSONWebKeySet;
import io.jans.as.model.jwk.JWKParameter;
import io.jans.as.model.jwk.Use;
import io.jans.as.model.jwt.Jwt;
import io.jans.as.model.jwt.JwtType;
import io.jans.as.model.token.JsonWebResponse;
import io.jans.as.model.util.JwtUtil;
import io.jans.as.server.model.common.IAuthorizationGrant;
import io.jans.as.server.service.ClientService;
import io.jans.as.server.service.SectorIdentifierService;
import io.jans.as.server.service.ServerCryptoProvider;
import org.apache.commons.lang.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;

import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.inject.Named;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

import static io.jans.as.model.jwt.JwtHeaderName.ALGORITHM;

/**
 * @author Yuriy Zabrovarnyy
 * @version April 10, 2020
 */
@Stateless
@Named
public class JwrService {

    @Inject
    private Logger log;

    @Inject
    private AbstractCryptoProvider cryptoProvider;

    @Inject
    private ClientService clientService;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private WebKeysConfiguration webKeysConfiguration;

    @SuppressWarnings("unused")
    @Inject
    private SectorIdentifierService sectorIdentifierService;

    /**
     * Encode means encrypt for Jwe and sign for Jwt, means it's implementaiton
     * specific but we want to abstract it.
     *
     * @return encoded Jwr
     */
    public io.jans.as.model.token.JsonWebResponse encode(io.jans.as.model.token.JsonWebResponse jwr, Client client)
            throws Exception {
        if (jwr instanceof Jwe) {
            return encryptJwe((Jwe) jwr, client);
        }
        if (jwr instanceof Jwt) {
            return signJwt((Jwt) jwr, client);
        }

        throw new IllegalArgumentException("Unknown Jwr instance.");
    }

    private Jwt signJwt(Jwt jwt, Client client) throws Exception {
        JwtSigner jwtSigner = JwtSigner.newJwtSigner(appConfiguration, webKeysConfiguration, client);
        jwtSigner.setJwt(jwt);
        jwtSigner.sign();
        return jwt;
    }

    private Jwe encryptJwe(Jwe jwe, Client client) throws Exception {
        if (appConfiguration.getUseNestedJwtDuringEncryption()) {
            JwtSigner jwtSigner = JwtSigner.newJwtSigner(appConfiguration, webKeysConfiguration, client);
            Jwt jwt = jwtSigner.newJwt();
            jwt.setClaims(jwe.getClaims());
            jwe.setSignedJWTPayload(signJwt(jwt, client));
        }
        final KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm
                .fromName(jwe.getHeader().getClaimAsString(ALGORITHM));
        final BlockEncryptionAlgorithm encryptionMethod = jwe.getHeader().getEncryptionMethod();
        final AlgorithmFamily keyEncryptionAlgorithmFamily = keyEncryptionAlgorithm.getFamily();
        if (keyEncryptionAlgorithmFamily == AlgorithmFamily.RSA) {
            JSONObject jsonWebKeys = JwtUtil.getJSONWebKeys(client.getJwksUri());
            String keyId = new ServerCryptoProvider(cryptoProvider).getKeyId(JSONWebKeySet.fromJSONObject(jsonWebKeys),
                    Algorithm.fromString(keyEncryptionAlgorithm.getName()), Use.ENCRYPTION);
            PublicKey publicKey = cryptoProvider.getPublicKey(keyId, jsonWebKeys, null);
            jwe.getHeader().setKeyId(keyId);
            if (publicKey == null) {
                throw new InvalidJweException("The public key is not valid");
            }
            JweEncrypter jweEncrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, encryptionMethod, publicKey);
            return jweEncrypter.encrypt(jwe);
        } else if (keyEncryptionAlgorithmFamily == AlgorithmFamily.EC) {
            JweEncrypter jweEncrypter = null;
            JSONObject jsonWebKeys = JwtUtil.getJSONWebKeys(client.getJwksUri());
            String keyId = new ServerCryptoProvider(cryptoProvider).getKeyId(JSONWebKeySet.fromJSONObject(jsonWebKeys),
                    Algorithm.fromString(keyEncryptionAlgorithm.getName()), Use.ENCRYPTION);
            JSONArray webKeys = jsonWebKeys.getJSONArray(JWKParameter.JSON_WEB_KEY_SET);
            JSONObject key = null;
            ECKey ecPublicKey = null;
            for (int i = 0; i < webKeys.length(); i++) {
                key = webKeys.getJSONObject(i);
                if (keyId.equals(key.getString(JWKParameter.KEY_ID))) {
                    ecPublicKey = (ECKey) (JWK.parse(key.toString()));
                    break;
                }
            }
            if (ecPublicKey == null) {
                throw new InvalidJweException("jweEncrypter was not created.");
            }
            jweEncrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, encryptionMethod, ecPublicKey);
            return jweEncrypter.encrypt(jwe);
        } else if (keyEncryptionAlgorithmFamily == AlgorithmFamily.AES
                || keyEncryptionAlgorithmFamily == AlgorithmFamily.DIR) {
            byte[] sharedSymmetricKey = clientService.decryptSecret(client.getClientSecret())
                    .getBytes(StandardCharsets.UTF_8);
            JweEncrypter jweEncrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, encryptionMethod,
                    sharedSymmetricKey);
            return jweEncrypter.encrypt(jwe);
        } else if (keyEncryptionAlgorithmFamily == AlgorithmFamily.PASSW) {
            String sharedSymmetricPassword = clientService.decryptSecret(client.getClientSecret());
            JweEncrypter jweEncrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, encryptionMethod,
                    sharedSymmetricPassword);
            return jweEncrypter.encrypt(jwe);
        }
        throw new IllegalArgumentException("Unsupported encryption algorithm: " + keyEncryptionAlgorithm);
    }

    public io.jans.as.model.token.JsonWebResponse createJwr(Client client) {
        try {
            KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm
                    .fromName(client.getIdTokenEncryptedResponseAlg());
            BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm
                    .fromName(client.getIdTokenEncryptedResponseEnc());

            if (keyEncryptionAlgorithm != null && blockEncryptionAlgorithm != null) {
                Jwe jwe = new Jwe();

                jwe.getHeader().setType(JwtType.JWT); // Header
                jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
                jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);
                return jwe;
            } else {
                JwtSigner jwtSigner = JwtSigner.newJwtSigner(appConfiguration, webKeysConfiguration, client);
                return jwtSigner.newJwt();
            }
        } catch (Exception e) {
            log.error("Failed to create token.", e);
            return null;
        }
    }

    public void setSubjectIdentifier(io.jans.as.model.token.JsonWebResponse jwr,
            IAuthorizationGrant authorizationGrant) {
        jwr.getClaims().setSubjectIdentifier(authorizationGrant.getSub());
    }

    public static Function<io.jans.as.model.token.JsonWebResponse, Void> wrapWithSidFunction(
            Function<JsonWebResponse, Void> input, String outsideSid) {
        return jwr -> {
            if (jwr == null) {
                return null;
            }
            if (input != null) {
                input.apply(jwr);
            }
            if (StringUtils.isNotEmpty(outsideSid)) {
                jwr.setClaim("sid", outsideSid);
            }
            return null;
        };
    }

}
