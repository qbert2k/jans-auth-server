/**
 * 
 */
package io.jans.as.model.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.exception.InvalidParameterException;
import io.jans.as.model.jwk.KeyType;

/**
 * @author Sergey Manoylo
 * 
 * @version August 24, 2021
 *
 */
public class JwkUtil {

    @SuppressWarnings("unused")
    private static final Logger log = LoggerFactory.getLogger(JwkUtil.class);

    /**
     * 
     * @param algFamily
     * @return
     * @throws InvalidParameterException
     */
    public static KeyType getKeyTypeFromAlgFamily(final AlgorithmFamily algFamily) throws InvalidParameterException {
        KeyType keyType = null;
        switch (algFamily) {
        case HMAC:
        case AES:
        case PASSW: {
            keyType = KeyType.OCT;
            break;
        }
        case RSA: {
            keyType = KeyType.RSA;
            break;
        }
        case EC: {
            keyType = KeyType.EC;
            break;
        }
        case ED: {
            keyType = KeyType.OKP;
            break;
        }
        default: {
            throw new InvalidParameterException("Wrong value of AlgorithmFamily: algFamily = " + algFamily);
        }
        }
        return keyType;
    }
}
