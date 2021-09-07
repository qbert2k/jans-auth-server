/**
 * 
 */
package io.jans.as.server.comp;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.jans.as.server.BaseTest;

/**
 * @author Sergey Manoylo
 * @version September 7, 2021 
 *
 */
public class JwtVerifyerTest extends BaseTest {
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    

}
