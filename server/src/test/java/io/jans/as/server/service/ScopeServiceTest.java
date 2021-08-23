package io.jans.as.server.service;

import com.google.common.collect.Lists;
import io.jans.as.common.model.common.User;
import io.jans.as.common.service.AttributeService;
import io.jans.as.model.config.StaticConfiguration;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.persistence.model.Scope;
import io.jans.model.GluuAttribute;
import io.jans.orm.PersistenceEntryManager;
import io.jans.service.CacheService;
import io.jans.service.LocalCacheService;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.slf4j.Logger;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@Listeners(MockitoTestNGListener.class)
public class ScopeServiceTest {

    @InjectMocks
    private ScopeService scopeService;

    @Mock
    private Logger log;

    @Mock
    private AppConfiguration appConfiguration;

    @Mock
    private CacheService cacheService;

    @Mock
    private LocalCacheService localCacheService;

    @Mock
    private PersistenceEntryManager ldapEntryManager;

    @Mock
    private StaticConfiguration staticConfiguration;

    @Mock
    private AttributeService attributeService;

    @Mock
    private PersistenceEntryManager entryManager;

    @Test
    public void getClaimsScopeParamNull() throws Exception {
        User user = new User();

        Map<String, Object> result = scopeService.getClaims(user, null);

        assertNotNull(result);
        assertEquals(0, result.size());

        verify(log).trace("Scope is null.");
        verifyNoMoreInteractions(log);
        verifyNoMoreInteractions(attributeService);
    }

    @Test
    public void getClaimsScopeClaimsNull() throws Exception {
        User user = new User();
        Scope scope = new Scope();
        scope.setClaims(null);

        Map<String, Object> result = scopeService.getClaims(user, scope);

        assertNotNull(result);
        assertEquals(0, result.size());

        verify(log).trace(startsWith("No claims set for scope:"));
        verifyNoMoreInteractions(log);
        verifyNoMoreInteractions(attributeService);
    }

    @Test
    public void getClaimsNoAttributeFound() throws Exception {
        User user = new User();
        Scope scope = new Scope();
        scope.setClaims(Lists.newArrayList("claim1", "claim2"));

        when(attributeService.getAttributeByDn(anyString())).thenReturn(new GluuAttribute());

        Map<String, Object> result = scopeService.getClaims(user, scope);



        assertNotNull(result);
        assertEquals(0, result.size());

        verify(log, times(2)).error(startsWith("Failed to get claim because "));
        verifyNoMoreInteractions(log);
        verifyNoMoreInteractions(attributeService);
    }

}
