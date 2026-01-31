package com.thehook.ias.authorize;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Slf4j
@Service
public class AuthorizeCacheService {

    public static final String CACHE_NAME = "authorization";

    private final CacheManager cacheManager;

    public AuthorizeCacheService(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    public void evictUserOrgCache(UUID userId, UUID orgId) {
        var cache = cacheManager.getCache(CACHE_NAME);
        if (cache != null) {
            cache.clear();
            log.debug("Authorization cache cleared for user {} in org {}", userId, orgId);
        }
    }

    public void evictAll() {
        var cache = cacheManager.getCache(CACHE_NAME);
        if (cache != null) {
            cache.clear();
            log.debug("Authorization cache cleared completely");
        }
    }
}
