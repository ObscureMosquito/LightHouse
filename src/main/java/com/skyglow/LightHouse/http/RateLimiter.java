package com.skyglow.LightHouse.http;

import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate limiter by an arbitrary string, in practice a client IP.
 * Callers record only the events they consider abusive, so {@link #isLimited}
 * never counts against the caller.
 */
public final class RateLimiter {

    /** prevent DOS */
    private static final int SWEEP_THRESHOLD = 4096;

    private final int  limit;
    private final long windowMs;
    private final ConcurrentHashMap<String, ArrayDeque<Long>> hits = new ConcurrentHashMap<>();

    public RateLimiter(int limit, long windowMs) {
        this.limit    = limit;
        this.windowMs = windowMs;
    }

    public boolean isLimited(String key) {
        ArrayDeque<Long> events = hits.get(key);
        if (events == null) return false;
        synchronized (events) {
            expire(events, System.currentTimeMillis());
            return events.size() >= limit;
        }
    }

    public void record(String key) {
        long now = System.currentTimeMillis();
        ArrayDeque<Long> events = hits.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (events) {
            expire(events, now);
            events.addLast(now);
        }
        if (hits.size() > SWEEP_THRESHOLD) sweep(now);
    }

    private void expire(ArrayDeque<Long> events, long now) {
        while (!events.isEmpty() && now - events.peekFirst() > windowMs) events.pollFirst();
    }

    /** Drops keys whose events have all aged out. */
    private void sweep(long now) {
        for (Map.Entry<String, ArrayDeque<Long>> e : hits.entrySet()) {
            ArrayDeque<Long> events = e.getValue();
            synchronized (events) {
                expire(events, now);
                if (events.isEmpty()) hits.remove(e.getKey(), events);
            }
        }
    }
}
