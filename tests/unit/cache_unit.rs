//! Unit tests for the EphemCache (Moka-based in-memory cache).
use janux::cache::EphemCache;

// ─── Insert / get operations ──────────────────────────────────────────────────

#[tokio::test]
async fn test_insert_and_get() {
    let cache: EphemCache<String, String> = EphemCache::new("test_insert", Some(60));
    let result = cache.insert("key1".to_string(), "value1".to_string()).await;
    assert!(result.is_ok());

    let got = cache.get(&"key1".to_string()).await;
    assert_eq!(got, Some("value1".to_string()));
}

#[tokio::test]
async fn test_get_missing_key_returns_none() {
    let cache: EphemCache<String, String> = EphemCache::new("test_miss", Some(60));
    let got = cache.get(&"missing-key".to_string()).await;
    assert_eq!(got, None);
}

#[tokio::test]
async fn test_insert_duplicate_key_rejected() {
    let cache: EphemCache<String, String> = EphemCache::new("test_dup", Some(60));

    let first = cache.insert("key1".to_string(), "value1".to_string()).await;
    assert!(first.is_ok());

    // Inserting the same key again should be rejected
    let second = cache.insert("key1".to_string(), "value2".to_string()).await;
    assert!(second.is_err());
    assert_eq!(second.unwrap_err(), "Key already exists");
}

#[tokio::test]
async fn test_multiple_inserts_different_keys() {
    let cache: EphemCache<String, String> = EphemCache::new("test_multi", Some(60));

    for i in 0..100 {
        let result = cache
            .insert(format!("key_{}", i), format!("value_{}", i))
            .await;
        assert!(result.is_ok(), "Insert key_{} should succeed", i);
    }

    for i in 0..100 {
        let got = cache.get(&format!("key_{}", i)).await;
        assert_eq!(
            got,
            Some(format!("value_{}", i)),
            "Should retrieve value_{}",
            i
        );
    }
}

// ─── Contains key ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_contains_key_true() {
    let cache: EphemCache<String, String> = EphemCache::new("test_contains", Some(60));
    let key = "x".to_string();
    cache.insert(key.clone(), "y".to_string()).await.unwrap();

    assert!(cache.contains_key(&key).await);
}

#[tokio::test]
async fn test_contains_key_false() {
    let cache: EphemCache<String, String> = EphemCache::new("test_no_contains", Some(60));
    let key = "nonexistent".to_string();
    assert!(!cache.contains_key(&key).await);
}

// ─── Remove ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_remove_existing_key() {
    let cache: EphemCache<String, String> = EphemCache::new("test_remove", Some(60));

    let key = "key".to_string();
    cache
        .insert(key.clone(), "value".to_string())
        .await
        .unwrap();
    assert!(cache.contains_key(&key).await);

    cache.remove(&key).await;
    assert!(!cache.contains_key(&key).await);
}

#[tokio::test]
async fn test_remove_missing_key_no_panic() {
    let cache: EphemCache<String, String> = EphemCache::new("test_no_remove", Some(60));
    // Should not panic or error
    cache.remove(&"nonexistent".to_string()).await;
}

// ─── Clear ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_clear_removes_all_keys() {
    let cache: EphemCache<String, String> = EphemCache::new("test_clear", Some(60));

    for i in 0..10 {
        cache
            .insert(format!("k{}", i), format!("v{}", i))
            .await
            .unwrap();
    }

    // All keys present before clearing
    assert!(cache.contains_key(&"k9".to_string()).await);

    cache.clear().await;
    // Even k9 should be gone after clear
    assert!(!cache.contains_key(&"k9".to_string()).await);
}

// ─── get_or_insert ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_or_insert_creates_new() {
    let cache: EphemCache<String, String> = EphemCache::new("test_goi", Some(60));

    // Key doesn't exist yet
    let val = cache
        .get_or_insert("key".to_string(), "value".to_string())
        .await;
    assert_eq!(val, "value");
}

#[tokio::test]
async fn test_get_or_insert_returns_existing() {
    let cache: EphemCache<String, String> = EphemCache::new("test_goi_exist", Some(60));

    // First call creates entry
    let val1 = cache
        .get_or_insert("key".to_string(), "v1".to_string())
        .await;
    assert_eq!(val1, "v1");

    // Second call returns the same value (not v2!)
    let val2 = cache
        .get_or_insert("key".to_string(), "v2".to_string())
        .await;
    assert_eq!(val2, "v1");
}

// ─── get_one_shot (extract + remove) ──────────────────────────────────────

#[tokio::test]
async fn test_get_one_shot_removes_key() {
    let cache: EphemCache<String, String> = EphemCache::new("test_one_shot", Some(60));

    cache
        .insert("key".to_string(), "value".to_string())
        .await
        .unwrap();

    // get_one_shot should return and remove the value
    let val = cache.get_one_shot(&"key".to_string()).await;
    assert_eq!(val, Some("value".to_string()));

    // Key should now be gone
    assert!(!cache.contains_key(&"key".to_string()).await);
}

// ─── Invalidate (TTL-based) ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_invalidate_removes_entry() {
    let cache: EphemCache<String, String> = EphemCache::new("test_inv", Some(3600)); // TTL cache

    let key = "key".to_string();
    cache
        .insert(key.clone(), "value".to_string())
        .await
        .unwrap();
    assert!(cache.contains_key(&key).await);

    cache.invalidate(&key).await;
    assert!(!cache.contains_key(&key).await);
}

// ─── TTL configuration tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_ttl_enabled() {
    // Just verify it creates without error
    let _: EphemCache<String, String> = EphemCache::new("ttl_on", Some(60));
}

#[tokio::test]
async fn test_ttl_disabled_by_none() {
    // Just verify it creates without error
    let _: EphemCache<String, String> = EphemCache::new("no_ttl", None);
}

// ─── Multi-threaded concurrent insert / get ──────────────────────────────

#[tokio::test]
async fn test_concurrent_access() {
    use tokio::task;

    let cache: EphemCache<String, String> = EphemCache::new("concurrent", Some(60));

    // Spawn multiple tasks concurrently inserting and reading
    let mut handles = vec![];

    for i in 0..10 {
        let c = cache.clone();
        let h = task::spawn(async move {
            c.insert(format!("key_{}", i), format!("val_{}", i))
                .await
                .unwrap();
            let val = c.get(&format!("key_{}", i)).await;
            assert_eq!(val, Some(format!("val_{}", i)));

            assert!(c.contains_key(&format!("key_{}", i)).await);
        });
        handles.push(h);
    }

    for h in handles {
        h.await.unwrap();
    }
}

// ─── Large value handling ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_large_value_handling() {
    let cache: EphemCache<String, Vec<u8>> = EphemCache::new("big_val", Some(60));

    let big_data: Vec<u8> = vec![42u8; 10_000];
    assert!(
        cache
            .insert("big_key".to_string(), big_data.clone())
            .await
            .is_ok()
    );

    let retrieved = cache.get(&"big_key".to_string()).await;
    assert_eq!(retrieved, Some(big_data));
}

// ─── get_mut (atomic clone-mutate-writeback) ───────────────────────────────────

#[tokio::test]
async fn test_get_mut_mutates_and_returns_closure_result() {
    let cache: EphemCache<String, u64> = EphemCache::new("test_get_mut", Some(60));
    cache.insert("counter".to_string(), 1).await.unwrap();

    let result = cache
        .get_mut(&"counter".to_string(), |v| {
            *v += 41;
            *v
        })
        .await;
    assert_eq!(result, Some(42));
    assert_eq!(cache.get(&"counter".to_string()).await, Some(42));
}

#[tokio::test]
async fn test_get_mut_accepts_borrowed_keys() {
    let cache: EphemCache<String, u64> = EphemCache::new("test_get_mut_borrow", Some(60));
    cache.insert("counter".to_string(), 1).await.unwrap();

    // &str against a String key, like the other lookup methods.
    let result = cache.get_mut("counter", |v| *v + 1).await;
    assert_eq!(result, Some(2));
}

#[tokio::test]
async fn test_get_mut_missing_key_returns_none_and_inserts_nothing() {
    let cache: EphemCache<String, u64> = EphemCache::new("test_get_mut_miss", Some(60));

    let result = cache.get_mut(&"missing".to_string(), |v| *v + 1).await;
    assert_eq!(result, None);
    assert!(!cache.contains_key(&"missing".to_string()).await);
}

#[tokio::test]
async fn test_get_mut_serializes_concurrent_mutations() {
    let cache: EphemCache<String, u64> = EphemCache::new("test_get_mut_race", Some(60));
    cache.insert("counter".to_string(), 0).await.unwrap();

    let mut handles = Vec::new();
    for _ in 0..100 {
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            cache
                .get_mut(&"counter".to_string(), |v| {
                    *v += 1;
                    *v
                })
                .await
        }));
    }
    let mut last_seen = std::collections::HashSet::new();
    for h in handles {
        last_seen.insert(h.await.unwrap());
    }
    // A get → mutate → insert sequence would lose updates under
    // contention; moka's per-key lock serializes the computes, so every
    // caller observes a distinct running total.
    assert_eq!(last_seen.len(), 100);
    assert_eq!(cache.get(&"counter".to_string()).await, Some(100));
}
