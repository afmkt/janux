use moka::future::Cache;
use std::borrow::Borrow;
use std::hash::Hash;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct EphemCache<K, V>
where
    K: Hash + Eq + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    inner: Cache<K, Arc<V>>,
}

impl<K, V> EphemCache<K, V>
where
    K: Hash + Eq + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(name: &str, ttl_sec: Option<u64>) -> Self {
        Self::with_capacity(name, ttl_sec, 10_000)
    }

    pub fn with_capacity(name: &str, ttl_sec: Option<u64>, max_capacity: u64) -> Self {
        let mut builder = Cache::builder().max_capacity(max_capacity).name(name);
        if let Some(secs) = ttl_sec {
            builder = builder.time_to_live(std::time::Duration::from_secs(secs));
        }
        Self {
            inner: builder.build(),
        }
    }

    pub async fn insert(&self, key: K, value: V) -> Result<(), String> {
        let entry = self.inner.entry(key).or_insert(Arc::new(value)).await;
        if entry.is_fresh() {
            Ok(())
        } else {
            Err("Key already exists".to_string())
        }
    }

    pub async fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.get(key).await.map(|arc| (*arc).clone())
    }

    /// Fetch and consume an entry atomically. `moka::Cache::remove`
    /// discards the entry and returns the prior value in one step, so two
    /// racing consumers can never both observe the same entry —
    /// a `get()`-then-`remove()` pair is racy.
    pub async fn get_one_shot<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.remove(key).await.map(|arc| (*arc).clone())
    }

    /// Mutable access to a cached value. moka stores values behind
    /// `Arc<V>` and never hands out references into the cache (entries
    /// can be evicted at any time), so a true `&mut V` cannot exist —
    /// instead the current value is cloned out, handed to `f` mutably,
    /// and written back atomically: moka serializes concurrent computes
    /// on the same key, so no update is lost (a get → mutate → insert
    /// sequence would race).
    ///
    /// Returns `Some(f's result)` when the key exists, `None` when it
    /// does not (nothing is inserted then) — so the `Option` doubles as
    /// the existence check.
    pub async fn get_mut<Q, F, R>(&self, key: &Q, f: F) -> Option<R>
    where
        K: Borrow<Q>,
        Q: ToOwned<Owned = K> + Hash + Eq + ?Sized,
        F: FnOnce(&mut V) -> R,
        R: Send,
    {
        // `f` runs inside moka's per-key compute, i.e. during the await
        // below, so its result is parked in a slot the closure can reach.
        let slot = Arc::new(std::sync::Mutex::new(None::<R>));
        let out = slot.clone();
        self.inner
            .entry_by_ref(key)
            .and_compute_with(move |entry| {
                let op = match entry {
                    Some(e) => {
                        let mut value = e.into_value().as_ref().clone();
                        *slot.lock().expect("get_mut slot poisoned") = Some(f(&mut value));
                        moka::ops::compute::Op::Put(Arc::new(value))
                    }
                    None => moka::ops::compute::Op::Nop,
                };
                async move { op }
            })
            .await;
        Arc::into_inner(out)
            .expect("get_mut slot is uniquely owned")
            .into_inner()
            .expect("get_mut slot poisoned")
    }

    pub async fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.contains_key(key)
    }

    pub async fn get_or_insert(&self, key: K, value: V) -> V
    where
        K: Hash + Eq + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let arc = self.inner.get_with(key, async { Arc::new(value) }).await;
        (*arc).clone()
    }

    /// Remove a single entry from the cache.
    /// Use [Self::invalidate] for TTL-based caches (more efficient).
    pub async fn remove<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.remove(key).await;
    }

    /// Invalidate a single entry — more efficient than remove for TTL-based caches.
    pub async fn invalidate<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.invalidate(key).await;
    }

    /// Invalidate all entries in the cache.
    pub async fn clear(&self) {
        self.inner.invalidate_all();
    }
}
