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

    /// Shared per-key compute machinery for [`Self::get_mut`] and
    /// [`Self::compute_or_insert`]. moka stores values behind `Arc<V>` and
    /// never hands out references into the cache (entries can be evicted
    /// at any time), so a true `&mut V` cannot exist — instead the value
    /// (existing, or created by `init` when absent) is handed to `f`
    /// mutably and written back inside moka's per-key compute, which
    /// serializes concurrent computes on the same key so no update is
    /// lost (a get → mutate → insert sequence would race). `f` runs
    /// during the await, so its result is parked in a slot the closure
    /// can reach. Returns `None` when the key was absent and no `init`
    /// was provided (nothing is inserted then).
    async fn compute_with_slot<Q, FI, F, R>(&self, key: &Q, init: Option<FI>, f: F) -> Option<R>
    where
        K: Borrow<Q>,
        Q: ToOwned<Owned = K> + Hash + Eq + ?Sized,
        FI: FnOnce() -> V,
        F: FnOnce(&mut V) -> R,
        R: Send,
    {
        let slot = Arc::new(std::sync::Mutex::new(None::<R>));
        let out = slot.clone();
        self.inner
            .entry_by_ref(key)
            .and_compute_with(move |entry| {
                let computed = match entry {
                    Some(e) => Some(e.into_value().as_ref().clone()),
                    None => init.map(|mk| mk()),
                };
                let op = match computed {
                    Some(mut value) => {
                        *slot.lock().expect("cache compute slot poisoned") = Some(f(&mut value));
                        moka::ops::compute::Op::Put(Arc::new(value))
                    }
                    None => moka::ops::compute::Op::Nop,
                };
                async move { op }
            })
            .await;
        Arc::into_inner(out)
            .expect("cache compute slot is uniquely owned")
            .into_inner()
            .expect("cache compute slot poisoned")
    }

    /// Mutable access to a cached value, atomic under moka's per-key
    /// compute. Returns `Some(f's result)` when the key exists, `None`
    /// when it does not (nothing is inserted then) — so the `Option`
    /// doubles as the existence check.
    pub async fn get_mut<Q, F, R>(&self, key: &Q, f: F) -> Option<R>
    where
        K: Borrow<Q>,
        Q: ToOwned<Owned = K> + Hash + Eq + ?Sized,
        F: FnOnce(&mut V) -> R,
        R: Send,
    {
        self.compute_with_slot::<Q, fn() -> V, F, R>(key, None, f)
            .await
    }

    /// Atomic create-or-update. Like [`Self::get_mut`], but an absent key
    /// is created by `init` in the same per-key compute instead of being
    /// skipped, so create-and-increment is one atomic step: concurrent
    /// first hits on a cold key serialize and every update lands (a
    /// get-then-insert pair races, letting a burst of first hits all
    /// observe absence).
    pub async fn compute_or_insert<Q, FI, F, R>(&self, key: &Q, init: FI, f: F) -> R
    where
        K: Borrow<Q>,
        Q: ToOwned<Owned = K> + Hash + Eq + ?Sized,
        FI: FnOnce() -> V,
        F: FnOnce(&mut V) -> R,
        R: Send,
    {
        self.compute_with_slot(key, Some(init), f)
            .await
            .expect("compute_or_insert always computes")
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
    #[allow(dead_code)] // public cache API surface
    pub async fn clear(&self) {
        self.inner.invalidate_all();
    }
}
