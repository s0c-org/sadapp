//! Metadata-only discovery cache. Callers must obtain measurements and indices on every poll.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

pub const DISCOVERY_TTL: Duration = Duration::from_secs(60 * 60);
pub const DISCOVERY_MAX_KEYS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DiscoveryKey {
    resource: String,
    identity: String,
}

impl DiscoveryKey {
    /// Hash length-prefixed identity components; authentication secrets are never retained.
    pub fn new(
        resource: &str,
        endpoint: &str,
        profile: &str,
        version: &str,
        auth_identity: &[String],
    ) -> Self {
        let mut digest = Sha256::new();
        for component in [endpoint, profile, version]
            .into_iter()
            .chain(auth_identity.iter().map(String::as_str))
        {
            digest.update((component.len() as u64).to_be_bytes());
            digest.update(component.as_bytes());
        }
        Self {
            resource: resource.to_string(),
            identity: digest
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }
}

struct Entry<V, K> {
    value: V,
    inserted: Instant,
    uptime: f64,
    indices: BTreeSet<K>,
}

pub struct DiscoveryCache<V, K = u32> {
    entries: HashMap<DiscoveryKey, Entry<V, K>>,
    resources: HashMap<String, DiscoveryKey>,
    by_insertion: BTreeMap<Instant, HashSet<DiscoveryKey>>,
    max_keys: usize,
}

impl<V, K> Default for DiscoveryCache<V, K> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            resources: HashMap::new(),
            by_insertion: BTreeMap::new(),
            max_keys: DISCOVERY_MAX_KEYS,
        }
    }
}

impl<V: Clone, K: Clone + Ord> DiscoveryCache<V, K> {
    pub fn with_capacity(max_keys: usize) -> Self {
        Self {
            entries: HashMap::new(),
            resources: HashMap::new(),
            by_insertion: BTreeMap::new(),
            max_keys: max_keys.clamp(1, DISCOVERY_MAX_KEYS),
        }
    }

    pub fn get(
        &mut self,
        key: &DiscoveryKey,
        uptime_seconds: Option<f64>,
        indices: &BTreeSet<K>,
        now: Instant,
    ) -> Option<V> {
        self.expire(key, now);
        let valid = self.entries.get(key).is_some_and(|entry| {
            uptime_seconds.is_some_and(|uptime| uptime.is_finite() && uptime >= entry.uptime)
                && &entry.indices == indices
                && !indices.is_empty()
        });
        if !valid {
            self.remove(key);
            return None;
        }
        let entry = self.entries.get_mut(key)?;
        entry.uptime = uptime_seconds?;
        Some(entry.value.clone())
    }

    pub fn insert(
        &mut self,
        key: DiscoveryKey,
        value: V,
        uptime_seconds: Option<f64>,
        indices: BTreeSet<K>,
        now: Instant,
    ) {
        self.expire(&key, now);
        let Some(uptime) = uptime_seconds.filter(|value| value.is_finite() && *value >= 0.0) else {
            self.remove(&key);
            return;
        };
        if indices.is_empty() {
            self.remove(&key);
            return;
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_keys {
            if let Some(oldest) = self
                .by_insertion
                .first_key_value()
                .and_then(|(_, keys)| keys.iter().next())
                .cloned()
            {
                self.remove(&oldest);
            }
        }
        self.remove(&key);
        self.resources.insert(key.resource.clone(), key.clone());
        self.by_insertion
            .entry(now)
            .or_default()
            .insert(key.clone());
        self.entries.insert(
            key,
            Entry {
                value,
                inserted: now,
                uptime,
                indices,
            },
        );
    }

    fn expire(&mut self, key: &DiscoveryKey, now: Instant) {
        while let Some((&inserted, keys)) = self.by_insertion.first_key_value() {
            if now.saturating_duration_since(inserted) < DISCOVERY_TTL {
                break;
            }
            let expired = keys
                .iter()
                .next()
                .expect("non-empty insertion bucket")
                .clone();
            self.remove(&expired);
        }
        if let Some(previous) = self
            .resources
            .get(&key.resource)
            .filter(|previous| *previous != key)
            .cloned()
        {
            self.remove(&previous);
        }
    }

    fn remove(&mut self, key: &DiscoveryKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.resources.remove(&key.resource);
            let keys = self
                .by_insertion
                .get_mut(&entry.inserted)
                .expect("cache insertion index");
            keys.remove(key);
            if keys.is_empty() {
                self.by_insertion.remove(&entry.inserted);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(endpoint: &str, profile: &str, version: &str, auth: &str) -> DiscoveryKey {
        DiscoveryKey::new("server", endpoint, profile, version, &[auth.into()])
    }

    #[test]
    fn column_membership_invalidates_even_when_union_of_indices_is_unchanged() {
        let now = Instant::now();
        let key = key("host", "sha", "2c", "secret");
        let mut cache = DiscoveryCache::default();
        cache.insert(
            key.clone(),
            42,
            Some(100.0),
            BTreeSet::from([("a", 1), ("b", 2)]),
            now,
        );
        assert_eq!(
            cache.get(
                &key,
                Some(101.0),
                &BTreeSet::from([("a", 2), ("b", 1)]),
                now
            ),
            None
        );
    }

    #[test]
    fn metadata_expires_without_sliding_and_reboot_or_index_changes_invalidate() {
        let now = Instant::now();
        let key = key("host", "profile-sha", "2c", "community-secret");
        let indices = BTreeSet::from([1, 2]);
        let mut cache = DiscoveryCache::default();
        cache.insert(key.clone(), 42, Some(100.0), indices.clone(), now);
        assert_eq!(
            cache.get(&key, Some(200.0), &indices, now + DISCOVERY_TTL / 2),
            Some(42)
        );
        assert_eq!(
            cache.get(&key, Some(201.0), &indices, now + DISCOVERY_TTL),
            None
        );
        for (uptime, changed) in [
            (Some(99.0), indices.clone()),
            (None, indices.clone()),
            (Some(101.0), BTreeSet::from([1])),
            (Some(101.0), BTreeSet::from([1, 2, 3])),
        ] {
            cache.insert(key.clone(), 42, Some(100.0), indices.clone(), now);
            assert_eq!(cache.get(&key, uptime, &changed, now), None);
            assert_eq!(cache.get(&key, Some(200.0), &indices, now), None);
        }
        assert!(!format!("{key:?}").contains("community-secret"));
    }

    #[test]
    fn identity_changes_remove_previous_metadata_and_capacity_is_bounded() {
        let now = Instant::now();
        let original = key("host", "sha", "2c", "secret");
        let indices = BTreeSet::from([1]);
        let mut cache = DiscoveryCache::default();
        for changed in [
            key("host2", "sha", "2c", "secret"),
            key("host", "sha2", "2c", "secret"),
            key("host", "sha", "3", "secret"),
            key("host", "sha", "2c", "secret2"),
        ] {
            cache.insert(original.clone(), 42, Some(100.0), indices.clone(), now);
            assert_eq!(cache.get(&changed, Some(101.0), &indices, now), None);
            assert_eq!(cache.get(&original, Some(101.0), &indices, now), None);
        }
        for index in 0..=DISCOVERY_MAX_KEYS {
            let key = DiscoveryKey::new(&index.to_string(), "host", "sha", "2c", &[]);
            cache.insert(key, index, Some(100.0), indices.clone(), now);
        }
        assert_eq!(cache.entries.len(), DISCOVERY_MAX_KEYS);
    }

    #[test]
    fn incomplete_discovery_is_not_cached_and_oldest_entry_is_evicted() {
        let now = Instant::now();
        let indices = BTreeSet::from([1]);
        let key = key("host", "sha", "2c", "secret");
        let mut cache = DiscoveryCache::default();
        for uptime in [None, Some(f64::NAN), Some(f64::INFINITY), Some(-1.0)] {
            cache.insert(key.clone(), 42, uptime, indices.clone(), now);
            assert!(cache.entries.is_empty());
        }

        cache.insert(key.clone(), 42, Some(1.0), BTreeSet::new(), now);
        assert!(cache.entries.is_empty());
        cache.insert(key.clone(), 42, Some(1.0), indices.clone(), now);
        for index in 0..DISCOVERY_MAX_KEYS {
            let other = DiscoveryKey::new(&format!("other-{index}"), "host", "sha", "2c", &[]);
            cache.insert(
                other,
                1,
                Some(1.0),
                indices.clone(),
                now + Duration::from_secs(1),
            );
        }
        assert!(!cache.entries.contains_key(&key));
        assert_eq!(cache.entries.len(), DISCOVERY_MAX_KEYS);
    }

    #[test]
    fn custom_capacity_is_bounded_and_evicts() {
        let now = Instant::now();
        let mut cache = DiscoveryCache::with_capacity(2);
        for index in 0..3 {
            cache.insert(
                DiscoveryKey::new(&index.to_string(), "host", "sha", "2c", &[]),
                index,
                Some(1.0),
                BTreeSet::from([1]),
                now,
            );
        }
        assert_eq!(cache.entries.len(), 2);
        assert_eq!(
            DiscoveryCache::<()>::with_capacity(usize::MAX).max_keys,
            DISCOVERY_MAX_KEYS
        );
        assert_eq!(DiscoveryCache::<()>::with_capacity(0).max_keys, 1);
    }

    #[test]
    fn indexes_stay_consistent_after_replacement_invalidation_and_expiration() {
        let now = Instant::now();
        let indices = BTreeSet::from([1]);
        let first = DiscoveryKey::new("first", "host", "profile", "2c", &[]);
        let changed = DiscoveryKey::new("first", "new-host", "profile", "2c", &[]);
        let second = DiscoveryKey::new("second", "host", "profile", "2c", &[]);
        let mut cache = DiscoveryCache::with_capacity(2);
        cache.insert(first.clone(), 1, Some(10.0), indices.clone(), now);
        cache.insert(second.clone(), 2, Some(10.0), indices.clone(), now);
        cache.insert(
            first.clone(),
            3,
            Some(11.0),
            indices.clone(),
            now + Duration::from_secs(1),
        );
        assert_eq!(cache.get(&first, Some(12.0), &indices, now), Some(3));
        assert_eq!(cache.get(&changed, Some(12.0), &indices, now), None);
        assert!(!cache.entries.contains_key(&first));
        cache.insert(
            changed.clone(),
            4,
            Some(12.0),
            indices.clone(),
            now + Duration::from_secs(2),
        );
        assert_eq!(
            cache.get(&second, Some(11.0), &indices, now + DISCOVERY_TTL),
            None
        );
        assert_eq!(
            cache.get(&changed, Some(13.0), &indices, now + DISCOVERY_TTL),
            Some(4)
        );
        assert_eq!(
            cache.get(&changed, None, &indices, now + DISCOVERY_TTL),
            None
        );
        assert!(cache.entries.is_empty());
        assert!(cache.resources.is_empty());
        assert!(cache.by_insertion.is_empty());
    }
}
