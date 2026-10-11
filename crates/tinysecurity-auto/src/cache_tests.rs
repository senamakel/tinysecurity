use super::*;
#[test]
fn cache_expires_at_exact_ttl_and_evicts_bounded_scores() {
    let mut cache = Cache::default();
    cache.put("a".into(), 0, 10, 1, [1.0; 3]);
    assert_eq!(cache.get("a", 9), Some([1.0; 3]));
    assert_eq!(cache.get("b", 9), None);
    cache.put("b".into(), 9, 10, 1, [0.0; 3]);
    assert_eq!(cache.get("a", 9), None);
    assert_eq!(cache.get("b", 19), None);
    cache.put("a".into(), 0, 0, 1, [1.0; 3]);
    cache.put("a".into(), 0, 10, 0, [1.0; 3]);
    cache.put("a".into(), u64::MAX, 10, 1, [1.0; 3]);
    assert_eq!(cache.get("a", 0), None);
}

#[test]
fn shrinking_capacity_trims_existing_inventory_before_insertion() {
    let mut cache = Cache::default();
    for key in ["a", "b", "c"] {
        cache.put(key.into(), 0, 100, 3, [1.0; 3]);
    }
    cache.put("d".into(), 1, 100, 1, [0.0; 3]);
    assert_eq!(cache.0.len(), 1);
    cache.put("e".into(), 2, 100, 0, [0.0; 3]);
    assert!(cache.0.is_empty());
}
