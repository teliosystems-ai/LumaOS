//! Ranking fixtures exercise exact DATA parity and bounds, not native NF08
//! authentication, I/O throughput or the end-to-end500ms product target.
use super::*;

#[test]
fn full_100000_scalar_ranking_matches_reference_with_at_most64_retained_rows() {
    for limit in [1, 7, crate::MAX_SEARCH_RESULTS] {
        let mut rank = TopMatches::new(limit, MAX_CORPUS_OBJECTS).unwrap();
        let mut reference = Vec::new();
        for ordinal in (0..MAX_CORPUS_OBJECTS as u32).rev() {
            let score = 1 + i64::from(ordinal.wrapping_mul(2_654_435_761) % 97);
            rank.offer(ordinal, score).unwrap();
            reference.push(Ranked { ordinal, score });
            assert!(rank.heap.len() <= limit);
        }
        reference.sort_unstable_by(|a, b| b.cmp(a));
        reference.truncate(limit);
        let (total, actual) = rank.finish();
        assert_eq!(total, MAX_CORPUS_OBJECTS);
        assert_eq!(actual, reference);
    }
}

#[test]
fn ties_and_ascending_scores_preserve_original_order_and_exact_total() {
    let mut rank = TopMatches::new(3, 8).unwrap();
    for ordinal in (0..8).rev() {
        rank.offer(ordinal, if ordinal >= 4 { 9 } else { 10 })
            .unwrap();
    }
    let (total, rows) = rank.finish();
    assert_eq!(total, 8);
    assert_eq!(
        rows.iter().map(|r| r.ordinal).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    let mut increasing = TopMatches::new(3, 8).unwrap();
    for ordinal in 0..8 {
        increasing.offer(ordinal, i64::from(ordinal) + 1).unwrap();
    }
    assert_eq!(
        increasing
            .finish()
            .1
            .iter()
            .map(|r| r.ordinal)
            .collect::<Vec<_>>(),
        vec![7, 6, 5]
    );
}

#[test]
fn invalid_rank_input_refuses_without_consuming_the_match_count() {
    assert!(TopMatches::new(0, 1).is_err());
    assert!(TopMatches::new(crate::MAX_SEARCH_RESULTS + 1, 1).is_err());
    assert!(TopMatches::new(1, MAX_CORPUS_OBJECTS + 1).is_err());
    let mut rank = TopMatches::new(1, 1).unwrap();
    for (ordinal, score) in [(1, 1), (0, 0), (0, -1)] {
        assert!(rank.offer(ordinal, score).is_err());
        assert_eq!(rank.total, 0);
        assert!(rank.heap.is_empty());
    }
    rank.offer(0, i64::MAX).unwrap();
    assert!(rank.offer(0, 1).is_err());
    assert_eq!(
        rank.finish(),
        (
            1,
            vec![Ranked {
                ordinal: 0,
                score: i64::MAX
            }]
        )
    );
    let empty = TopMatches::new(1, 0).unwrap();
    assert_eq!(empty.finish(), (0, Vec::new()));
}
