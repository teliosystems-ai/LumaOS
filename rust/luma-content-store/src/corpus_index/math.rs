//! Deterministic feature-space decomposition. The matrix dimension is bounded
//! by the vocabulary, never by the number of documents in the owner corpus.
use super::{Result, MAX_DIMENSIONS, MAX_FEATURES};

const MAX_SWEEPS: usize = 64;

pub(super) fn normalize(values: &mut [f64]) -> Result<bool> {
    if values.iter().any(|value| !value.is_finite()) {
        return Err("nonfinite corpus feature vector".into());
    }
    let norm = values.iter().map(|value| value * value).sum::<f64>().sqrt();
    if !norm.is_finite() {
        return Err("corpus vector norm overflow".into());
    }
    if norm <= 1e-14 {
        values.fill(0.0);
        return Ok(false);
    }
    for value in values {
        *value /= norm;
    }
    Ok(true)
}

/// Cyclic symmetric Jacobi sweeps have bounded O(features²) retained storage.
/// Non-convergence refuses the entire generation; no partial basis is returned.
/// `work` accounts operations and must retain the caller's live cancellation,
/// selected-root and resource checks throughout computation.
pub(super) fn projection(
    mut matrix: Vec<Vec<f64>>,
    requested: usize,
    work: &mut impl FnMut(u64) -> Result<()>,
) -> Result<Vec<Vec<f64>>> {
    let n = matrix.len();
    if n > MAX_FEATURES
        || requested == 0
        || requested > MAX_DIMENSIONS
        || matrix.iter().any(|row| row.len() != n)
        || matrix.iter().flatten().any(|value| !value.is_finite())
    {
        return Err("invalid bounded feature covariance/decomposition request".into());
    }
    work((n * n) as u64)?;
    for i in 0..n {
        if matrix[i][i] < 0.0 {
            return Err("negative feature covariance diagonal".into());
        }
        for j in 0..i {
            if matrix[i][j] != matrix[j][i] {
                return Err("feature covariance must be exactly symmetric".into());
            }
        }
    }
    if n == 0 {
        return Ok(Vec::new());
    }
    let scale = matrix
        .iter()
        .enumerate()
        .map(|(i, row)| row[i])
        .sum::<f64>()
        .max(1.0);
    if !scale.is_finite() {
        return Err("feature covariance trace overflow".into());
    }
    let tolerance = 1e-12 * scale / n as f64;
    let mut vectors = vec![vec![0.0; n]; n];
    for (i, row) in vectors.iter_mut().enumerate() {
        row[i] = 1.0;
    }
    let mut converged = n == 1;
    for _ in 0..MAX_SWEEPS {
        work((n * n) as u64)?;
        let mut changed = false;
        for p in 0..n {
            for q in p + 1..n {
                let off = matrix[p][q];
                if off.abs() <= tolerance {
                    continue;
                }
                changed = true;
                work((8 * n + 32) as u64)?;
                let angle = 0.5 * (2.0 * off).atan2(matrix[q][q] - matrix[p][p]);
                let (s, c) = angle.sin_cos();
                let (a, d) = (matrix[p][p], matrix[q][q]);
                matrix[p][p] = c * c * a - 2.0 * s * c * off + s * s * d;
                matrix[q][q] = s * s * a + 2.0 * s * c * off + c * c * d;
                matrix[p][q] = 0.0;
                matrix[q][p] = 0.0;
                for i in 0..n {
                    if i != p && i != q {
                        let (x, y) = (matrix[i][p], matrix[i][q]);
                        matrix[i][p] = c * x - s * y;
                        matrix[p][i] = matrix[i][p];
                        matrix[i][q] = s * x + c * y;
                        matrix[q][i] = matrix[i][q];
                    }
                    let (x, y) = (vectors[i][p], vectors[i][q]);
                    vectors[i][p] = c * x - s * y;
                    vectors[i][q] = s * x + c * y;
                }
            }
        }
        if !changed {
            converged = true;
            break;
        }
    }
    work((n * n) as u64)?;
    if !converged
        || matrix
            .iter()
            .flatten()
            .chain(vectors.iter().flatten())
            .any(|v| !v.is_finite())
    {
        return Err("bounded corpus feature eigensolver did not converge".into());
    }
    if matrix
        .iter()
        .enumerate()
        .any(|(i, row)| row[i] < -1e-10 * scale)
    {
        return Err("corpus covariance is not positive semidefinite".into());
    }
    let mut order: Vec<usize> = (0..n).filter(|i| matrix[*i][*i] > 1e-10 * scale).collect();
    order.sort_by(|a, b| matrix[*b][*b].total_cmp(&matrix[*a][*a]).then(a.cmp(b)));
    order.truncate(requested);
    let mut result = vec![vec![0.0; order.len()]; n];
    for (dimension, column) in order.into_iter().enumerate() {
        // Fix sign by the first largest-magnitude coordinate. Equal input and
        // fixed runtime therefore produce the same serialized basis bytes.
        let pivot = (0..n)
            .max_by(|a, b| {
                vectors[*a][column]
                    .abs()
                    .total_cmp(&vectors[*b][column].abs())
                    .then(b.cmp(a))
            })
            .ok_or("corpus projection pivot missing")?;
        let sign = if vectors[pivot][column] < 0.0 {
            -1.0
        } else {
            1.0
        };
        for i in 0..n {
            result[i][dimension] = vectors[i][column] * sign;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_rank_one_feature_projection_and_deterministic_sign() {
        let matrix = vec![vec![1.0, 1.0], vec![1.0, 1.0]];
        let a = projection(matrix.clone(), 8, &mut |_| Ok(())).unwrap();
        let b = projection(matrix, 8, &mut |_| Ok(())).unwrap();
        assert_eq!(a, b);
        assert_eq!(a[0].len(), 1);
        assert!((a[0][0] - 2_f64.sqrt().recip()).abs() < 1e-12);
        assert!((a[1][0] - a[0][0]).abs() < 1e-12);
    }

    #[test]
    fn diagonal_repeated_eigenvalues_have_stable_bounded_order() {
        let basis = projection(
            vec![
                vec![2.0, 0.0, 0.0],
                vec![0.0, 2.0, 0.0],
                vec![0.0, 0.0, 1.0],
            ],
            2,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(basis, vec![vec![1.0, 0.0], vec![0.0, 1.0], vec![0.0, 0.0]]);
    }

    #[test]
    fn malformed_nonfinite_negative_and_cancelled_decompositions_refuse() {
        for matrix in [
            vec![vec![1.0, 0.0]],
            vec![vec![f64::NAN]],
            vec![vec![-1.0]],
            vec![vec![1.0, 1.0], vec![0.0, 1.0]],
            vec![vec![1.0, 2.0], vec![2.0, 1.0]],
        ] {
            assert!(projection(matrix, 1, &mut |_| Ok(())).is_err());
        }
        assert!(projection(vec![vec![1.0]], 1, &mut |_| Err("revoked".into())).is_err());
        assert!(projection(vec![vec![1.0]], 0, &mut |_| Ok(())).is_err());
    }
}
