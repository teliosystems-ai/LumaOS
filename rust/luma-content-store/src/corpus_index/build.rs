use super::*;
use pages::{Body, BucketHead, Feature};
use std::collections::BTreeSet;

const MAP_WALK_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn build<B: CorpusIndexBoundary, C: CorpusContent>(
    store: &ObjectStore,
    root: &MapRoot,
    builder: &BuilderIdentity,
    content: &mut C,
    mutation: &Mutation,
    limits: CorpusIndexLimits,
    b: &mut B,
) -> Result<BuiltCorpusIndex> {
    if limits.write_bytes == 0 {
        return Err("index construction requires finite admitted writes".into());
    }
    let mut m = Meter::new(root, builder, limits, None, b)?;
    m.read(MAP_WALK_BYTES)?;
    let mut heads = vec![BucketHead::empty(); BUCKETS];
    // At most 4096 * 95 pending records: no corpus-sized postings materialization.
    let mut pending: Vec<Vec<Posting>> = (0..BUCKETS).map(|_| Vec::new()).collect();
    let mut document_leaves = Vec::new();
    let mut document_rows = Vec::new();
    let mut ordinal = 0_u32;
    let count = store.visit_map_checked(
        root,
        IoBudget {
            read_bytes: MAP_WALK_BYTES,
            write_bytes: 0,
            new_files: 0,
        },
        b,
        |key, value, b| {
            m.check(root, b)?;
            let record = CorpusRecord::parse(value, root, key)?;
            m.source = m
                .source
                .checked_add(record.content_bytes)
                .ok_or("corpus source total overflow")?;
            if m.source > m.limits.source_bytes {
                return Err("finite corpus source budget exhausted".into());
            }
            let bytes = read_content(root, &record, content, &mut m, b)?;
            for (term, (frequency, offset)) in words(&bytes, root, &mut m, b)? {
                m.postings = m
                    .postings
                    .checked_add(1)
                    .ok_or("index posting total overflow")?;
                if m.postings > m.limits.postings {
                    return Err("finite index postings budget exhausted".into());
                }
                let id = bucket(&term);
                pending[id].push(Posting {
                    term,
                    document: ordinal,
                    frequency,
                    offset,
                });
                if pending[id].len() == pages::POSTING_ROWS {
                    flush(
                        store,
                        root,
                        id,
                        &mut heads[id],
                        &mut pending[id],
                        mutation,
                        &mut m,
                        b,
                    )?;
                }
            }
            document_rows.push(record);
            ordinal = ordinal.checked_add(1).ok_or("corpus ordinal overflow")?;
            if document_rows.len() == pages::DOCUMENT_ROWS {
                document_leaves.push(pages::put_leaf(
                    store,
                    root,
                    Body::Documents {
                        first: ordinal - document_rows.len() as u32,
                        records: std::mem::take(&mut document_rows),
                    },
                    mutation,
                    &mut m,
                    b,
                )?);
            }
            Ok(())
        },
    )?;
    if count != root.entry_count || u64::from(ordinal) != count {
        return Err("authenticated corpus walk lost coverage".into());
    }
    if !document_rows.is_empty() {
        document_leaves.push(pages::put_leaf(
            store,
            root,
            Body::Documents {
                first: ordinal - document_rows.len() as u32,
                records: document_rows,
            },
            mutation,
            &mut m,
            b,
        )?);
    }
    let documents = pages::tree(store, root, document_leaves, mutation, &mut m, b)?;
    for id in 0..BUCKETS {
        flush(
            store,
            root,
            id,
            &mut heads[id],
            &mut pending[id],
            mutation,
            &mut m,
            b,
        )?;
    }
    drop(pending);
    let mut directory_leaves = Vec::new();
    for (first, rows) in heads.chunks(pages::BUCKET_ROWS).enumerate() {
        directory_leaves.push(pages::put_leaf(
            store,
            root,
            Body::Buckets {
                first: (first * pages::BUCKET_ROWS) as u32,
                rows: rows.to_vec(),
            },
            mutation,
            &mut m,
            b,
        )?);
    }
    let buckets = pages::tree(store, root, directory_leaves, mutation, &mut m, b)?
        .ok_or("index bucket directory missing")?;
    let (vocabulary_terms, frequencies, actual_postings) =
        statistics(store, root, &heads, &mut m, b)?;
    if actual_postings != m.postings {
        return Err("posting construction total differs from verified chains".into());
    }
    drop(heads);
    let idfs: Vec<f64> = frequencies
        .iter()
        .map(|(_, df)| idf(root.entry_count, *df))
        .collect();
    let mut covariance = vec![vec![0.0; frequencies.len()]; frequencies.len()];
    if let Some(span) = &documents {
        pages::walk(store, root, span, &mut m, b, &mut |body, m, b| {
            let Body::Documents { records, .. } = body else {
                return Err("document traversal crossed page types".into());
            };
            for record in records {
                let bytes = read_content(root, record, content, m, b)?;
                let tf = words(&bytes, root, m, b)?;
                let vector = weights(&tf, &frequencies, &idfs)?;
                let nonzero: Vec<_> = vector
                    .iter()
                    .copied()
                    .enumerate()
                    .filter(|(_, x)| *x != 0.0)
                    .collect();
                m.work((nonzero.len() * nonzero.len()) as u64, root, b)?;
                for (i, x) in &nonzero {
                    for (j, y) in &nonzero {
                        covariance[*i][*j] += x * y;
                    }
                }
            }
            Ok(())
        })?;
    }
    let projection = if frequencies.is_empty() {
        Vec::new()
    } else {
        math::projection(
            covariance,
            MAX_DIMENSIONS.min(frequencies.len()),
            &mut |n| m.work(n, root, b),
        )?
    };
    let dimensions = projection.first().map_or(0, Vec::len);
    let features: Vec<Feature> = frequencies
        .iter()
        .enumerate()
        .map(|(i, (term, df))| Feature {
            term: term.clone(),
            documents: *df,
            idf_bits: idfs[i].to_bits(),
            projection_bits: projection[i].iter().map(|x| x.to_bits()).collect(),
        })
        .collect();
    let mut leaves = Vec::new();
    for (first, rows) in features.chunks(pages::MODEL_ROWS).enumerate() {
        leaves.push(pages::put_leaf(
            store,
            root,
            Body::Model {
                first: (first * pages::MODEL_ROWS) as u32,
                features: rows.to_vec(),
            },
            mutation,
            &mut m,
            b,
        )?);
    }
    let model = pages::tree(store, root, leaves, mutation, &mut m, b)?;
    let mut vector_leaves = Vec::new();
    let mut rows = Vec::new();
    let mut next = 0_u32;
    if let Some(span) = &documents {
        pages::walk(store, root, span, &mut m, b, &mut |body, m, b| {
            let Body::Documents { records, .. } = body else {
                return Err("document traversal crossed page types".into());
            };
            for record in records {
                let bytes = read_content(root, record, content, m, b)?;
                let tf = words(&bytes, root, m, b)?;
                let vector = weights(&tf, &frequencies, &idfs)?;
                m.work((vector.len() * dimensions) as u64, root, b)?;
                let latent = project(&vector, &projection, dimensions)?;
                rows.push(latent.iter().map(|x| (*x as f32).to_bits()).collect());
                next += 1;
                if rows.len() == pages::VECTOR_ROWS {
                    vector_leaves.push(pages::put_leaf(
                        store,
                        root,
                        Body::Vectors {
                            first: next - rows.len() as u32,
                            rows: std::mem::take(&mut rows),
                        },
                        mutation,
                        m,
                        b,
                    )?);
                }
            }
            Ok(())
        })?;
    }
    if !rows.is_empty() {
        vector_leaves.push(pages::put_leaf(
            store,
            root,
            Body::Vectors {
                first: next - rows.len() as u32,
                rows,
            },
            mutation,
            &mut m,
            b,
        )?);
    }
    let vectors = pages::tree(store, root, vector_leaves, mutation, &mut m, b)?;
    let manifest = CorpusIndexManifest {
        schema_version: 1,
        profile: CORPUS_INDEX_PROFILE.into(),
        builder: builder.clone(),
        corpus: root.clone(),
        corpus_sha256: root.sha256()?,
        source_bytes: m.source,
        posting_records: m.postings,
        vocabulary_terms,
        features: features.len() as u16,
        dimensions: dimensions as u8,
        documents,
        buckets,
        model,
        vectors,
    };
    let manifest_sha256 = manifest.sha256()?;
    m.check(root, b)?;
    Ok(BuiltCorpusIndex {
        manifest,
        manifest_sha256,
    })
}

fn flush<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    root: &MapRoot,
    id: usize,
    head: &mut BucketHead,
    pending: &mut Vec<Posting>,
    mutation: &Mutation,
    m: &mut Meter,
    b: &mut B,
) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let count = pending.len() as u64;
    let sha = pages::put(
        store,
        root,
        Body::Postings {
            bucket: id as u16,
            sequence: head.pages,
            previous: head.head.clone(),
            entries: std::mem::take(pending),
        },
        mutation,
        m,
        b,
    )?;
    head.head = Some(sha);
    head.records = head
        .records
        .checked_add(count)
        .ok_or("posting bucket count overflow")?;
    head.pages = head
        .pages
        .checked_add(1)
        .ok_or("posting bucket page overflow")?;
    Ok(())
}

/// Streaming per-bucket DF: never retain a term's document-ID list. The explicit
/// 65536-term/8MiB key-byte ceiling bounds even deliberately hash-skewed corpora.
pub(super) fn statistics<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    root: &MapRoot,
    heads: &[BucketHead],
    m: &mut Meter,
    b: &mut B,
) -> Result<(u64, Vec<(String, u32)>, u64)> {
    if heads.len() != BUCKETS {
        return Err("statistics require the entire bucket directory".into());
    }
    let mut vocabulary = 0_u64;
    let mut postings = 0_u64;
    let mut top = BTreeSet::new();
    for (id, head) in heads.iter().enumerate() {
        let mut terms: BTreeMap<String, (u32, u32)> = BTreeMap::new();
        let mut key_bytes = 0_usize;
        pages::postings(store, root, id, head, m, b, |entry, m, b| {
            m.work(1, root, b)?;
            postings = postings
                .checked_add(1)
                .ok_or("verified postings overflow")?;
            if postings > MAX_INDEX_POSTINGS {
                return Err("verified posting total exceeds profile".into());
            }
            match terms.get_mut(&entry.term) {
                Some((df, last)) => {
                    if entry.document >= *last {
                        return Err("duplicate or unordered document posting".into());
                    }
                    *df += 1;
                    *last = entry.document;
                }
                None => {
                    key_bytes = key_bytes
                        .checked_add(entry.term.len())
                        .ok_or("bucket word bytes overflow")?;
                    if terms.len() >= MAX_BUCKET_TERMS || key_bytes > 8 * 1024 * 1024 {
                        return Err(
                            "bounded hash-bucket vocabulary exhausted; generation not ready".into(),
                        );
                    }
                    terms.insert(entry.term.clone(), (1, entry.document));
                }
            }
            Ok(())
        })?;
        vocabulary = vocabulary
            .checked_add(terms.len() as u64)
            .ok_or("vocabulary total overflow")?;
        for (term, (df, _)) in terms {
            // Lowest DF, then lexically greatest term, is discarded first.
            top.insert((df, std::cmp::Reverse(term)));
            if top.len() > MAX_FEATURES {
                top.pop_first();
            }
        }
    }
    let mut selected: Vec<_> = top.into_iter().map(|(df, term)| (term.0, df)).collect();
    selected.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((vocabulary, selected, postings))
}
pub(super) fn idf(objects: u64, documents: u32) -> f64 {
    ((1.0 + objects as f64) / (1.0 + f64::from(documents))).ln() + 1.0
}
pub(super) fn weights(
    tf: &BTreeMap<String, (u32, u32)>,
    features: &[(String, u32)],
    idfs: &[f64],
) -> Result<Vec<f64>> {
    if features.len() != idfs.len() {
        return Err("feature/IDF dimensions differ".into());
    }
    let mut vector: Vec<_> = features
        .iter()
        .zip(idfs)
        .map(|((term, _), idf)| {
            tf.get(term)
                .map_or(0.0, |(count, _)| (1.0 + f64::from(*count).ln()) * idf)
        })
        .collect();
    math::normalize(&mut vector)?;
    Ok(vector)
}
pub(super) fn project(
    vector: &[f64],
    projection: &[Vec<f64>],
    dimensions: usize,
) -> Result<Vec<f64>> {
    if vector.len() != projection.len() || projection.iter().any(|row| row.len() != dimensions) {
        return Err("projection dimensions differ".into());
    }
    let mut latent = vec![0.0; dimensions];
    for (x, row) in vector.iter().zip(projection) {
        for (y, p) in latent.iter_mut().zip(row) {
            *y += x * p;
        }
    }
    math::normalize(&mut latent)?;
    Ok(latent)
}
