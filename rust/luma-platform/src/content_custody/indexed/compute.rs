//! Actual selected jobs/generations and explicit finite effect-review DATA.
use super::*;
use luma_content_store::corpus_index::job::covariance::projection::vectors::generation::query::VerifiedGeneration;
use luma_content_store::v2::{BlobObjectPlan, BlobReference, ObjectWriteSpec};
use phase::NativeIndexBoundary;

fn quota_preview<A: Checkpoint>(
    gate: &mut Gate<'_, '_, '_, '_, A>,
    requested: &content_index::policy::Liability,
) -> Result<serde_json::Value> {
    let mut c = gate
        .shared
        .try_borrow_mut()
        .map_err(|_| "reentrant quota review")?;
    c.check()?;
    // An absent preparation has been proved against current C selection, not
    // guessed from a caller's list. Actual retained immutable files already
    // contribute to the selected physical counters. An unresolved index hold
    // cannot be omitted from a capacity preview.
    if c.leaf.as_ref().is_some_and(Leaf::has_preparation) {
        return Err(
            "pending index liability requires explicit recovery, not an empty retained preview"
                .into(),
        );
    }
    let physical = c.physical.clone();
    let segments = c.head.history.segments;
    let summary = content_index::policy::Policy::compiled().admit_data(
        &physical,
        segments,
        [],
        requested,
        &mut || c.check(),
    )?;
    let sha = summary.sha256()?;
    c.check()?;
    Ok(
        serde_json::json!({"summary":summary,"sha256":sha,"quota_data_only":true,
        "free_space_proven":false,"reservation_created":false,"effect_admitted":false}),
    )
}

fn read_credit(reference: &BlobReference) -> Result<u64> {
    reference.validate()?;
    reference
        .bytes
        .checked_mul(2)
        .and_then(|v| v.checked_add(1024 * 1024))
        .filter(|v| *v <= 128 * 1024 * 1024)
        .ok_or_else(|| "selected index blob exceeds closed original read envelope".into())
}

fn load_job<A: Checkpoint>(
    storage: &dyn IndexReadStore,
    gate: &mut Gate<'_, '_, '_, '_, A>,
) -> Result<Option<Job>> {
    let reference = {
        let mut c = gate
            .shared
            .try_borrow_mut()
            .map_err(|_| "reentrant selected job read")?;
        c.check()?;
        c.leaf.as_ref().and_then(|v| v.current_job.clone())
    };
    let Some(reference) = reference else {
        return Ok(None);
    };
    let bytes = storage.read_blob(
        &reference,
        IoBudget {
            read_bytes: read_credit(&reference)?,
            write_bytes: 0,
            new_files: 0,
        },
        gate,
    )?;
    let job = Job::parse(&bytes)?;
    if job.sha256()? != reference.sha256 || job.source_owner.binding != reference.binding {
        return Err(
            "actual selected job blob changed its exact owner or canonical commitment".into(),
        );
    }
    let mut c = gate
        .shared
        .try_borrow_mut()
        .map_err(|_| "reentrant selected job attribution")?;
    c.check()?;
    c.job = Some(job.clone());
    c.check()?;
    Ok(Some(job))
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionReview {
    schema_version: u32,
    input_sha256: String,
    base_owner_sha256: String,
    base_job_sha256: Option<String>,
    selection_sha256: String,
    operation: String,
    core_review_sha256: String,
    builder: BuilderIdentity,
    policy_sha256: String,
    metadata_maximum: phase::MetadataMaximum,
    next_job: BlobReference,
    objects: Vec<ObjectWriteSpec>,
    review_sha256: String,
}
fn transition<A: Checkpoint>(
    input: &Input,
    next: &Job,
    core_review_sha256: String,
    gate: &mut Gate<'_, '_, '_, '_, A>,
) -> Result<serde_json::Value> {
    digest(&core_review_sha256)?;
    let bytes = next.canonical_bytes()?;
    let planned = BlobObjectPlan::data(&input.binding, &bytes, || gate.current(|_| Ok(())))?;
    let objects = planned.write_set(|| gate.current(|_| Ok(())))?;
    let quota = quota_preview(
        gate,
        &content_index::policy::Policy::metadata_liability(&objects)?,
    )?;
    let mut c = gate
        .shared
        .try_borrow_mut()
        .map_err(|_| "reentrant index transition review")?;
    c.check()?;
    let mut review = TransitionReview {
        schema_version: 2,
        input_sha256: input.sha256()?,
        base_owner_sha256: c.head.sha256()?,
        base_job_sha256: c.job.as_ref().map(Job::sha256).transpose()?,
        selection_sha256: c.selection_sha256.clone(),
        operation: input.mode().name().into(),
        core_review_sha256,
        builder: c.builder.identity().clone(),
        policy_sha256: content_index::policy::sha256()?,
        metadata_maximum: phase::MetadataMaximum::compiled(),
        next_job: planned.reference().clone(),
        objects,
        review_sha256: String::new(),
    };
    review.review_sha256 = luma_content::sha256(&serde_json::to_vec(&(
        "luma-native-index-transition-review-v2",
        review.schema_version,
        &review.input_sha256,
        &review.base_owner_sha256,
        &review.base_job_sha256,
        &review.selection_sha256,
        &review.operation,
        &review.core_review_sha256,
        &review.builder,
        &review.policy_sha256,
        &review.metadata_maximum,
        &review.next_job,
        &review.objects,
    ))?);
    let profile = input.effect_profile(&review.review_sha256)?;
    c.check()?;
    Ok(
        serde_json::json!({"schema_version":2,"kind":"review","review":review,"effect_profile":profile,"quota_preview":quota,"effect_executed":false,"authority_returned":false,"production_qualified":false}),
    )
}

pub(super) fn run<A: Checkpoint>(
    storage: &dyn IndexReadStore,
    input: &Input,
    gate: &mut Gate<'_, '_, '_, '_, A>,
) -> Result<serde_json::Value> {
    gate.current_native_operation(input)?;
    let selected_job = load_job(storage, gate)?;
    let result=match &input.operation{
        Operation::Status {}=>{
            let mut c=gate.shared.try_borrow_mut().map_err(|_|"reentrant current index status")?;c.check()?;
            let job=selected_job.as_ref().map(|job|->Result<serde_json::Value>{Ok(serde_json::json!({"job_id":job.job_id,"job_sha256":job.sha256()?,"revision":job.revision,"phase":job.stage.name(),"phase_complete":job.stage.complete()?,"totals":job.stage.totals(),"source_corpus_sha256":job.source_owner.roots.corpus.sha256()?,"stale_corpus":job.source_owner.roots.corpus!=c.head.roots.corpus,"stale_builder":job.builder!=*c.builder.identity()}))}).transpose()?;
            let current_generation=c.leaf.as_ref().and_then(|v|v.current_generation.as_ref()).map(|v|v.sha256.clone());
            serde_json::json!({"schema_version":2,"kind":"status","owner_sha256":c.head.sha256()?,"corpus_sha256":c.head.roots.corpus.sha256()?,"documents":c.head.roots.corpus.entry_count,"current_generation":current_generation,"job":job,"preparation_pending":c.leaf.as_ref().is_some_and(Leaf::has_preparation),"effect_executed":false,"authority_returned":false,"production_qualified":false})
        }
        Operation::Query{generation_sha256,query_kind,query,limit,limits}=>{
            let reference={let mut c=gate.shared.try_borrow_mut().map_err(|_|"reentrant current index generation")?;c.check()?;c.leaf.as_ref().and_then(|v|v.current_generation.clone()).ok_or("no current independently C-selected index generation")?};
            if reference.sha256!=*generation_sha256{return Err("query chooses a stale/foreign generation".into());}
            let bytes=storage.read_blob(&reference,IoBudget{read_bytes:read_credit(&reference)?,write_bytes:0,new_files:0},gate)?;
            let verified=VerifiedGeneration::open(storage,&bytes,generation_sha256,*limits,gate)?;
            let result=verified.query(storage,query_kind.core(),query,usize::from(*limit),*limits,gate)?;
            serde_json::json!({"schema_version":2,"kind":"query","result":result,"effect_executed":false,"authority_returned":false,"production_qualified":false})
        }
        Operation::Start{..}=>{
            let (owner,builder,selection)={let mut c=gate.shared.try_borrow_mut().map_err(|_|"reentrant start review")?;c.check()?;
            if c.leaf.as_ref().is_some_and(Leaf::has_preparation)||selected_job.as_ref().is_some_and(|v|!matches!(v.stage,Stage::Published{..}|Stage::Retained{..})){return Err("existing index preparation/active job must be explicitly completed or recovered first".into());}
            (c.head.clone(),c.builder.identity().clone(),c.selection_sha256.clone())};
            let next=Job::beginning_data(input,&owner,&builder,&selection)?;
            transition(input,&next,Job::beginning_review_data(input,&owner,&builder,&selection)?,gate)?
        }
        Operation::Advance{..}=>{
            let job=selected_job.as_ref().ok_or("no actual current build job to advance")?;gate.current_native_job(job)?;
            gate.current(|c|{if c.leaf.as_ref().is_some_and(Leaf::has_preparation){return Err("pending C preparation fences phase advance".into());}Ok(())})?;
            let next=job.advance_data(input)?;transition(input,&next,job.advance_review_data(input)?,gate)?
        }
        Operation::Step{..}|Operation::Publish{..}=>{
            let job=selected_job.as_ref().ok_or("no actual current index build job")?;gate.current_native_job(job)?;
            gate.current(|c|{if c.leaf.as_ref().is_some_and(Leaf::has_preparation){return Err("pending C preparation fences new review/effect".into());}Ok(())})?;
            let mut content=Content{gate:Gate{shared:gate.shared,client:gate.client}};
            let plan=phase::plan(storage,job,input,&mut content,gate)?;let review=plan.review()?;review.validate()?;
            let objects=plan.planned_objects(||gate.current(|_|Ok(())))?;
            let quota=quota_preview(gate,&content_index::policy::Policy::preview_liability(&review,&objects)?)?;
            serde_json::json!({"schema_version":2,"kind":"review","effect_profile":input.effect_profile(&review.review_sha256)?,"review":review,"quota_preview":quota,"effect_executed":false,"authority_returned":false,"production_qualified":false})
        }
        Operation::Retain{..}=>return Err("retention review requires independently observed current preparation recovery, not caller inventory DATA through IndexRead".into()),
    };
    if serde_json::to_vec(&result)?.len() > content_index::MAX_OUTPUT as usize {
        return Err("actual index reply exceeds original finite output reservation".into());
    }
    gate.current_native_operation(input)?;
    Ok(result)
}
