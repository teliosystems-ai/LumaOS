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

/// Exact digest-bound Start/Advance transition review DATA. Reconstructing it
/// never substitutes for the current owner, selection, builder or grant checks.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::content_checkpoint::custody) struct TransitionReview {
    pub(in crate::content_checkpoint::custody) schema_version: u32,
    pub(in crate::content_checkpoint::custody) input_sha256: String,
    pub(in crate::content_checkpoint::custody) base_owner_sha256: String,
    pub(in crate::content_checkpoint::custody) base_job_sha256: Option<String>,
    pub(in crate::content_checkpoint::custody) selection_sha256: String,
    pub(in crate::content_checkpoint::custody) operation: String,
    pub(in crate::content_checkpoint::custody) core_review_sha256: String,
    pub(in crate::content_checkpoint::custody) builder: BuilderIdentity,
    pub(in crate::content_checkpoint::custody) policy_sha256: String,
    pub(in crate::content_checkpoint::custody) metadata_maximum: phase::MetadataMaximum,
    pub(in crate::content_checkpoint::custody) next_job: BlobReference,
    pub(in crate::content_checkpoint::custody) objects: Vec<ObjectWriteSpec>,
    pub(in crate::content_checkpoint::custody) review_sha256: String,
}
/// The selected before-DATA a transition review binds.
pub(in crate::content_checkpoint::custody) struct TransitionBase<'a> {
    pub(in crate::content_checkpoint::custody) owner: &'a OwnerHeadV2,
    pub(in crate::content_checkpoint::custody) job: Option<&'a Job>,
    pub(in crate::content_checkpoint::custody) selection_sha256: &'a str,
    pub(in crate::content_checkpoint::custody) builder: &'a BuilderIdentity,
}
impl TransitionReview {
    pub(in crate::content_checkpoint::custody) fn data(
        input: &Input,
        base: TransitionBase<'_>,
        core_review_sha256: String,
        next_job: BlobReference,
        objects: Vec<ObjectWriteSpec>,
    ) -> Result<Self> {
        digest(&core_review_sha256)?;
        let mut review = Self {
            schema_version: 2,
            input_sha256: input.sha256()?,
            base_owner_sha256: base.owner.sha256()?,
            base_job_sha256: base.job.map(Job::sha256).transpose()?,
            selection_sha256: base.selection_sha256.into(),
            operation: input.mode().name().into(),
            core_review_sha256,
            builder: base.builder.clone(),
            policy_sha256: content_index::policy::sha256()?,
            metadata_maximum: phase::MetadataMaximum::compiled(),
            next_job,
            objects,
            review_sha256: String::new(),
        };
        review.review_sha256 = review.digest()?;
        review.validate()?;
        Ok(review)
    }
    fn digest(&self) -> Result<String> {
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            "luma-native-index-transition-review-v2",
            self.schema_version,
            &self.input_sha256,
            &self.base_owner_sha256,
            &self.base_job_sha256,
            &self.selection_sha256,
            &self.operation,
            &self.core_review_sha256,
            &self.builder,
            &self.policy_sha256,
            &self.metadata_maximum,
            &self.next_job,
            &self.objects,
        ))?))
    }
    pub(in crate::content_checkpoint::custody) fn validate(&self) -> Result<()> {
        for value in [
            &self.input_sha256,
            &self.base_owner_sha256,
            &self.selection_sha256,
            &self.core_review_sha256,
            &self.policy_sha256,
            &self.review_sha256,
        ] {
            digest(value)?;
        }
        if let Some(value) = &self.base_job_sha256 {
            digest(value)?;
        }
        self.builder.validate()?;
        self.next_job.validate()?;
        if self.schema_version != 2 || self.review_sha256 != self.digest()? {
            return Err("index transition review changes its exact digest-bound DATA".into());
        }
        Ok(())
    }
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
    let review = TransitionReview::data(
        input,
        TransitionBase {
            owner: &c.head,
            job: c.job.as_ref(),
            selection_sha256: &c.selection_sha256,
            builder: c.builder.identity(),
        },
        core_review_sha256,
        planned.reference().clone(),
        objects,
    )?;
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
            let mut review=transition(input,&next,Job::beginning_review_data(input,&owner,&builder,&selection)?,gate)?;
            // The review hash already binds this warning; the human approves or declines it.
            if let Some(warning)=Job::start_warning(&owner){review["warning"]=warning.into();review["approval_required"]=true.into();}
            review
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
