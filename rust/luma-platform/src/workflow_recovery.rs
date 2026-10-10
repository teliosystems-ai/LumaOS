//! Disposition of retained owner-bound runs, never execution from old evidence.
use super::history::{self, Domain};
use crate::{
    artifacts as io,
    finite_grants::{Action, Kind, Selector, Use},
    Result,
};
use serde::Serialize;

const MAX_EVIDENCE: u64 = 4 * 1024 * 1024;

pub(super) trait Run {
    fn epoch(&self) -> u64;
    fn evidence(&self) -> Result<serde_json::Value>;
    fn scope(&self, action: Action) -> Result<Use>;
    fn cancel(
        &self,
        review: &str,
        operation: &str,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<serde_json::Value>;
    fn reconcile(
        &self,
        review: &str,
        operation: &str,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<serde_json::Value>;
}
pub(super) fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(io::digest(&serde_json::to_vec(value)?))
}
pub(super) fn disposition_scope<T: Serialize>(
    domain: Domain,
    principal: &str,
    generation: u64,
    request: &str,
    plan: &T,
    action: Action,
) -> Result<Use> {
    if !matches!(action, Action::Cancel | Action::Resume) {
        return Err("recovery may only cancel or acknowledge an existing committed outcome".into());
    }
    let usage = Use {
        action,
        selector: Selector {
            kind: Kind::Workflow,
            id: request.into(),
            generation,
            digest: digest(&(
                "luma-workflow-disposition-v1",
                domain,
                principal,
                generation,
                plan,
                action,
            ))?,
        },
        input_bytes: 0,
        output_bytes: MAX_EVIDENCE,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}
fn generation(value: &str) -> Result<u64> {
    let generation = value.parse::<u64>()?;
    if generation == 0 || generation.to_string() != value {
        return Err("recovery generation must be canonical and nonzero".into());
    }
    Ok(generation)
}
fn target(principal: &str, generation: u64, request: &str) -> Result<()> {
    if !io::hash(principal)
        || principal == "0".repeat(64)
        || generation == 0
        || !io::identifier(request)
    {
        return Err("recovery requires an exact retained principal, generation and request".into());
    }
    Ok(())
}
fn read_scope(
    installation: &str,
    domain: Domain,
    principal: &str,
    generation: u64,
    request: &str,
) -> Result<Use> {
    target(principal, generation, request)?;
    let usage = Use {
        action: Action::Read,
        selector: Selector {
            kind: Kind::File,
            id: "workflow-recovery-inspect".into(),
            generation,
            digest: digest(&(
                "luma-workflow-recovery-inspection-v1",
                installation,
                domain,
                principal,
                generation,
                request,
            ))?,
        },
        input_bytes: 0,
        output_bytes: MAX_EVIDENCE,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}
fn open(domain: Domain, principal: &str, generation: u64, request: &str) -> Result<Box<dyn Run>> {
    history::active_epoch(domain, principal)?;
    match domain {
        Domain::Invoice => super::recovery_open(principal, generation, request),
        Domain::Dag => super::dag::recovery_open(principal, generation, request),
    }
}
fn check(
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    domain: Domain,
    principal: &str,
    generation: u64,
    epoch: u64,
) -> Result<()> {
    boundary.authorize_workflow_recovery(principal, generation)?;
    history::check_epoch(domain, principal, epoch)
}
pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let (domain_at,principal_at,generation_at,request_at)=match args.first().map(String::as_str){
        Some("workflow-recovery-review") if args.len()==6=>(2,3,4,5),
        Some("workflow-recovery-inspect") if args.len()==7=>(3,4,5,6),
        Some("workflow-recovery-cancel"|"workflow-recovery-reconcile") if args.len()==9=>(4,5,6,7),
        _=>return Err("recovery needs LOGIN, exact READ/action grants, TYPE PRINCIPAL OLD-GENERATION REQUEST and explicit review SHA".into()),
    };
    let domain = Domain::parse(&args[domain_at])?;
    let principal = &args[principal_at];
    let old = generation(&args[generation_at])?;
    let request = &args[request_at];
    target(principal, old, request)?;
    let read = read_scope(&io::installation()?, domain, principal, old, request)?;
    if args[0] == "workflow-recovery-review" {
        println!(
            "{}",
            serde_json::json!({"read":read,"private_history_read":false,"grant_issued":false})
        );
        return Ok(());
    }
    let result = crate::admin_governance::with_grant(&args[1], &args[2], &read, |reader| {
        reader.authorize_workflow_recovery(principal, old)?;
        let run = open(domain, principal, old, request)?;
        check(reader, domain, principal, old, run.epoch())?;
        if args[0] == "workflow-recovery-inspect" {
            let evidence = run.evidence()?;
            check(reader, domain, principal, old, run.epoch())?;
            return Ok(evidence);
        }
        let action = if args[0] == "workflow-recovery-cancel" {
            Action::Cancel
        } else {
            Action::Resume
        };
        let usage = run.scope(action)?;
        crate::admin_governance::with_grant(&args[1], &args[3], &usage, |boundary| {
            check(reader, domain, principal, old, run.epoch())?;
            check(boundary, domain, principal, old, run.epoch())?;
            let pending = boundary.effect_begin(
                &format!("{request}.disposition"),
                crate::policy_decisions::EffectKind::Recovery,
            )?;
            let operation = boundary.operation_id().to_owned();
            let mut authorize = || {
                check(reader, domain, principal, old, run.epoch())?;
                check(boundary, domain, principal, old, run.epoch())
            };
            let outcome = if action == Action::Cancel {
                run.cancel(&args[8], &operation, &mut authorize)?
            } else {
                run.reconcile(&args[8], &operation, &mut authorize)?
            };
            authorize()?;
            boundary.effect_complete(pending, &digest(&outcome)?)?;
            Ok(outcome)
        })
    })?;
    println!("{result}");
    Ok(())
}
