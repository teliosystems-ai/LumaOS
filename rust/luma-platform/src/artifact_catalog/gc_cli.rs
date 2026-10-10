//! Fixed owner-domain GC entry points. Inspection requires its own finite Read
//! grant; a proposed mark or receipt is never authority to remove an object.
use super::*;
use crate::{
    finite_grants::{Action, Kind, Selector, Use},
    principal,
};

pub(super) fn subject(
    login: &str,
) -> Result<(principal::RegistryBinding, principal::Principal, String)> {
    crate::admin_governance::current_principal(login)
}

pub(super) fn inspection(installation: &str, account: &principal::Principal) -> Result<Use> {
    let usage = Use {
        action: Action::Read,
        selector: Selector {
            kind: Kind::File,
            id: "catalog-inspect".into(),
            generation: account.generation,
            digest: io::digest(&serde_json::to_vec(&(
                "luma-owner-artifact-inspection-v1",
                installation,
                &account.id,
                account.generation,
            ))?),
        },
        input_bytes: 0,
        output_bytes: MAX_CONTENT,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}

pub(super) fn check_owner(
    binding: &principal::RegistryBinding,
    account: &principal::Principal,
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
) -> Result<()> {
    boundary.check()?;
    binding.current()?;
    if boundary.subject()? != account.id
        || boundary.subject_generation()? != account.generation
        || boundary.subject_uid()? != account.uid
    {
        return Err("artifact owner subject changed".into());
    }
    Ok(())
}

pub(super) fn catalog(installation: &str, account: &principal::Principal) -> Result<Catalog> {
    domains::open_at_base(
        Path::new("/var/lib/luma-os/artifact-catalog-domains"),
        installation,
        &account.id,
        false,
        || Ok(()),
    )
}

fn target(area: &str, name: &str) -> Result<gc::Target> {
    let area = match area {
        "object" => gc::Area::Object,
        "retained" => gc::Area::Retained,
        _ => return Err("GC accepts only object or retained targets".into()),
    };
    Ok(gc::Target {
        area,
        name: name.into(),
    })
}
fn grace(value: &str) -> Result<u64> {
    let grace = value.parse::<u64>()?;
    if grace.to_string() != value {
        return Err("GC grace must be canonical seconds".into());
    }
    Ok(grace)
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    if args.len() < 2 {
        return Err("GC requires a fixed command and current human login".into());
    }
    let (binding, account, installation) = subject(&args[1])?;
    let result=match args[0].as_str() {
        "artifact-gc-inspection-review" if args.len()==2=>{
            binding.current()?;
            serde_json::json!({"usage":inspection(&installation,&account)?,"grant_issued":false,"private_catalog_read":false})
        },
        "artifact-gc-proposal" if args.len()==6=>{
            let usage=inspection(&installation,&account)?;
            let target=target(&args[3],&args[4])?;let grace=grace(&args[5])?;
            crate::admin_governance::with_grant(&args[1],&args[2],&usage,|boundary|{
                check_owner(&binding,&account,boundary)?;
                let catalog=catalog(&installation,&account)?;
                let result=catalog.gc_proposal(&target,grace,account.generation)?;
                check_owner(&binding,&account,boundary)?;Ok(result)
            })?
        },
        "artifact-gc-mark" if args.len()==8=>{
            let target=target(&args[4],&args[5])?;let grace=grace(&args[6])?;
            let read=inspection(&installation,&account)?;
            crate::admin_governance::with_grant(&args[1],&args[2],&read,|reader|{
                check_owner(&binding,&account,reader)?;
                let catalog=catalog(&installation,&account)?;
                let proposal=catalog.gc_proposal(&target,grace,account.generation)?;
                let usage:Use=serde_json::from_value(proposal["usage"].clone())?;
                check_owner(&binding,&account,reader)?;
                crate::admin_governance::with_grant(&args[1],&args[3],&usage,|boundary|{
                    check_owner(&binding,&account,reader)?;
                    check_owner(&binding,&account,boundary)?;
                    let result=catalog.gc_mark(&target,grace,&args[7],boundary)?;
                    check_owner(&binding,&account,boundary)?;Ok(result)
                })
            })?
        },
        "artifact-gc-delete-proposal" if args.len()==4=>{
            let usage=inspection(&installation,&account)?;
            crate::admin_governance::with_grant(&args[1],&args[2],&usage,|boundary|{
                check_owner(&binding,&account,boundary)?;
                let catalog=catalog(&installation,&account)?;
                let result=catalog.gc_delete_proposal(&args[3],account.generation)?;
                check_owner(&binding,&account,boundary)?;Ok(result)
            })?
        },
        "artifact-gc-delete" if args.len()==6=>{
            let read=inspection(&installation,&account)?;
            crate::admin_governance::with_grant(&args[1],&args[2],&read,|reader|{
                check_owner(&binding,&account,reader)?;
                let catalog=catalog(&installation,&account)?;
                let proposal=catalog.gc_delete_proposal(&args[4],account.generation)?;
                let usage:Use=serde_json::from_value(proposal["usage"].clone())?;
                check_owner(&binding,&account,reader)?;
                crate::admin_governance::with_grant(&args[1],&args[3],&usage,|boundary|{
                    check_owner(&binding,&account,reader)?;
                    check_owner(&binding,&account,boundary)?;
                    let result=catalog.gc_delete(&args[4],&args[5],boundary)?;
                    check_owner(&binding,&account,boundary)?;Ok(result)
                })
            })?
        },
        "artifact-gc-outcomes" if args.len()==3=>{
            let usage=inspection(&installation,&account)?;
            crate::admin_governance::with_grant(&args[1],&args[2],&usage,|boundary|{
                check_owner(&binding,&account,boundary)?;
                let catalog=catalog(&installation,&account)?;
                let result=catalog.gc_outcomes()?;
                check_owner(&binding,&account,boundary)?;Ok(result)
            })?
        },
        _=>return Err("expected artifact-gc-inspection-review LOGIN | artifact-gc-proposal LOGIN READ-GRANT AREA NAME GRACE-SECONDS | artifact-gc-mark LOGIN READ-GRANT RETAIN-GRANT AREA NAME GRACE-SECONDS REVIEW | artifact-gc-delete-proposal LOGIN READ-GRANT MARK-SHA256 | artifact-gc-delete LOGIN READ-GRANT DELETE-GRANT MARK-SHA256 REVIEW | artifact-gc-outcomes LOGIN READ-GRANT".into()),
    };
    println!("{result}");
    Ok(())
}
