//! Closed, typed file-to-artifact DAG admission. The executor consumes this
//! validated topology only after signed installation and live grant checks.
use crate::{bundle, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const MAX_SPEC_BYTES: u64 = 64 * 1024;
const MAX_NODES: usize = 64;
const MAX_INPUTS: usize = 16;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind {
    FileRead,
    DeterministicCalculate,
    ArtifactWrite,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ValueType {
    Text,
    Report,
    Artifact,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Node {
    pub id: String,
    pub kind: Kind,
    pub dependencies: Vec<String>,
    pub input_types: Vec<ValueType>,
    pub output_type: ValueType,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Graph {
    pub schema_version: u32,
    pub profile: String,
    pub graph_id: String,
    pub nodes: Vec<Node>,
}

pub(crate) struct Executable {
    pub graph: Graph,
    pub order: Vec<String>,
    pub sha256: String,
}
impl Executable {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let validation = validate_bytes(bytes)?;
        Ok(Self {
            graph: serde_json::from_slice(bytes)?,
            order: serde_json::from_value(validation["order"].clone())?,
            sha256: bundle::hex(&Sha256::digest(bytes)),
        })
    }
    pub(crate) fn installed() -> Result<Self> {
        let admitted = crate::skills::admission()?;
        let directory =
            crate::scoped_read::open_directory(Path::new("/usr/share/luma-os/workflows"))?;
        let bytes = crate::scoped_read::read_relative(
            &directory,
            crate::scoped_read::identity(&directory)?,
            "file-to-artifact-v1.json",
            MAX_SPEC_BYTES,
        )?;
        let result = Self::from_bytes(&bytes)?;
        if admitted["workflow_sha256"] != result.sha256 {
            return Err("signed workflow changed before executable admission".into());
        }
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        if crate::skills::admission()?["workflow_sha256"] != self.sha256 {
            return Err("installed signed DAG changed".into());
        }
        Ok(())
    }
    pub(crate) fn node(&self, id: &str) -> Result<&Node> {
        self.graph
            .nodes
            .iter()
            .find(|node| node.id == id)
            .ok_or_else(|| "unknown DAG node".into())
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn validate(graph: &Graph) -> Result<serde_json::Value> {
    if graph.schema_version != 1
        || graph.profile != "file-to-artifact-v1"
        || !identifier(&graph.graph_id)
        || graph.nodes.is_empty()
        || graph.nodes.len() > MAX_NODES
    {
        return Err("invalid native workflow profile or graph bounds".into());
    }
    let mut nodes = BTreeMap::new();
    for node in &graph.nodes {
        if !identifier(&node.id)
            || node.dependencies.len() > MAX_INPUTS
            || node.dependencies.len() != node.input_types.len()
            || nodes.insert(node.id.as_str(), node).is_some()
        {
            return Err("invalid or duplicate native workflow node".into());
        }
    }
    for node in &graph.nodes {
        let mut unique = BTreeSet::new();
        for dependency in &node.dependencies {
            if !identifier(dependency)
                || dependency == &node.id
                || !unique.insert(dependency)
                || !nodes.contains_key(dependency.as_str())
            {
                return Err("unknown, duplicate or self-dependent workflow input".into());
            }
        }
    }

    // Stable topological ordering is independent of the caller's node order.
    let mut remaining: BTreeMap<&str, BTreeSet<&str>> = nodes
        .iter()
        .map(|(id, node)| (*id, node.dependencies.iter().map(String::as_str).collect()))
        .collect();
    let mut order = Vec::with_capacity(nodes.len());
    while !remaining.is_empty() {
        let ready: Vec<&str> = remaining
            .iter()
            .filter_map(|(id, deps)| deps.is_empty().then_some(*id))
            .collect();
        if ready.is_empty() {
            return Err("native workflow contains a dependency cycle".into());
        }
        for id in &ready {
            remaining.remove(id);
            order.push(*id);
        }
        for deps in remaining.values_mut() {
            for id in &ready {
                deps.remove(id);
            }
        }
    }

    let mut sinks = Vec::new();
    for node in &graph.nodes {
        let (min_inputs, max_inputs, expected_input, expected_output) = match node.kind {
            Kind::FileRead => (0, 0, None, ValueType::Text),
            Kind::DeterministicCalculate => {
                (1, MAX_INPUTS, Some(ValueType::Text), ValueType::Report)
            }
            Kind::ArtifactWrite => (1, 1, Some(ValueType::Report), ValueType::Artifact),
        };
        if node.dependencies.len() < min_inputs
            || node.dependencies.len() > max_inputs
            || node.output_type != expected_output
            || node
                .input_types
                .iter()
                .any(|input| Some(input) != expected_input.as_ref())
            || node.dependencies.iter().any(|id| {
                nodes[id.as_str()].output_type
                    != *expected_input.as_ref().unwrap_or(&ValueType::Text)
            })
        {
            return Err("native workflow node type contract mismatch".into());
        }
        if node.kind == Kind::ArtifactWrite {
            sinks.push(node.id.as_str());
        }
    }
    if sinks.is_empty() {
        return Err("native workflow has no managed artifact output".into());
    }
    let mut connected = BTreeSet::new();
    while let Some(id) = sinks.pop() {
        if connected.insert(id) {
            sinks.extend(nodes[id].dependencies.iter().map(String::as_str));
        }
    }
    if connected.len() != nodes.len() {
        return Err("native workflow contains unused nodes".into());
    }

    let canonical_nodes: Vec<&Node> = nodes.values().copied().collect();
    let normalized = serde_json::json!({"schema_version":1,
        "profile":graph.profile,"graph_id":graph.graph_id,"nodes":canonical_nodes});
    let fingerprint = bundle::hex(&Sha256::digest(serde_json::to_vec(&normalized)?));
    Ok(
        serde_json::json!({"schema_version":1,"profile":graph.profile,
        "graph_id":graph.graph_id,"nodes":nodes.len(),"order":order,
        "fingerprint":fingerprint,"signed_registry_admitted":false,
        "effect_executed":false,"gate_closing":false}),
    )
}

pub(crate) fn validate_bytes(bytes: &[u8]) -> Result<serde_json::Value> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_SPEC_BYTES {
        return Err("invalid or oversized native workflow bytes".into());
    }
    let graph: Graph = serde_json::from_slice(bytes)?;
    validate(&graph)
}

pub(crate) fn invoice_execution_supported(bytes: &[u8]) -> Result<bool> {
    validate_bytes(bytes)?;
    Ok(true)
}

pub(crate) fn legacy_invoice_execution_supported(bytes: &[u8]) -> Result<bool> {
    let expected = include_bytes!(
        "../../../native/image/overlay/usr/share/luma-os/workflows/file-to-artifact-v1.json"
    );
    Ok(validate_bytes(bytes)?["fingerprint"] == validate_bytes(expected)?["fingerprint"])
}

pub fn validate_file(path: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_SPEC_BYTES {
        return Err("invalid or oversized native workflow file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_SPEC_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err("native workflow file changed during read".into());
    }
    println!("{}", validate_bytes(&bytes)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> Graph {
        Graph {
            schema_version: 1,
            profile: "file-to-artifact-v1".into(),
            graph_id: "report-1".into(),
            nodes: vec![
                Node {
                    id: "source".into(),
                    kind: Kind::FileRead,
                    dependencies: vec![],
                    input_types: vec![],
                    output_type: ValueType::Text,
                },
                Node {
                    id: "calculate".into(),
                    kind: Kind::DeterministicCalculate,
                    dependencies: vec!["source".into()],
                    input_types: vec![ValueType::Text],
                    output_type: ValueType::Report,
                },
                Node {
                    id: "publish".into(),
                    kind: Kind::ArtifactWrite,
                    dependencies: vec!["calculate".into()],
                    input_types: vec![ValueType::Report],
                    output_type: ValueType::Artifact,
                },
            ],
        }
    }

    #[test]
    fn stable_order_and_fingerprint_do_not_depend_on_node_listing() {
        let mut graph = fixture();
        let first = validate(&graph).unwrap();
        assert_eq!(
            first["order"],
            serde_json::json!(["source", "calculate", "publish"])
        );
        assert_eq!(first["effect_executed"], false);
        graph.nodes.reverse();
        let second = validate(&graph).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn cycles_missing_inputs_duplicates_and_unused_nodes_are_denied() {
        let mut graph = fixture();
        graph.nodes[0].dependencies = vec!["publish".into()];
        graph.nodes[0].input_types = vec![ValueType::Artifact];
        assert!(validate(&graph).is_err());
        let mut graph = fixture();
        graph.nodes[1].dependencies = vec!["missing".into()];
        assert!(validate(&graph).is_err());
        let mut graph = fixture();
        graph.nodes.push(graph.nodes[0].clone());
        assert!(validate(&graph).is_err());
        let mut graph = fixture();
        graph.nodes.push(Node {
            id: "unused".into(),
            kind: Kind::FileRead,
            dependencies: vec![],
            input_types: vec![],
            output_type: ValueType::Text,
        });
        assert!(validate(&graph).is_err());
    }

    #[test]
    fn type_substitution_undeclared_kinds_and_profile_changes_are_denied() {
        let mut graph = fixture();
        graph.nodes[1].input_types = vec![ValueType::Report];
        assert!(validate(&graph).is_err());
        let mut graph = fixture();
        graph.nodes[1].output_type = ValueType::Artifact;
        assert!(validate(&graph).is_err());
        let mut graph = fixture();
        graph.profile = "general-execution".into();
        assert!(validate(&graph).is_err());
        let mut bytes = serde_json::to_vec(&fixture()).unwrap();
        bytes.splice(1..1, b"\"authority\":true,".iter().copied());
        assert!(serde_json::from_slice::<Graph>(&bytes).is_err());
        let unknown = serde_json::to_string(&fixture())
            .unwrap()
            .replace("file-read", "shell-exec");
        assert!(serde_json::from_str::<Graph>(&unknown).is_err());
    }

    #[test]
    fn bounded_file_reader_refuses_symlink_and_oversize() {
        let dir = std::env::temp_dir().join(format!("luma-dag-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("graph.json");
        fs::write(&path, serde_json::to_vec(&fixture()).unwrap()).unwrap();
        validate_file(&path).unwrap();
        std::os::unix::fs::symlink(&path, dir.join("link.json")).unwrap();
        assert!(validate_file(&dir.join("link.json")).is_err());
        fs::write(&path, vec![b' '; MAX_SPEC_BYTES as usize + 1]).unwrap();
        assert!(validate_file(&path).is_err());
        fs::remove_file(dir.join("link.json")).unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn valid_closed_dag_shapes_have_executor_support_without_conferring_authority() {
        let expected = include_bytes!(
            "../../../native/image/overlay/usr/share/luma-os/workflows/file-to-artifact-v1.json"
        );
        assert!(invoice_execution_supported(expected).unwrap());
        let mut graph: Graph = serde_json::from_slice(expected).unwrap();
        graph.nodes.reverse();
        assert!(invoice_execution_supported(&serde_json::to_vec(&graph).unwrap()).unwrap());
        graph.graph_id = "different-valid-graph".into();
        let bytes = serde_json::to_vec(&graph).unwrap();
        assert!(validate_bytes(&bytes).is_ok());
        assert!(invoice_execution_supported(&bytes).unwrap());
    }
}
