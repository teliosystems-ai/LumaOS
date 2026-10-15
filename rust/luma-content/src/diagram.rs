//! Bounded editable diagram source and deterministic inert SVG serialization.
//!
//! Integer canvas geometry, explicit cardinal ports and a fixed palette need no
//! layout process, fonts, files, clock or network. Byte determinism is not a
//! promise of identical pixels across SVG viewers or external editor support.
use crate::{canonical, sha256, Format, MAX_CONTENT_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub const MAX_NODES: usize = 128;
pub const MAX_EDGES: usize = 256;
pub const MAX_CANVAS: u32 = 8192;
pub const MAX_LABEL_BYTES: usize = 256;
pub const MAX_WORK_UNITS: usize = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Source,
    Bounds,
    Text,
    Identifier,
    Reference,
    Geometry,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Source => "invalid closed diagram source",
            Self::Bounds => "diagram input, output or work bound exceeded",
            Self::Text => "diagram text contains unsupported controls or line endings",
            Self::Identifier => "invalid or duplicate diagram identifier",
            Self::Reference => "diagram edge has an absent or identical endpoint",
            Self::Geometry => "diagram node is outside the canvas, too small or overlapping",
        })
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub schema_version: u32,
    pub title: String,
    pub width: u32,
    pub height: u32,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub shape: Shape,
    pub fill: Color,
    pub label: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Shape {
    Rectangle,
    RoundedRectangle,
    Ellipse,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Color {
    White,
    Gray,
    Blue,
    Green,
    Yellow,
    Red,
}
impl Color {
    fn svg(self) -> &'static str {
        match self {
            Self::White => "#ffffff",
            Self::Gray => "#e5e7eb",
            Self::Blue => "#dbeafe",
            Self::Green => "#dcfce7",
            Self::Yellow => "#fef9c3",
            Self::Red => "#fee2e2",
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub id: String,
    pub from: String,
    pub from_port: Port,
    pub to: String,
    pub to_port: Port,
    pub arrow: Arrow,
    pub label: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Port {
    North,
    East,
    South,
    West,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Arrow {
    None,
    End,
    Both,
}

#[derive(Clone, Debug, Serialize)]
pub struct Rendered {
    pub schema_version: u32,
    pub engine: &'static str,
    pub canonical_source: String,
    pub source_sha256: String,
    pub canonical_svg: String,
    pub svg_sha256: String,
    pub work_units: usize,
}

struct Builder {
    svg: String,
    work: usize,
}
impl Builder {
    fn charge(&mut self, units: usize) -> Result<()> {
        self.work = self.work.checked_add(units).ok_or(Error::Bounds)?;
        if self.work > MAX_WORK_UNITS {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    fn push(&mut self, text: &str) -> Result<()> {
        if self
            .svg
            .len()
            .checked_add(text.len())
            .ok_or(Error::Bounds)?
            > MAX_CONTENT_BYTES
        {
            return Err(Error::Bounds);
        }
        self.svg.push_str(text);
        Ok(())
    }
    fn text(&mut self, text: &str, maximum: usize, multiline: bool) -> Result<()> {
        if text.len() > maximum {
            return Err(Error::Bounds);
        }
        self.charge(text.len().checked_add(1).ok_or(Error::Bounds)?)?;
        for c in text.chars() {
            if (c.is_control() && !(multiline && c == '\n'))
                || matches!(c, '\u{feff}' | '\u{fffe}' | '\u{ffff}')
            {
                return Err(Error::Text);
            }
            match c {
                '&' => self.push("&amp;")?,
                '<' => self.push("&lt;")?,
                '>' => self.push("&gt;")?,
                '"' => self.push("&quot;")?,
                '\'' => self.push("&apos;")?,
                _ => self.push(c.encode_utf8(&mut [0; 4]))?,
            }
        }
        Ok(())
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn half(value: i64) -> String {
    if value % 2 == 0 {
        (value / 2).to_string()
    } else if value < 0 {
        format!("-{}.5", value.unsigned_abs() / 2)
    } else {
        format!("{}.5", value / 2)
    }
}
fn port(node: &Node, at: Port) -> (i64, i64) {
    let x = i64::from(node.x) * 2;
    let y = i64::from(node.y) * 2;
    let w = i64::from(node.width);
    let h = i64::from(node.height);
    match at {
        Port::North => (x + w, y),
        Port::East => (x + w * 2, y + h),
        Port::South => (x + w, y + h * 2),
        Port::West => (x, y + h),
    }
}
fn overlap(a: &Node, b: &Node) -> bool {
    u64::from(a.x) < u64::from(b.x) + u64::from(b.width)
        && u64::from(b.x) < u64::from(a.x) + u64::from(a.width)
        && u64::from(a.y) < u64::from(b.y) + u64::from(b.height)
        && u64::from(b.y) < u64::from(a.y) + u64::from(a.height)
}

/// Render a closed editable source. Caller-supplied labels never become SVG
/// markup, attributes, references or paths. All dimensions and references are
/// checked before rendering; no automatic routing or external resource loading.
pub fn render(bytes: &[u8]) -> Result<Rendered> {
    let canonical_source = canonical::content(Format::Json, bytes).map_err(|_| Error::Source)?;
    let source: Source = serde_json::from_str(&canonical_source).map_err(|_| Error::Source)?;
    let typed = serde_json::to_vec(&source).map_err(|_| Error::Source)?;
    if canonical::content(Format::Json, &typed).map_err(|_| Error::Source)? != canonical_source
        || source.schema_version != 1
    {
        return Err(Error::Source);
    }
    if source.title.is_empty()
        || source.title.len() > MAX_LABEL_BYTES
        || source.width == 0
        || source.height == 0
        || source.width > MAX_CANVAS
        || source.height > MAX_CANVAS
        || source.nodes.len() > MAX_NODES
        || source.edges.len() > MAX_EDGES
    {
        return Err(Error::Bounds);
    }
    let mut builder = Builder {
        svg: String::new(),
        work: 0,
    };
    let mut nodes = BTreeMap::new();
    for (index, node) in source.nodes.iter().enumerate() {
        builder.charge(1)?;
        if !identifier(&node.id) || nodes.insert(node.id.as_str(), node).is_some() {
            return Err(Error::Identifier);
        }
        if node.width < 32
            || node.height < 24
            || node
                .x
                .checked_add(node.width)
                .map_or(true, |v| v > source.width)
            || node
                .y
                .checked_add(node.height)
                .map_or(true, |v| v > source.height)
        {
            return Err(Error::Geometry);
        }
        for prior in &source.nodes[..index] {
            builder.charge(1)?;
            if overlap(node, prior) {
                return Err(Error::Geometry);
            }
        }
        if node.label.len() > MAX_LABEL_BYTES || node.label.split('\n').count() > 8 {
            return Err(Error::Bounds);
        }
    }
    let mut edge_ids = BTreeMap::new();
    for edge in &source.edges {
        builder.charge(1)?;
        if !identifier(&edge.id) || edge_ids.insert(edge.id.as_str(), ()).is_some() {
            return Err(Error::Identifier);
        }
        if edge.from == edge.to
            || !nodes.contains_key(edge.from.as_str())
            || !nodes.contains_key(edge.to.as_str())
        {
            return Err(Error::Reference);
        }
    }
    builder.push(&format!("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{}\" height=\"{}\" viewBox=\"0 0 {} {}\" role=\"img\" aria-labelledby=\"luma-title\">\n<title id=\"luma-title\">", source.width, source.height, source.width, source.height))?;
    builder.text(&source.title, MAX_LABEL_BYTES, false)?;
    builder.push("</title>\n<defs>\n<marker id=\"luma-end\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\" orient=\"auto\"><path d=\"M 0 0 L 10 5 L 0 10 z\" fill=\"#111827\"/></marker>\n<marker id=\"luma-start\" viewBox=\"0 0 10 10\" refX=\"1\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\" orient=\"auto\"><path d=\"M 10 0 L 0 5 L 10 10 z\" fill=\"#111827\"/></marker>\n")?;
    for (index, node) in source.nodes.iter().enumerate() {
        builder.push(&format!("<clipPath id=\"luma-clip-{index}\"><rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\"/></clipPath>\n", node.x, node.y, node.width, node.height))?;
    }
    builder.push("</defs>\n")?;
    builder.push(&format!(
        "<rect width=\"{}\" height=\"{}\" fill=\"#ffffff\"/>\n",
        source.width, source.height
    ))?;
    for edge in &source.edges {
        let from = nodes.get(edge.from.as_str()).ok_or(Error::Reference)?;
        let to = nodes.get(edge.to.as_str()).ok_or(Error::Reference)?;
        let (x1, y1) = port(from, edge.from_port);
        let (x2, y2) = port(to, edge.to_port);
        builder.push(&format!("<g data-edge-id=\"{}\"><line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#111827\" stroke-width=\"2\"", edge.id, half(x1), half(y1), half(x2), half(y2)))?;
        match edge.arrow {
            Arrow::None => {}
            Arrow::End => builder.push(" marker-end=\"url(#luma-end)\"")?,
            Arrow::Both => {
                builder.push(" marker-start=\"url(#luma-start)\" marker-end=\"url(#luma-end)\"")?
            }
        }
        builder.push("/>")?;
        // Midpoints are expressed in doubled units. Rounding down by at most
        // one quarter pixel is deterministic and nonsemantic.
        builder.push(&format!("<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" font-family=\"sans-serif\" font-size=\"12\" fill=\"#111827\">", half((x1 + x2) / 2), half((y1 + y2) / 2 - 8)))?;
        builder.text(&edge.label, MAX_LABEL_BYTES, false)?;
        builder.push("</text></g>\n")?;
    }
    for (index, node) in source.nodes.iter().enumerate() {
        builder.push(&format!("<g data-node-id=\"{}\">", node.id))?;
        match node.shape {
            Shape::Rectangle | Shape::RoundedRectangle => {
                builder.push(&format!(
                    "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\"",
                    node.x, node.y, node.width, node.height
                ))?;
                if node.shape == Shape::RoundedRectangle {
                    builder.push(" rx=\"8\"")?;
                }
            }
            Shape::Ellipse => builder.push(&format!(
                "<ellipse cx=\"{}\" cy=\"{}\" rx=\"{}\" ry=\"{}\"",
                half(i64::from(node.x) * 2 + i64::from(node.width)),
                half(i64::from(node.y) * 2 + i64::from(node.height)),
                half(i64::from(node.width)),
                half(i64::from(node.height))
            ))?,
        }
        builder.push(&format!(
            " fill=\"{}\" stroke=\"#111827\" stroke-width=\"2\"/>",
            node.fill.svg()
        ))?;
        let x = half(i64::from(node.x) * 2 + i64::from(node.width));
        let lines = node.label.split('\n').count();
        let start_y = i64::from(node.y) * 2 + i64::from(node.height) - (lines as i64 - 1) * 14;
        builder.push(&format!("<text text-anchor=\"middle\" dominant-baseline=\"middle\" font-family=\"sans-serif\" font-size=\"14\" fill=\"#111827\" clip-path=\"url(#luma-clip-{index})\">"))?;
        for (line_index, line) in node.label.split('\n').enumerate() {
            builder.push(&format!(
                "<tspan x=\"{x}\" y=\"{}\">",
                half(start_y + line_index as i64 * 28)
            ))?;
            builder.text(line, MAX_LABEL_BYTES, false)?;
            builder.push("</tspan>")?;
        }
        builder.push("</text></g>\n")?;
    }
    builder.push("</svg>\n")?;
    Ok(Rendered {
        schema_version: 1,
        engine: "luma-static-diagram-v1",
        source_sha256: sha256(canonical_source.as_bytes()),
        canonical_source,
        svg_sha256: sha256(builder.svg.as_bytes()),
        canonical_svg: builder.svg,
        work_units: builder.work,
    })
}

#[cfg(test)]
mod tests;
