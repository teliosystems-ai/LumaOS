//! Bounded editable document source and deterministic, inert standalone HTML.
//!
//! This is a pure content engine, not an Office adapter, authorization receipt,
//! browser sandbox, publisher or pixel-layout qualification. All source text is
//! escaped; the closed grammar has no scripts, URLs, CSS or embedded resources.
use crate::{canonical, sha256, Format, MAX_CONTENT_BYTES};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_BLOCKS: usize = 256;
pub const MAX_INLINE_RUNS: usize = 4096;
pub const MAX_RUNS_PER_ITEM: usize = 64;
pub const MAX_LIST_ITEMS: usize = 128;
pub const MAX_TABLE_CELLS: usize = 2048;
pub const MAX_TEXT_BYTES: usize = 4096;
pub const MAX_WORK_UNITS: usize = 2 * MAX_CONTENT_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Source,
    Bounds,
    Text,
    Structure,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Source => "invalid closed document source",
            Self::Bounds => "document input, output or work bound exceeded",
            Self::Text => "document text contains unsupported controls or line endings",
            Self::Structure => "invalid document block, run or table structure",
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
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Block {
    Heading {
        level: u8,
        text: String,
    },
    Paragraph {
        runs: Vec<Inline>,
    },
    List {
        ordered: bool,
        items: Vec<Vec<Inline>>,
    },
    Table {
        header: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    Code {
        text: String,
    },
    Rule,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Inline {
    Text { text: String },
    Strong { text: String },
    Emphasis { text: String },
    Code { text: String },
    LineBreak,
}

#[derive(Clone, Debug, Serialize)]
pub struct Rendered {
    pub schema_version: u32,
    pub engine: &'static str,
    pub canonical_source: String,
    pub source_sha256: String,
    pub canonical_html: String,
    pub html_sha256: String,
    pub work_units: usize,
}

struct Builder {
    html: String,
    work: usize,
    runs: usize,
    cells: usize,
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
            .html
            .len()
            .checked_add(text.len())
            .ok_or(Error::Bounds)?
            > MAX_CONTENT_BYTES
        {
            return Err(Error::Bounds);
        }
        self.html.push_str(text);
        Ok(())
    }

    fn text(&mut self, text: &str, maximum: usize) -> Result<()> {
        if text.len() > maximum {
            return Err(Error::Bounds);
        }
        self.charge(text.len().checked_add(1).ok_or(Error::Bounds)?)?;
        for c in text.chars() {
            if (c.is_control() && !matches!(c, '\n' | '\t')) || c == '\u{feff}' {
                return Err(Error::Text);
            }
            match c {
                '&' => self.push("&amp;")?,
                '<' => self.push("&lt;")?,
                '>' => self.push("&gt;")?,
                '"' => self.push("&quot;")?,
                '\'' => self.push("&#39;")?,
                _ => self.push(c.encode_utf8(&mut [0; 4]))?,
            }
        }
        Ok(())
    }

    fn inline(&mut self, runs: &[Inline]) -> Result<()> {
        if runs.is_empty() || runs.len() > MAX_RUNS_PER_ITEM {
            return Err(Error::Structure);
        }
        self.runs = self.runs.checked_add(runs.len()).ok_or(Error::Bounds)?;
        if self.runs > MAX_INLINE_RUNS {
            return Err(Error::Bounds);
        }
        for run in runs {
            self.charge(1)?;
            let (tag, text) = match run {
                Inline::Text { text } => (None, text),
                Inline::Strong { text } => (Some("strong"), text),
                Inline::Emphasis { text } => (Some("em"), text),
                Inline::Code { text } => (Some("code"), text),
                Inline::LineBreak => {
                    self.push("<br>")?;
                    continue;
                }
            };
            if let Some(tag) = tag {
                self.push("<")?;
                self.push(tag)?;
                self.push(">")?;
            }
            self.text(text, MAX_TEXT_BYTES)?;
            if let Some(tag) = tag {
                self.push("</")?;
                self.push(tag)?;
                self.push(">")?;
            }
        }
        Ok(())
    }

    fn block(&mut self, block: &Block) -> Result<()> {
        self.charge(1)?;
        match block {
            Block::Heading { level, text } => {
                if !(1..=6).contains(level) || text.is_empty() {
                    return Err(Error::Structure);
                }
                self.push(&format!("<h{level}>"))?;
                self.text(text, MAX_TEXT_BYTES)?;
                self.push(&format!("</h{level}>\n"))?;
            }
            Block::Paragraph { runs } => {
                self.push("<p>")?;
                self.inline(runs)?;
                self.push("</p>\n")?;
            }
            Block::List { ordered, items } => {
                if items.is_empty() || items.len() > MAX_LIST_ITEMS {
                    return Err(Error::Structure);
                }
                let tag = if *ordered { "ol" } else { "ul" };
                self.push(&format!("<{tag}>\n"))?;
                for item in items {
                    self.charge(1)?;
                    self.push("<li>")?;
                    self.inline(item)?;
                    self.push("</li>\n")?;
                }
                self.push(&format!("</{tag}>\n"))?;
            }
            Block::Table { header, rows } => {
                if header.is_empty()
                    || header.len() > 32
                    || rows.len() > 256
                    || rows.iter().any(|row| row.len() != header.len())
                {
                    return Err(Error::Structure);
                }
                let cells = rows
                    .len()
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(header.len()))
                    .ok_or(Error::Bounds)?;
                self.cells = self.cells.checked_add(cells).ok_or(Error::Bounds)?;
                if self.cells > MAX_TABLE_CELLS {
                    return Err(Error::Bounds);
                }
                self.push("<table>\n<thead><tr>")?;
                for text in header {
                    self.push("<th scope=\"col\">")?;
                    self.text(text, MAX_TEXT_BYTES)?;
                    self.push("</th>")?;
                }
                self.push("</tr></thead>\n<tbody>\n")?;
                for row in rows {
                    self.push("<tr>")?;
                    for text in row {
                        self.push("<td>")?;
                        self.text(text, MAX_TEXT_BYTES)?;
                        self.push("</td>")?;
                    }
                    self.push("</tr>\n")?;
                }
                self.push("</tbody>\n</table>\n")?;
            }
            Block::Code { text } => {
                self.push("<pre><code>")?;
                self.text(text, MAX_TEXT_BYTES)?;
                self.push("</code></pre>\n")?;
            }
            Block::Rule => self.push("<hr>\n")?,
        }
        Ok(())
    }
}

/// Validate and render an editable source. The retained source digest describes
/// canonical JSON, not the original transport spelling. Re-rendering that exact
/// retained source produces the same HTML and digests; changing it is an edit.
pub fn render(bytes: &[u8]) -> Result<Rendered> {
    let canonical_source = canonical::content(Format::Json, bytes).map_err(|_| Error::Source)?;
    let source: Source = serde_json::from_str(&canonical_source).map_err(|_| Error::Source)?;
    let typed = serde_json::to_vec(&source).map_err(|_| Error::Source)?;
    if canonical::content(Format::Json, &typed).map_err(|_| Error::Source)? != canonical_source {
        return Err(Error::Source);
    }
    if source.schema_version != 1 {
        return Err(Error::Source);
    }
    if source.title.is_empty() || source.title.len() > 256 || source.blocks.len() > MAX_BLOCKS {
        return Err(Error::Structure);
    }
    let mut builder = Builder {
        html: String::new(),
        work: 0,
        runs: 0,
        cells: 0,
    };
    builder.push("<!doctype html>\n<html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'none'; base-uri 'none'; form-action 'none'\"><title>")?;
    builder.text(&source.title, 256)?;
    builder.push("</title></head>\n<body><main>\n")?;
    for block in &source.blocks {
        builder.block(block)?;
    }
    builder.push("</main></body></html>\n")?;
    Ok(Rendered {
        schema_version: 1,
        engine: "luma-static-document-v1",
        source_sha256: sha256(canonical_source.as_bytes()),
        canonical_source,
        html_sha256: sha256(builder.html.as_bytes()),
        canonical_html: builder.html,
        work_units: builder.work,
    })
}

#[cfg(test)]
mod tests;
