//! Bounded deterministic animation as inert sampled SVG frames, not scripts.
use crate::{canonical, sha256, Error, Format, Result, MAX_CONTENT_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write;

pub const MAX_FRAMES: usize = 120;
pub const MAX_SPRITES: usize = 32;
pub const MAX_KEYFRAMES: usize = 64;
pub const MAX_RENDER_BYTES: usize = MAX_CONTENT_BYTES;
pub const MAX_RENDER_WORK_UNITS: usize = MAX_FRAMES * (1 + MAX_SPRITES * MAX_KEYFRAMES);
const MAX_DIMENSION: u32 = 4096;
const MAX_COORDINATE: i32 = 8192;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub schema_version: u32,
    pub width: u32,
    pub height: u32,
    pub frames_per_second: u32,
    pub frame_count: usize,
    pub background: String,
    pub sprites: Vec<Sprite>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sprite {
    pub id: String,
    pub shape: Shape,
    pub fill: String,
    pub keyframes: Vec<Keyframe>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Shape {
    Rectangle { width: u32, height: u32 },
    Circle { radius: u32 },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Keyframe {
    pub frame: usize,
    pub x: i32,
    pub y: i32,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Frame {
    pub index: usize,
    pub canonical_svg: String,
    pub svg_sha256: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Rendered {
    pub schema_version: u32,
    pub engine: &'static str,
    pub canonical_source: String,
    pub source_sha256: String,
    pub frames_per_second: u32,
    pub frames: Vec<Frame>,
    /// Hash of canonical JSON serialization of the ordered frame records.
    pub frames_sha256: String,
    pub work_units: usize,
}

fn color(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value.as_bytes()[1..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn dimension(value: u32) -> bool {
    (1..=MAX_DIMENSION).contains(&value)
}

impl Source {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || !dimension(self.width)
            || !dimension(self.height)
            || !(1..=60).contains(&self.frames_per_second)
            || !(1..=MAX_FRAMES).contains(&self.frame_count)
            || self.sprites.len() > MAX_SPRITES
            || !color(&self.background)
        {
            return Err(Error::Bounds);
        }
        let mut identifiers = BTreeSet::new();
        for sprite in &self.sprites {
            if sprite.id.is_empty()
                || sprite.id.len() > 64
                || !sprite
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || !identifiers.insert(&sprite.id)
                || !color(&sprite.fill)
                || sprite.keyframes.is_empty()
                || sprite.keyframes.len() > MAX_KEYFRAMES
                || sprite.keyframes.first().map(|k| k.frame) != Some(0)
                || sprite.keyframes.last().map(|k| k.frame) != Some(self.frame_count - 1)
            {
                return Err(Error::InvalidEnvelope);
            }
            match sprite.shape {
                Shape::Rectangle { width, height } if dimension(width) && dimension(height) => {}
                Shape::Circle { radius } if dimension(radius) => {}
                _ => return Err(Error::Bounds),
            }
            let mut previous = None;
            for key in &sprite.keyframes {
                if key.frame >= self.frame_count
                    || previous.map_or(false, |prior| prior >= key.frame)
                    || !(-MAX_COORDINATE..=MAX_COORDINATE).contains(&key.x)
                    || !(-MAX_COORDINATE..=MAX_COORDINATE).contains(&key.y)
                {
                    return Err(Error::Bounds);
                }
                previous = Some(key.frame);
            }
        }
        Ok(())
    }
}

/// Linear interpolation rounded down to integer canvas units, including negatives.
/// Inputs have already been bounded; signed products are at most 16384 * 119.
fn coordinate(start: i32, end: i32, elapsed: usize, duration: usize) -> i32 {
    start
        + ((i64::from(end) - i64::from(start)) * elapsed as i64).div_euclid(duration as i64) as i32
}

fn position(sprite: &Sprite, frame: usize) -> (i32, i32, usize) {
    for (index, pair) in sprite.keyframes.windows(2).enumerate() {
        let (start, end) = (&pair[0], &pair[1]);
        if frame < end.frame {
            return (
                coordinate(start.x, end.x, frame - start.frame, end.frame - start.frame),
                coordinate(start.y, end.y, frame - start.frame, end.frame - start.frame),
                index + 1,
            );
        }
    }
    let last = &sprite.keyframes[sprite.keyframes.len() - 1];
    (last.x, last.y, sprite.keyframes.len() - 1)
}

pub fn render(bytes: &[u8]) -> Result<Rendered> {
    // This parser rejects duplicates, excessive nesting/nodes and oversized source.
    let canonical_source = canonical::content(Format::Json, bytes)?;
    let source: Source = serde_json::from_str(&canonical_source).map_err(|_| Error::InvalidJson)?;
    let typed = serde_json::to_vec(&source).map_err(|_| Error::InvalidJson)?;
    if canonical::content(Format::Json, &typed)? != canonical_source {
        return Err(Error::InvalidJson);
    }
    source.validate()?;
    let mut frames = Vec::with_capacity(source.frame_count);
    let mut total = 0usize;
    let mut work_units = 0usize;
    for index in 0..source.frame_count {
        work_units += 1;
        let mut svg = format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{}\" height=\"{}\" viewBox=\"0 0 {} {}\"><rect width=\"{}\" height=\"{}\" fill=\"{}\"/>",
            source.width, source.height, source.width, source.height,
            source.width, source.height, source.background
        );
        for sprite in &source.sprites {
            let (x, y, scanned) = position(sprite, index);
            work_units += 1 + scanned;
            if work_units > MAX_RENDER_WORK_UNITS {
                return Err(Error::Bounds);
            }
            match sprite.shape {
                Shape::Rectangle { width, height } => write!(svg,
                    "<rect id=\"{}\" x=\"{x}\" y=\"{y}\" width=\"{width}\" height=\"{height}\" fill=\"{}\"/>",
                    sprite.id, sprite.fill),
                Shape::Circle { radius } => write!(svg,
                    "<circle id=\"{}\" cx=\"{x}\" cy=\"{y}\" r=\"{radius}\" fill=\"{}\"/>",
                    sprite.id, sprite.fill),
            }.map_err(|_| Error::Bounds)?;
        }
        svg.push_str("</svg>");
        total = total.checked_add(svg.len()).ok_or(Error::Bounds)?;
        if total > MAX_RENDER_BYTES {
            return Err(Error::Bounds);
        }
        frames.push(Frame {
            index,
            svg_sha256: sha256(svg.as_bytes()),
            canonical_svg: svg,
        });
    }
    let frame_bytes = serde_json::to_vec(&frames).map_err(|_| Error::InvalidJson)?;
    if frame_bytes.len() > MAX_RENDER_BYTES {
        return Err(Error::Bounds);
    }
    Ok(Rendered {
        schema_version: 1,
        engine: "luma-sampled-animation-v1",
        source_sha256: sha256(canonical_source.as_bytes()),
        canonical_source,
        frames_per_second: source.frames_per_second,
        frames_sha256: sha256(&frame_bytes),
        frames,
        work_units,
    })
}

#[cfg(test)]
mod tests;
