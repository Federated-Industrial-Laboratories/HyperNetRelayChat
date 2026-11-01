// SPDX-License-Identifier: Apache-2.0
//! Validate bounds and deterministic encoding before allocating decoded CBOR values.
use super::{Error, MAX_COLLECTION, MAX_DEPTH, MAX_NODES, Result};
use ciborium::Value;

pub fn canonical_decode(bytes: &[u8], maximum: usize) -> Result<Value> {
    decode_at_depth(bytes, maximum, MAX_DEPTH)
}

pub(super) fn decode_at_depth(bytes: &[u8], maximum: usize, depth: usize) -> Result<Value> {
    validate(bytes, maximum, depth)?;
    ciborium::de::from_reader(bytes).map_err(|_| Error::Encoding)
}

pub fn canonical_encode(value: &Value, maximum: usize) -> Result<Vec<u8>> {
    let value = ordered(value, 1, &mut 0, &mut 0, maximum)?;
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).map_err(|_| Error::Encoding)?;
    validate(&bytes, maximum, MAX_DEPTH)?;
    Ok(bytes)
}

fn ordered(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    content: &mut usize,
    maximum: usize,
) -> Result<Value> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES {
        return Err(Error::Limit);
    }
    match value {
        Value::Integer(_) | Value::Bool(_) | Value::Null => Ok(value.clone()),
        Value::Bytes(b) => {
            *content = content.checked_add(b.len()).ok_or(Error::Limit)?;
            if *content > maximum {
                return Err(Error::Limit);
            }
            Ok(value.clone())
        }
        Value::Text(s) => {
            *content = content.checked_add(s.len()).ok_or(Error::Limit)?;
            if *content > maximum {
                return Err(Error::Limit);
            }
            Ok(value.clone())
        }
        Value::Array(items) => {
            if items.len() > MAX_COLLECTION {
                return Err(Error::Limit);
            }
            items
                .iter()
                .map(|v| ordered(v, depth + 1, nodes, content, maximum))
                .collect::<Result<Vec<_>>>()
                .map(Value::Array)
        }
        Value::Map(items) => {
            if items.len() > MAX_COLLECTION {
                return Err(Error::Limit);
            }
            let mut sorted = Vec::with_capacity(items.len());
            for (key, value) in items {
                if !matches!(key, Value::Text(_))
                    && !matches!(key,Value::Integer(i) if u64::try_from(*i).is_ok())
                {
                    return Err(Error::Encoding);
                }
                let key = ordered(key, depth + 1, nodes, content, maximum)?;
                let value = ordered(value, depth + 1, nodes, content, maximum)?;
                let mut encoding = Vec::new();
                ciborium::ser::into_writer(&key, &mut encoding).map_err(|_| Error::Encoding)?;
                sorted.push((encoding, key, value));
            }
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            if sorted.windows(2).any(|p| p[0].0 == p[1].0) {
                return Err(Error::Encoding);
            }
            Ok(Value::Map(
                sorted.into_iter().map(|(_, k, v)| (k, v)).collect(),
            ))
        }
        _ => Err(Error::Encoding),
    }
}

pub(super) fn validate(bytes: &[u8], maximum: usize, depth: usize) -> Result<()> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Error::Limit);
    }
    let mut scanner = Scanner {
        bytes,
        position: 0,
        nodes: 0,
        maximum_depth: depth,
    };
    scanner.item(1)?;
    if scanner.position != bytes.len() {
        return Err(Error::Encoding);
    }
    Ok(())
}
struct Scanner<'a> {
    bytes: &'a [u8],
    position: usize,
    nodes: usize,
    maximum_depth: usize,
}
impl<'a> Scanner<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(length).ok_or(Error::Limit)?;
        let value = self.bytes.get(self.position..end).ok_or(Error::Encoding)?;
        self.position = end;
        Ok(value)
    }
    fn argument(&mut self, info: u8) -> Result<u64> {
        if info < 24 {
            return Ok(info.into());
        }
        let (size, minimum) = match info {
            24 => (1, 24),
            25 => (2, 256),
            26 => (4, 65_536),
            27 => (8, 4_294_967_296),
            _ => return Err(Error::Encoding),
        };
        let mut value = 0u64;
        for byte in self.take(size)? {
            value = (value << 8) | u64::from(*byte);
        }
        if value < minimum {
            return Err(Error::Encoding);
        }
        Ok(value)
    }
    fn item(&mut self, depth: usize) -> Result<()> {
        self.nodes += 1;
        if depth > self.maximum_depth || self.nodes > MAX_NODES {
            return Err(Error::Limit);
        }
        let first = self.take(1)?[0];
        let major = first >> 5;
        let info = first & 31;
        if major == 7 {
            return if matches!(info, 20..=22) {
                Ok(())
            } else {
                Err(Error::Encoding)
            };
        }
        if major == 6 {
            return Err(Error::Encoding);
        }
        let argument = self.argument(info)?;
        match major {
            0 | 1 => Ok(()),
            2 | 3 => {
                let length = usize::try_from(argument).map_err(|_| Error::Limit)?;
                let bytes = self.take(length)?;
                if major == 3 {
                    std::str::from_utf8(bytes).map_err(|_| Error::Encoding)?;
                }
                Ok(())
            }
            4 | 5 => {
                let count = usize::try_from(argument).map_err(|_| Error::Limit)?;
                if count > MAX_COLLECTION {
                    return Err(Error::Limit);
                }
                let mut previous: Option<&[u8]> = None;
                for _ in 0..count {
                    if major == 5 {
                        let start = self.position;
                        let key_major = self.bytes.get(start).ok_or(Error::Encoding)? >> 5;
                        if !matches!(key_major, 0 | 3) {
                            return Err(Error::Encoding);
                        }
                        self.item(depth + 1)?;
                        let current = &self.bytes[start..self.position];
                        if previous.is_some_and(|old| old >= current) {
                            return Err(Error::Encoding);
                        }
                        previous = Some(current);
                    }
                    self.item(depth + 1)?;
                }
                Ok(())
            }
            _ => Err(Error::Encoding),
        }
    }
}
