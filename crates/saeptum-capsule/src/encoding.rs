// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The wire form of the bounded values.
//!
//! One file holds every hand-written `Serialize`/`Deserialize` pair, so the
//! wire form of a bounded value is reviewed in one place rather than
//! rediscovered by every payload that carries one. The pairs live beside the
//! types because Rust's orphan rule lets no other crate implement a foreign
//! trait for them. Three properties are deliberate:
//!
//! * **Validation happens during decoding.** Identifiers, labels, slots,
//!   memory limits and context identifiers are parsed through the same
//!   constructors the library already uses, so an out-of-range field is refused
//!   by the decoder rather than accepted and checked afterwards. This is why a
//!   payload naming slot 129 does not decode.
//! * **Every value lands in a fixed inline slot.** Nothing in this file owns
//!   heap. What this does not claim is that decoding is allocation-free in
//!   every case: `serde_json` unescapes a JSON string into a heap scratch
//!   buffer before any visitor here sees it, so an escaped field costs a
//!   transient copy bounded by the payload that carried it.
//! * **A capability set is a list of names on the wire**, not four booleans.
//!   The reader of a payload sees what was granted; an unknown name is refused
//!   rather than ignored, and the list is bounded at
//!   [`MAX_CAPABILITY_ENTRIES`], so a payload cannot make the decoder walk an
//!   unbounded sequence.

use core::fmt;

use serde::de::{Error as DeError, SeqAccess, Unexpected, Visitor};
use serde::ser::{Error as SerError, SerializeSeq};
use serde::{Deserializer, Serializer};

use crate::capsule::{Capability, CapabilitySet, CapsuleMemoryLimit, CapsuleSlot};
use crate::id::{CorrelationId, Label};
use crate::microvm::{GuestMemoryMib, VsockCid};

/// Scalar upper bound on the entries a capability list may carry.
///
/// One per declared capability. A repeated entry is admissible and idempotent,
/// so the bound is on the decoder's work and not on the set's contents.
pub const MAX_CAPABILITY_ENTRIES: usize = Capability::ALL.len();

/// A visitor that parses one string field through a validating constructor.
struct Parsed<T> {
    label: &'static str,
    parse: fn(&str) -> Option<T>,
}

impl<T> Visitor<'_> for Parsed<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label)
    }

    fn visit_str<E: DeError>(self, value: &str) -> Result<T, E> {
        match (self.parse)(value) {
            Some(parsed) => Ok(parsed),
            None => Err(E::invalid_value(Unexpected::Str(value), &self)),
        }
    }
}

/// A visitor that parses one unsigned field through a validating constructor.
struct Bounded<T> {
    label: &'static str,
    parse: fn(u64) -> Option<T>,
}

impl<T> Visitor<'_> for Bounded<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label)
    }

    fn visit_u64<E: DeError>(self, value: u64) -> Result<T, E> {
        match (self.parse)(value) {
            Some(parsed) => Ok(parsed),
            None => Err(E::invalid_value(Unexpected::Unsigned(value), &self)),
        }
    }
}

impl serde::Serialize for CorrelationId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = core::str::from_utf8(self.as_bytes()).map_err(S::Error::custom)?;
        serializer.serialize_str(text)
    }
}

impl<'de> serde::Deserialize<'de> for CorrelationId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Parsed {
            label: "a bounded correlation identifier",
            parse: |text| Self::parse(text).ok(),
        })
    }
}

impl serde::Serialize for Label {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = core::str::from_utf8(self.as_bytes()).map_err(S::Error::custom)?;
        serializer.serialize_str(text)
    }
}

impl<'de> serde::Deserialize<'de> for Label {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Parsed {
            label: "a bounded sandbox or capsule label",
            parse: |text| Self::parse(text).ok(),
        })
    }
}

impl serde::Serialize for CapsuleSlot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let slot = u64::try_from(self.get()).map_err(S::Error::custom)?;
        serializer.serialize_u64(slot)
    }
}

impl<'de> serde::Deserialize<'de> for CapsuleSlot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_u64(Bounded {
            label: "a capsule slot inside the declared bound",
            parse: |value| {
                usize::try_from(value)
                    .ok()
                    .and_then(|slot| Self::new(slot).ok())
            },
        })
    }
}

impl serde::Serialize for CapsuleMemoryLimit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.get())
    }
}

impl<'de> serde::Deserialize<'de> for CapsuleMemoryLimit {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_u64(Bounded {
            label: "a capsule memory limit inside the declared range",
            parse: |value| Self::new(value).ok(),
        })
    }
}

impl serde::Serialize for GuestMemoryMib {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(u64::from(self.get()))
    }
}

impl<'de> serde::Deserialize<'de> for GuestMemoryMib {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_u64(Bounded {
            label: "a guest memory size inside the declared range",
            parse: |value| {
                u32::try_from(value)
                    .ok()
                    .and_then(|mib| Self::new(mib).ok())
            },
        })
    }
}

impl serde::Serialize for VsockCid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(u64::from(self.get()))
    }
}

impl<'de> serde::Deserialize<'de> for VsockCid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_u64(Bounded {
            label: "a guest vsock context identifier",
            parse: |value| {
                u32::try_from(value)
                    .ok()
                    .and_then(|cid| Self::new(cid).ok())
            },
        })
    }
}

impl serde::Serialize for CapabilitySet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.count()))?;
        for capability in Capability::ALL {
            if self.allows(capability) {
                seq.serialize_element(capability.tag())?;
            }
        }
        seq.end()
    }
}

/// A visitor that reads a bounded list of capability tags.
struct CapabilityList;

impl<'de> Visitor<'de> for CapabilityList {
    type Value = CapabilitySet;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded list of capability names")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<CapabilitySet, A::Error> {
        let mut granted = CapabilitySet::new();
        for _ in 0..MAX_CAPABILITY_ENTRIES {
            let Some(tag) = access.next_element::<&str>()? else {
                return Ok(granted);
            };
            let capability = Capability::from_tag(tag)
                .ok_or_else(|| A::Error::invalid_value(Unexpected::Str(tag), &self))?;
            granted = granted.with(capability);
        }
        if access.next_element::<&str>()?.is_some() {
            return Err(A::Error::invalid_length(
                MAX_CAPABILITY_ENTRIES.saturating_add(1),
                &self,
            ));
        }
        Ok(granted)
    }
}

impl<'de> serde::Deserialize<'de> for CapabilitySet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(CapabilityList)
    }
}
