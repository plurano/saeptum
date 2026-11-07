// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The wire form of the bounded values.
//!
//! A capability set is a list of names on the wire, not four booleans.
//! The reader of a payload sees what was granted; an unknown name is refused
//! rather than ignored, and the list is bounded at
//! [`MAX_CAPABILITY_ENTRIES`], so a payload cannot make the decoder walk an
//! unbounded sequence.

use crate::capsule::Capability;

/// Scalar upper bound on the entries a capability list may carry.
///
/// One per declared capability. A repeated entry is admissible and idempotent,
/// so the bound is on the decoder's work and not on the set's contents.
pub const MAX_CAPABILITY_ENTRIES: usize = Capability::ALL.len();

/// Wire codec for [`CapabilitySet`](crate::capsule::CapabilitySet).
pub(crate) mod capability_set_codec {
    use core::fmt;

    use serde::Deserializer;
    use serde::de::{Error as DeError, SeqAccess, Unexpected, Visitor};
    use serde::ser::{SerializeSeq, Serializer};

    use crate::capsule::{Capability, CapabilitySet};
    use crate::encoding::MAX_CAPABILITY_ENTRIES;

    /// Serializes a [`CapabilitySet`]'s bits as a sequence of capability tag strings.
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde serialize_with contract requires a reference"
    )]
    pub(crate) fn serialize<S: Serializer>(bits: &u8, serializer: S) -> Result<S::Ok, S::Error> {
        let set = CapabilitySet::from_bits(*bits);
        let mut seq = serializer.serialize_seq(Some(set.count()))?;
        for capability in Capability::ALL {
            if set.allows(capability) {
                seq.serialize_element(capability.tag())?;
            }
        }
        seq.end()
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

    /// Deserializes a [`CapabilitySet`]'s bits from a sequence of capability tag strings.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
        let set = deserializer.deserialize_seq(CapabilityList)?;
        Ok(set.bits())
    }
}
