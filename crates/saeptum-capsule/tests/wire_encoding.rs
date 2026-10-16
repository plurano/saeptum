// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The wire form of the bounded values, at their edges.
//!
//! Positive: every bounded value round-trips through JSON unchanged.
//! Negative: a value its constructor refuses is refused by the decoder too, an
//! unknown capability name is refused rather than ignored, and a capability
//! list one entry past [`MAX_CAPABILITY_ENTRIES`] does not decode. Boundary:
//! the last admissible slot, memory limit and label length decode, and the
//! first inadmissible ones do not.

mod common;

use saeptum_capsule::{
    Capability, CapabilitySet, CapsuleMemoryLimit, CapsuleSlot, CorrelationId, FIRST_GUEST_CID,
    GuestMemoryMib, Label, MAX_CAPABILITY_ENTRIES, MAX_CAPSULE_MEMORY_BYTES, MAX_GUEST_MEMORY_MIB,
    MAX_LABEL_LEN, MAX_WASM_CAPSULES, MIN_CAPSULE_MEMORY_BYTES, VsockCid,
};

use common::{CAPSULE, CORRELATION, Fallible};

/// Decodes `text` as `T`, reporting only whether it decoded.
fn decodes<T: serde::de::DeserializeOwned>(text: &str) -> bool {
    serde_json::from_str::<T>(text).is_ok()
}

// --- Positive -------------------------------------------------------------

/// Positive: identifiers and labels travel as their own text.
#[test]
fn identifiers_round_trip_as_text() -> Fallible {
    let correlation = CorrelationId::parse(CORRELATION)?;
    let text = serde_json::to_string(&correlation)?;
    assert_eq!(text, format!("\"{CORRELATION}\""));
    assert_eq!(serde_json::from_str::<CorrelationId>(&text)?, correlation);

    let label = Label::parse(CAPSULE)?;
    let text = serde_json::to_string(&label)?;
    assert_eq!(text, format!("\"{CAPSULE}\""));
    assert_eq!(serde_json::from_str::<Label>(&text)?, label);
    Ok(())
}

/// Positive: slots, sizes and context identifiers travel as plain numbers.
#[test]
fn bounded_numbers_round_trip_as_numbers() -> Fallible {
    let slot = CapsuleSlot::new(7)?;
    assert_eq!(serde_json::to_string(&slot)?, "7");
    assert_eq!(serde_json::from_str::<CapsuleSlot>("7")?, slot);

    let limit = CapsuleMemoryLimit::new(MIN_CAPSULE_MEMORY_BYTES)?;
    let text = serde_json::to_string(&limit)?;
    assert_eq!(serde_json::from_str::<CapsuleMemoryLimit>(&text)?, limit);

    let guest = GuestMemoryMib::new(4)?;
    assert_eq!(serde_json::to_string(&guest)?, "4");
    assert_eq!(serde_json::from_str::<GuestMemoryMib>("4")?, guest);

    let cid = VsockCid::new(FIRST_GUEST_CID)?;
    let text = serde_json::to_string(&cid)?;
    assert_eq!(serde_json::from_str::<VsockCid>(&text)?, cid);
    Ok(())
}

/// Positive: a capability set travels as the list of names it grants.
#[test]
fn a_capability_set_travels_as_names() -> Fallible {
    let set = CapabilitySet::new()
        .with(Capability::FilesystemRead)
        .with(Capability::ZenohIpc);
    let text = serde_json::to_string(&set)?;
    assert_eq!(text, "[\"filesystem-read\",\"zenoh-ipc\"]");
    assert_eq!(serde_json::from_str::<CapabilitySet>(&text)?, set);
    assert_eq!(
        serde_json::from_str::<CapabilitySet>("[]")?,
        CapabilitySet::new()
    );
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: what a constructor refuses, the decoder refuses.
#[test]
fn refused_values_do_not_decode() {
    assert!(!decodes::<CorrelationId>("\"\""));
    assert!(!decodes::<Label>("\"has space\""));
    assert!(!decodes::<CapsuleSlot>("0"));
    assert!(!decodes::<CapsuleMemoryLimit>("0"));
    assert!(!decodes::<GuestMemoryMib>("0"));
    assert!(!decodes::<VsockCid>("0"));
    assert!(!decodes::<Label>("7"));
    assert!(!decodes::<CapsuleSlot>("\"7\""));
    assert!(!decodes::<CapsuleSlot>("-1"));

    let id_err = serde_json::from_str::<CorrelationId>("\"\"")
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(
        id_err.contains("a bounded correlation identifier"),
        "got: {id_err}"
    );

    let slot_err = serde_json::from_str::<CapsuleSlot>("0")
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(
        slot_err.contains("a capsule slot inside the declared bound"),
        "got: {slot_err}"
    );
}

/// Negative: an unknown capability name is refused, not dropped.
#[test]
fn an_unknown_capability_is_refused() {
    assert!(!decodes::<CapabilitySet>("[\"network\",\"root\"]"));
    assert!(!decodes::<CapabilitySet>("\"network\""));

    let cap_err = serde_json::from_str::<CapabilitySet>("[\"unknown\"]")
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(
        cap_err.contains("a bounded list of capability names"),
        "got: {cap_err}"
    );
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the last admissible slot, limit and guest size decode; one past
/// each does not.
#[test]
fn numeric_bounds_hold_on_the_wire() {
    assert!(decodes::<CapsuleSlot>(&MAX_WASM_CAPSULES.to_string()));
    assert!(!decodes::<CapsuleSlot>(
        &MAX_WASM_CAPSULES.saturating_add(1).to_string()
    ));
    assert!(decodes::<CapsuleMemoryLimit>(
        &MAX_CAPSULE_MEMORY_BYTES.to_string()
    ));
    assert!(!decodes::<CapsuleMemoryLimit>(
        &MAX_CAPSULE_MEMORY_BYTES.saturating_add(1).to_string()
    ));
    assert!(decodes::<GuestMemoryMib>(&MAX_GUEST_MEMORY_MIB.to_string()));
    assert!(!decodes::<GuestMemoryMib>(
        &MAX_GUEST_MEMORY_MIB.saturating_add(1).to_string()
    ));
    assert!(!decodes::<GuestMemoryMib>(&u64::MAX.to_string()));
}

/// Boundary: a label of the maximum length decodes; one byte more does not.
#[test]
fn a_label_at_its_length_bound_decodes() {
    let longest = "a".repeat(MAX_LABEL_LEN);
    assert!(decodes::<Label>(&format!("\"{longest}\"")));
    assert!(!decodes::<Label>(&format!("\"{longest}a\"")));
}

/// Boundary: a capability list of exactly [`MAX_CAPABILITY_ENTRIES`] entries
/// decodes, repeats included; one entry more does not.
///
/// The refusal is asserted by its message, because `serde_json` refuses a
/// sequence the visitor leaves unread on its own: without the decoder's own
/// length check the over-long list would still fail, for the wrong reason.
#[test]
fn a_capability_list_at_its_entry_bound_decodes() {
    assert_eq!(MAX_CAPABILITY_ENTRIES, Capability::ALL.len());
    let at_bound = ["\"network\""; MAX_CAPABILITY_ENTRIES].join(",");
    assert!(decodes::<CapabilitySet>(&format!("[{at_bound}]")));
    let over = ["\"network\""; MAX_CAPABILITY_ENTRIES.saturating_add(1)].join(",");
    let refused = serde_json::from_str::<CapabilitySet>(&format!("[{over}]"))
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    let expected = format!(
        "invalid length {}",
        MAX_CAPABILITY_ENTRIES.saturating_add(1)
    );
    assert!(refused.contains(&expected), "refused with: {refused}");
}
