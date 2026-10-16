// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The bounded identifiers and sizes, at their edges.
//!
//! Positive: a value inside its bound parses and reads back byte for byte.
//! Negative: an empty value, one outside the charset and one outside the range
//! are each refused rather than truncated. Boundary: the last admissible byte
//! is accepted and the first inadmissible one is not.

mod common;

use saeptum_capsule::{
    CorrelationId, FIRST_GUEST_CID, GuestMemoryMib, IdError, Label, MAX_CORRELATION_LEN,
    MAX_GUEST_MEMORY_MIB, MAX_LABEL_LEN, MIN_GUEST_MEMORY_MIB, SandboxError, VsockCid,
};

use common::{CAPSULE, CORRELATION, Fallible};

// --- Positive -------------------------------------------------------------

/// Positive: an identifier inside its bound reads back byte for byte.
#[test]
fn an_identifier_reads_back_byte_for_byte() -> Fallible {
    let correlation = CorrelationId::parse(CORRELATION)?;
    assert_eq!(correlation.as_bytes(), CORRELATION.as_bytes());
    assert_eq!(correlation.len(), CORRELATION.len());
    assert!(!correlation.is_empty());
    assert_eq!(correlation.to_string(), CORRELATION);

    let label = Label::parse(CAPSULE)?;
    assert_eq!(label.as_bytes(), CAPSULE.as_bytes());
    assert_eq!(label.len(), CAPSULE.len());
    assert!(!label.is_empty());
    assert_eq!(label.to_string(), CAPSULE);
    Ok(())
}

/// Positive: a guest size and a context identifier inside their ranges are
/// carried unchanged.
#[test]
fn sizes_and_context_identifiers_are_carried_unchanged() -> Fallible {
    assert_eq!(GuestMemoryMib::new(4)?.get(), 4);
    assert_eq!(VsockCid::new(FIRST_GUEST_CID)?.get(), FIRST_GUEST_CID);
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: an empty identifier, a byte outside the charset and a
/// non-identifier are refused rather than sanitised.
#[test]
fn a_malformed_identifier_is_refused() {
    assert_eq!(CorrelationId::parse(""), Err(IdError::Empty));
    assert_eq!(Label::parse(""), Err(IdError::Empty));
    for bad in ["with space", "semi;colon", "quote\"mark", "new\nline"] {
        assert_eq!(Label::parse(bad), Err(IdError::Charset));
        assert_eq!(CorrelationId::parse(bad), Err(IdError::Charset));
    }
}

/// Negative: a size or a context identifier outside its range is refused, and
/// the refusal names the range it failed.
#[test]
fn a_value_outside_its_range_is_refused() {
    assert_eq!(
        GuestMemoryMib::new(0),
        Err(SandboxError::GuestMemoryOutOfRange {
            mib: 0,
            min: MIN_GUEST_MEMORY_MIB,
            max: MAX_GUEST_MEMORY_MIB,
        })
    );
    assert_eq!(
        VsockCid::new(2),
        Err(SandboxError::VsockCidOutOfRange {
            cid: 2,
            min: FIRST_GUEST_CID,
        })
    );
    assert!(VsockCid::new(0).is_err());
}

/// Negative: an identifier refusal reaches the controller error as itself,
/// so a caller matching on [`SandboxError`] still sees which rule was broken.
#[test]
fn an_identifier_refusal_is_carried_into_the_controller_error() {
    let refused = SandboxError::from(IdError::Empty);
    assert_eq!(refused, SandboxError::Identifier(IdError::Empty));
    assert!(refused.to_string().contains("identifier"));
    let too_long = SandboxError::from(IdError::TooLong {
        max: MAX_LABEL_LEN,
        actual: MAX_LABEL_LEN.saturating_add(1),
    });
    assert_ne!(too_long, refused);
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the last admissible byte is accepted and the first inadmissible
/// one is refused, with the refusal naming both lengths.
#[test]
fn the_length_bound_is_closed_at_the_last_byte() -> Fallible {
    let at_label_bound = "a".repeat(MAX_LABEL_LEN);
    assert_eq!(Label::parse(&at_label_bound)?.len(), MAX_LABEL_LEN);
    let over_label_bound = "a".repeat(MAX_LABEL_LEN.saturating_add(1));
    assert_eq!(
        Label::parse(&over_label_bound),
        Err(IdError::TooLong {
            max: MAX_LABEL_LEN,
            actual: MAX_LABEL_LEN.saturating_add(1),
        })
    );

    let at_correlation_bound = "b".repeat(MAX_CORRELATION_LEN);
    assert_eq!(
        CorrelationId::parse(&at_correlation_bound)?.len(),
        MAX_CORRELATION_LEN
    );
    let over_correlation_bound = "b".repeat(MAX_CORRELATION_LEN.saturating_add(1));
    assert!(CorrelationId::parse(&over_correlation_bound).is_err());
    assert!(
        CorrelationId::parse(&at_label_bound).is_ok(),
        "a label is the narrower bound, so text that fits a label fits a correlation"
    );
    Ok(())
}

/// Boundary: the guest memory range is closed at both ends.
#[test]
fn the_guest_memory_range_is_closed_at_both_ends() -> Fallible {
    assert_eq!(
        GuestMemoryMib::new(MIN_GUEST_MEMORY_MIB)?.get(),
        MIN_GUEST_MEMORY_MIB
    );
    assert_eq!(
        GuestMemoryMib::new(MAX_GUEST_MEMORY_MIB)?.get(),
        MAX_GUEST_MEMORY_MIB
    );
    assert!(GuestMemoryMib::new(MAX_GUEST_MEMORY_MIB.saturating_add(1)).is_err());
    assert!(GuestMemoryMib::new(MIN_GUEST_MEMORY_MIB.saturating_sub(1)).is_err());
    Ok(())
}
