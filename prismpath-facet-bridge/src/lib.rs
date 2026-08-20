// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC

//! `prismpath-facet-bridge` — Deriving PrismPath telemetry wire field bindings
//! from types reflected with the `facet` reflection crate.

use facet::{Facet, PrimitiveType, Type, UserType};
use prismpath_rs::V;
pub use prismpath_telemetry_rs::quantizer::FieldKind;
use std::collections::HashMap;

/// The telemetry wire reading structure encoded by `prismpath-telemetry-rs`.
pub type Reading = HashMap<String, V>;

/// Errors that can occur during field binding or reading extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// An expected field is missing on the reflected type.
    MissingField { field: String },
    /// A field has an unrepresentable or incompatible type for the policy.
    UnrepresentableType { field: String, details: String },
    /// The target type is not a struct.
    NotAStruct { type_name: String },
    /// A reading extraction was attempted on a type different from the bound type.
    TypeMismatch {
        expected_type: String,
        actual_type: String,
    },
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindError::MissingField { field } => write!(f, "missing field: '{field}'"),
            BindError::UnrepresentableType { field, details } => {
                write!(f, "unrepresentable type for field '{field}': {details}")
            }
            BindError::NotAStruct { type_name } => {
                write!(f, "type '{type_name}' is not a struct")
            }
            BindError::TypeMismatch {
                expected_type,
                actual_type,
            } => {
                write!(
                    f,
                    "type mismatch: expected '{expected_type}', got '{actual_type}'"
                )
            }
        }
    }
}

impl std::error::Error for BindError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessorKind {
    I8,
    I16,
    I32,
    I64,
    I128,
    Isize,
    U8,
    U16,
    U32,
    U64,
    U128,
    Usize,
    Bool,
    String,
    Str,
}

/// An accessor pointing to a specific field's offset and primitive type representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldAccessor {
    kind: AccessorKind,
    offset: usize,
}

impl FieldAccessor {
    /// Returns the byte offset of the field within the struct layout.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

/// Compiled binding mapping policy field names to field accessors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    target_type_id: facet::ConstTypeId,
    target_type_name: String,
    fields: Vec<(String, FieldAccessor)>,
}

impl Binding {
    /// Returns the field bindings in canonical sorted-name order.
    pub fn fields(&self) -> &[(String, FieldAccessor)] {
        &self.fields
    }

    /// Returns the target type identifier name.
    pub fn target_type_name(&self) -> &str {
        &self.target_type_name
    }
}

/// Binds an expected set of policy fields `(field_name, FieldKind)` against type `T`'s reflected shape.
///
/// Returns a [`Binding`] containing field accessors in canonical sorted-name order.
pub fn bind<T: for<'a> Facet<'a>>(expected: &[(&str, FieldKind)]) -> Result<Binding, BindError> {
    let shape = <T as Facet>::SHAPE;
    let struct_type = match &shape.ty {
        Type::User(UserType::Struct(st)) => st,
        _ => {
            return Err(BindError::NotAStruct {
                type_name: shape.type_identifier.to_string(),
            });
        }
    };

    let available_fields: HashMap<&str, &facet::Field> =
        struct_type.fields.iter().map(|f| (f.name, f)).collect();

    let mut bindings = Vec::with_capacity(expected.len());

    for &(name, ref kind) in expected {
        let field = available_fields
            .get(name)
            .ok_or_else(|| BindError::MissingField {
                field: name.to_string(),
            })?;

        let field_shape = field.shape.get();
        let accessor_kind = match kind {
            FieldKind::Numeric => match field_shape.ty {
                Type::Primitive(PrimitiveType::Numeric(facet::NumericType::Integer {
                    signed,
                })) => match (field_shape.type_identifier, signed) {
                    ("i8", true) => AccessorKind::I8,
                    ("i16", true) => AccessorKind::I16,
                    ("i32", true) => AccessorKind::I32,
                    ("i64", true) => AccessorKind::I64,
                    ("i128", true) => AccessorKind::I128,
                    ("isize", true) => AccessorKind::Isize,
                    ("u8", false) => AccessorKind::U8,
                    ("u16", false) => AccessorKind::U16,
                    ("u32", false) => AccessorKind::U32,
                    ("u64", false) => AccessorKind::U64,
                    ("u128", false) => AccessorKind::U128,
                    ("usize", false) => AccessorKind::Usize,
                    _ => {
                        if let Ok(layout) = field_shape.layout.sized_layout() {
                            match (layout.size(), signed) {
                                (1, true) => AccessorKind::I8,
                                (2, true) => AccessorKind::I16,
                                (4, true) => AccessorKind::I32,
                                (8, true) => AccessorKind::I64,
                                (16, true) => AccessorKind::I128,
                                (1, false) => AccessorKind::U8,
                                (2, false) => AccessorKind::U16,
                                (4, false) => AccessorKind::U32,
                                (8, false) => AccessorKind::U64,
                                (16, false) => AccessorKind::U128,
                                _ => {
                                    return Err(BindError::UnrepresentableType {
                                        field: name.to_string(),
                                        details: format!(
                                            "unsupported integer layout size {} for field '{}'",
                                            layout.size(),
                                            name
                                        ),
                                    });
                                }
                            }
                        } else {
                            return Err(BindError::UnrepresentableType {
                                field: name.to_string(),
                                details: format!(
                                    "unsized or unknown integer layout for field '{name}'"
                                ),
                            });
                        }
                    }
                },
                _ => {
                    return Err(BindError::UnrepresentableType {
                        field: name.to_string(),
                        details: format!(
                            "field '{name}' has type '{}' which is not an integer-representable type",
                            field_shape.type_identifier
                        ),
                    });
                }
            },
            FieldKind::Boolean => match field_shape.ty {
                Type::Primitive(PrimitiveType::Boolean) => AccessorKind::Bool,
                _ => {
                    return Err(BindError::UnrepresentableType {
                        field: name.to_string(),
                        details: format!(
                            "field '{name}' has type '{}' which is not boolean",
                            field_shape.type_identifier
                        ),
                    });
                }
            },
            FieldKind::Categorical => {
                let is_string = field_shape.type_identifier == "String"
                    || matches!(field_shape.ty, Type::User(UserType::Opaque) if field_shape.type_identifier == "String");
                let is_str_ref = field_shape.type_identifier == "str"
                    || matches!(field_shape.ty, Type::Primitive(PrimitiveType::Textual(facet::TextualType::Str)))
                    || matches!(field_shape.ty, Type::Pointer(facet::PointerType::Reference(ref r)) if r.target.type_identifier == "str");

                if is_string {
                    AccessorKind::String
                } else if is_str_ref {
                    AccessorKind::Str
                } else {
                    return Err(BindError::UnrepresentableType {
                        field: name.to_string(),
                        details: format!(
                            "field '{name}' has type '{}' which is not string/categorical",
                            field_shape.type_identifier
                        ),
                    });
                }
            }
        };

        bindings.push((
            name.to_string(),
            FieldAccessor {
                kind: accessor_kind,
                offset: field.offset,
            },
        ));
    }

    // Sort bindings into canonical sorted-name order, matching telemetry wire convention
    bindings.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(Binding {
        target_type_id: shape.id,
        target_type_name: shape.type_identifier.to_string(),
        fields: bindings,
    })
}

/// Extracts a telemetry wire [`Reading`] from an instance `value` of type `T` using the given [`Binding`].
pub fn reading_from<T: for<'a> Facet<'a>>(
    binding: &Binding,
    value: &T,
) -> Result<Reading, BindError> {
    let shape = <T as Facet>::SHAPE;
    if binding.target_type_id != shape.id {
        return Err(BindError::TypeMismatch {
            expected_type: binding.target_type_name.clone(),
            actual_type: shape.type_identifier.to_string(),
        });
    }

    let mut reading = Reading::with_capacity(binding.fields.len());
    let base_ptr = value as *const T as *const u8;

    for (name, accessor) in &binding.fields {
        let field_ptr = unsafe { base_ptr.add(accessor.offset) };
        let val = match accessor.kind {
            AccessorKind::I8 => V::Num(unsafe { *(field_ptr as *const i8) } as f64),
            AccessorKind::I16 => V::Num(unsafe { *(field_ptr as *const i16) } as f64),
            AccessorKind::I32 => V::Num(unsafe { *(field_ptr as *const i32) } as f64),
            AccessorKind::I64 => V::Num(unsafe { *(field_ptr as *const i64) } as f64),
            AccessorKind::I128 => V::Num(unsafe { *(field_ptr as *const i128) } as f64),
            AccessorKind::Isize => V::Num(unsafe { *(field_ptr as *const isize) } as f64),
            AccessorKind::U8 => V::Num(unsafe { *field_ptr } as f64),
            AccessorKind::U16 => V::Num(unsafe { *(field_ptr as *const u16) } as f64),
            AccessorKind::U32 => V::Num(unsafe { *(field_ptr as *const u32) } as f64),
            AccessorKind::U64 => V::Num(unsafe { *(field_ptr as *const u64) } as f64),
            AccessorKind::U128 => V::Num(unsafe { *(field_ptr as *const u128) } as f64),
            AccessorKind::Usize => V::Num(unsafe { *(field_ptr as *const usize) } as f64),
            AccessorKind::Bool => V::Bool(unsafe { *(field_ptr as *const bool) }),
            AccessorKind::String => V::Str(unsafe { (&*(field_ptr as *const String)).clone() }),
            AccessorKind::Str => V::Str(unsafe { (*(field_ptr as *const &str)).to_string() }),
        };
        reading.insert(name.clone(), val);
    }

    Ok(reading)
}
