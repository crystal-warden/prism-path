// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! serde for canon/2: the one Serializer and the one Deserializer, so a document type derives
//! `Serialize` and `Deserialize` and its field list is its member list.
//!
//! `from_bytes` reads with the strict reader first (`canon2::read`, so canon/2 in another spelling is
//! `Canon2Error::NotCanonical` and never reaches the type), then hands the document to the type. A
//! struct reads only from an object and a sequence only from an array, so a document cannot change its
//! shape to pass. With `#[serde(deny_unknown_fields)]` a member missing or extra is a `Shape` error.
//! `to_bytes` builds the document and writes its canonical bytes (`canon2::write`), so a value with no
//! canon/2 form (a float, an integer beyond 2^53 minus 1, bytes, a key that is not a string, a key
//! twice) is refused, never written in some other form.
//!
//! An enum is externally tagged, as serde_json writes it: a unit variant is its name, any other a one
//! member object from the name to its value. `Doc` itself is `Serialize` and `Deserialize`, so a member
//! whose form is any canon/2 value is a `Doc` field. A serde_json value reads from a document as any
//! type does, and becomes one through `canon2::from_json`.

use super::{read, write, Canon2Error, Doc, EXACT_LIMIT};
use serde::de::{self, DeserializeOwned, DeserializeSeed, IntoDeserializer, Unexpected, Visitor};
use serde::ser::{self, Serialize};
use serde::Deserialize;

/// Why a value has no canon/2 bytes or bytes do not read as the type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A rule of canon/2 itself: the bytes are not canon/2 or not its canonical spelling, or the
    /// value has no canon/2 form.
    Canon2(Canon2Error),
    /// The document is canon/2 but not of the type's shape: a member missing or extra, or a value of
    /// another kind or outside the type's own form.
    Shape(String),
}

impl Error {
    /// True when the bytes are canon/2 in a spelling other than their canonical one.
    pub fn is_not_canonical(&self) -> bool {
        *self == Error::Canon2(Canon2Error::NotCanonical)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Canon2(error) => error.fmt(formatter),
            Error::Shape(detail) => write!(formatter, "canon/2 shape: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

impl ser::Error for Error {
    fn custom<T: std::fmt::Display>(message: T) -> Self {
        Error::Shape(message.to_string())
    }
}

impl de::Error for Error {
    fn custom<T: std::fmt::Display>(message: T) -> Self {
        Error::Shape(message.to_string())
    }
}

/// The canon/2 document of a value.
pub fn to_doc<T: Serialize + ?Sized>(value: &T) -> Result<Doc, Error> {
    value.serialize(DocSerializer)
}

/// The canonical canon/2 bytes of a value.
pub fn to_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    write(&to_doc(value)?).map_err(Error::Canon2)
}

/// The value a document holds, read as `T`.
pub fn from_doc<T: DeserializeOwned>(doc: Doc) -> Result<T, Error> {
    T::deserialize(DocDeserializer(doc))
}

/// The value the canonical canon/2 bytes `bytes` hold, read as `T`. The strict reader runs first.
pub fn from_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    from_doc(read(bytes).map_err(Error::Canon2)?)
}

fn integer<N: TryInto<i64>>(number: N) -> Result<Doc, Error> {
    match number.try_into() {
        Ok(value) if (-EXACT_LIMIT..=EXACT_LIMIT).contains(&value) => Ok(Doc::Int(value)),
        _ => Err(Error::Canon2(Canon2Error::IntegerRange)),
    }
}

// ------------------------------------------------------------------ the Serializer

struct DocSerializer;

/// An array being built, and the variant name when it is a tuple variant's value.
struct ArrayBuilder {
    variant: Option<&'static str>,
    items: Vec<Doc>,
}

/// An object being built, the key waiting for its value, and the variant name of a struct variant.
struct ObjectBuilder {
    variant: Option<&'static str>,
    members: Vec<(String, Doc)>,
    key: Option<String>,
}

fn tagged(variant: Option<&'static str>, doc: Doc) -> Doc {
    match variant {
        Some(name) => Doc::Obj(vec![(name.to_string(), doc)]),
        None => doc,
    }
}

impl ser::Serializer for DocSerializer {
    type Ok = Doc;
    type Error = Error;
    type SerializeSeq = ArrayBuilder;
    type SerializeTuple = ArrayBuilder;
    type SerializeTupleStruct = ArrayBuilder;
    type SerializeTupleVariant = ArrayBuilder;
    type SerializeMap = ObjectBuilder;
    type SerializeStruct = ObjectBuilder;
    type SerializeStructVariant = ObjectBuilder;

    fn serialize_bool(self, value: bool) -> Result<Doc, Error> {
        Ok(Doc::Bool(value))
    }
    fn serialize_i8(self, value: i8) -> Result<Doc, Error> {
        integer(value)
    }
    fn serialize_i16(self, value: i16) -> Result<Doc, Error> {
        integer(value)
    }
    fn serialize_i32(self, value: i32) -> Result<Doc, Error> {
        integer(value)
    }
    fn serialize_i64(self, value: i64) -> Result<Doc, Error> {
        integer(value)
    }
    fn serialize_i128(self, value: i128) -> Result<Doc, Error> {
        integer(value)
    }
    fn serialize_u8(self, value: u8) -> Result<Doc, Error> {
        integer(value)
    }
    fn serialize_u16(self, value: u16) -> Result<Doc, Error> {
        integer(value)
    }
    fn serialize_u32(self, value: u32) -> Result<Doc, Error> {
        integer(value)
    }
    fn serialize_u64(self, value: u64) -> Result<Doc, Error> {
        integer(value)
    }
    fn serialize_u128(self, value: u128) -> Result<Doc, Error> {
        integer(value)
    }
    fn serialize_f32(self, _value: f32) -> Result<Doc, Error> {
        Err(Error::Canon2(Canon2Error::Float))
    }
    fn serialize_f64(self, _value: f64) -> Result<Doc, Error> {
        Err(Error::Canon2(Canon2Error::Float))
    }
    fn serialize_char(self, value: char) -> Result<Doc, Error> {
        Ok(Doc::Str(value.to_string()))
    }
    fn serialize_str(self, value: &str) -> Result<Doc, Error> {
        Ok(Doc::Str(value.to_string()))
    }
    fn serialize_bytes(self, _value: &[u8]) -> Result<Doc, Error> {
        Err(Error::Shape("bytes have no canon/2 form; a document carries them as hex".to_string()))
    }
    fn serialize_none(self) -> Result<Doc, Error> {
        Ok(Doc::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Doc, Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Doc, Error> {
        Ok(Doc::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Doc, Error> {
        Ok(Doc::Null)
    }
    fn serialize_unit_variant(self, _name: &'static str, _index: u32, variant: &'static str) -> Result<Doc, Error> {
        Ok(Doc::Str(variant.to_string()))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(self, _name: &'static str, value: &T) -> Result<Doc, Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Doc, Error> {
        Ok(tagged(Some(variant), to_doc(value)?))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<ArrayBuilder, Error> {
        Ok(ArrayBuilder { variant: None, items: Vec::with_capacity(len.unwrap_or(0)) })
    }
    fn serialize_tuple(self, len: usize) -> Result<ArrayBuilder, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<ArrayBuilder, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<ArrayBuilder, Error> {
        Ok(ArrayBuilder { variant: Some(variant), items: Vec::with_capacity(len) })
    }
    fn serialize_map(self, len: Option<usize>) -> Result<ObjectBuilder, Error> {
        Ok(ObjectBuilder { variant: None, members: Vec::with_capacity(len.unwrap_or(0)), key: None })
    }
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<ObjectBuilder, Error> {
        // serde_json with `arbitrary_precision` writes a number as a private struct only its own
        // Serializer reads; such a value is converted by `canon2::from_json`, never through here.
        if name.starts_with("$serde_json::private") {
            return Err(Error::Shape("a serde_json number is converted with canon2::from_json".to_string()));
        }
        self.serialize_map(Some(len))
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<ObjectBuilder, Error> {
        Ok(ObjectBuilder { variant: Some(variant), members: Vec::with_capacity(len), key: None })
    }
}

impl ArrayBuilder {
    fn push<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.items.push(to_doc(value)?);
        Ok(())
    }
    fn finish(self) -> Result<Doc, Error> {
        Ok(tagged(self.variant, Doc::Arr(self.items)))
    }
}

impl ser::SerializeSeq for ArrayBuilder {
    type Ok = Doc;
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }
    fn end(self) -> Result<Doc, Error> {
        self.finish()
    }
}

impl ser::SerializeTuple for ArrayBuilder {
    type Ok = Doc;
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }
    fn end(self) -> Result<Doc, Error> {
        self.finish()
    }
}

impl ser::SerializeTupleStruct for ArrayBuilder {
    type Ok = Doc;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }
    fn end(self) -> Result<Doc, Error> {
        self.finish()
    }
}

impl ser::SerializeTupleVariant for ArrayBuilder {
    type Ok = Doc;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }
    fn end(self) -> Result<Doc, Error> {
        self.finish()
    }
}

impl ObjectBuilder {
    fn member<T: Serialize + ?Sized>(&mut self, key: String, value: &T) -> Result<(), Error> {
        self.members.push((key, to_doc(value)?));
        Ok(())
    }
    fn finish(self) -> Result<Doc, Error> {
        Ok(tagged(self.variant, Doc::Obj(self.members)))
    }
}

impl ser::SerializeMap for ObjectBuilder {
    type Ok = Doc;
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        match to_doc(key)? {
            Doc::Str(text) => {
                self.key = Some(text);
                Ok(())
            }
            _ => Err(Error::Shape("an object key is a string".to_string())),
        }
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let key = self.key.take().ok_or_else(|| Error::Shape("a value with no key".to_string()))?;
        self.member(key, value)
    }
    fn end(self) -> Result<Doc, Error> {
        self.finish()
    }
}

impl ser::SerializeStruct for ObjectBuilder {
    type Ok = Doc;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<(), Error> {
        self.member(key.to_string(), value)
    }
    fn end(self) -> Result<Doc, Error> {
        self.finish()
    }
}

impl ser::SerializeStructVariant for ObjectBuilder {
    type Ok = Doc;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<(), Error> {
        self.member(key.to_string(), value)
    }
    fn end(self) -> Result<Doc, Error> {
        self.finish()
    }
}

// ------------------------------------------------------------------ the Deserializer

struct DocDeserializer(Doc);

fn unexpected(doc: &Doc) -> Unexpected<'_> {
    match doc {
        Doc::Null => Unexpected::Unit,
        Doc::Bool(flag) => Unexpected::Bool(*flag),
        Doc::Int(number) => Unexpected::Signed(*number),
        Doc::Str(text) => Unexpected::Str(text),
        Doc::Arr(_) => Unexpected::Seq,
        Doc::Obj(_) => Unexpected::Map,
    }
}

fn visit_array<'de, V: Visitor<'de>>(items: Vec<Doc>, visitor: V) -> Result<V::Value, Error> {
    let count = items.len();
    let mut access = ArrayAccess(items.into_iter());
    let value = visitor.visit_seq(&mut access)?;
    if access.0.len() != 0 {
        return Err(de::Error::invalid_length(count, &"fewer elements in the array"));
    }
    Ok(value)
}

fn visit_object<'de, V: Visitor<'de>>(members: Vec<(String, Doc)>, visitor: V) -> Result<V::Value, Error> {
    let mut access = ObjectAccess { members: members.into_iter(), value: None };
    visitor.visit_map(&mut access)
}

impl<'de> de::Deserializer<'de> for DocDeserializer {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Doc::Null => visitor.visit_unit(),
            Doc::Bool(flag) => visitor.visit_bool(flag),
            Doc::Int(number) => visitor.visit_i64(number),
            Doc::Str(text) => visitor.visit_string(text),
            Doc::Arr(items) => visit_array(items, visitor),
            Doc::Obj(members) => visit_object(members, visitor),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Doc::Null => visitor.visit_none(),
            doc => visitor.visit_some(DocDeserializer(doc)),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Doc::Arr(items) => visit_array(items, visitor),
            doc => Err(de::Error::invalid_type(unexpected(&doc), &visitor)),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(self, _name: &'static str, _len: usize, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Doc::Obj(members) => visit_object(members, visitor),
            doc => Err(de::Error::invalid_type(unexpected(&doc), &visitor)),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.0 {
            Doc::Str(variant) => visitor.visit_enum(EnumAccess { variant, value: None }),
            Doc::Obj(mut members) if members.len() == 1 => {
                let (variant, value) = members.remove(0);
                visitor.visit_enum(EnumAccess { variant, value: Some(value) })
            }
            doc => Err(de::Error::invalid_type(unexpected(&doc), &visitor)),
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf unit unit_struct
        identifier ignored_any
    }
}

struct ArrayAccess(std::vec::IntoIter<Doc>);

impl<'de> de::SeqAccess<'de> for ArrayAccess {
    type Error = Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, Error> {
        self.0.next().map(|doc| seed.deserialize(DocDeserializer(doc))).transpose()
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

struct ObjectAccess {
    members: std::vec::IntoIter<(String, Doc)>,
    value: Option<Doc>,
}

impl<'de> de::MapAccess<'de> for ObjectAccess {
    type Error = Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, Error> {
        match self.members.next() {
            Some((key, value)) => {
                self.value = Some(value);
                seed.deserialize(key.into_deserializer()).map(Some)
            }
            None => Ok(None),
        }
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let value = self.value.take().ok_or_else(|| Error::Shape("a value asked for with no key".to_string()))?;
        seed.deserialize(DocDeserializer(value))
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.members.len())
    }
}

struct EnumAccess {
    variant: String,
    value: Option<Doc>,
}

struct VariantAccess(Option<Doc>);

impl<'de> de::EnumAccess<'de> for EnumAccess {
    type Error = Error;
    type Variant = VariantAccess;
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, VariantAccess), Error> {
        let variant = seed.deserialize(self.variant.into_deserializer())?;
        Ok((variant, VariantAccess(self.value)))
    }
}

impl<'de> de::VariantAccess<'de> for VariantAccess {
    type Error = Error;
    fn unit_variant(self) -> Result<(), Error> {
        match self.0 {
            None => Ok(()),
            Some(doc) => Err(de::Error::invalid_type(unexpected(&doc), &"a unit variant, written as its name")),
        }
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        match self.0 {
            Some(doc) => seed.deserialize(DocDeserializer(doc)),
            None => Err(de::Error::invalid_type(Unexpected::UnitVariant, &"a newtype variant")),
        }
    }
    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Some(Doc::Arr(items)) => visit_array(items, visitor),
            Some(doc) => Err(de::Error::invalid_type(unexpected(&doc), &visitor)),
            None => Err(de::Error::invalid_type(Unexpected::UnitVariant, &visitor)),
        }
    }
    fn struct_variant<V: Visitor<'de>>(self, _fields: &'static [&'static str], visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Some(Doc::Obj(members)) => visit_object(members, visitor),
            Some(doc) => Err(de::Error::invalid_type(unexpected(&doc), &visitor)),
            None => Err(de::Error::invalid_type(Unexpected::UnitVariant, &visitor)),
        }
    }
}

// ------------------------------------------------------------------ Doc as a serde value

impl Serialize for Doc {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use ser::SerializeMap;
        match self {
            Doc::Null => serializer.serialize_unit(),
            Doc::Bool(flag) => serializer.serialize_bool(*flag),
            Doc::Int(number) => serializer.serialize_i64(*number),
            Doc::Str(text) => serializer.serialize_str(text),
            Doc::Arr(items) => serializer.collect_seq(items),
            Doc::Obj(members) => {
                let mut map = serializer.serialize_map(Some(members.len()))?;
                for (key, value) in members {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

struct DocVisitor;

impl<'de> Visitor<'de> for DocVisitor {
    type Value = Doc;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a canon/2 value")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Doc, E> {
        Ok(Doc::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Doc, E> {
        Ok(Doc::Null)
    }
    fn visit_some<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Doc, D::Error> {
        Doc::deserialize(deserializer)
    }
    fn visit_bool<E: de::Error>(self, flag: bool) -> Result<Doc, E> {
        Ok(Doc::Bool(flag))
    }
    fn visit_i64<E: de::Error>(self, number: i64) -> Result<Doc, E> {
        integer(number).map_err(|_| E::invalid_value(Unexpected::Signed(number), &self))
    }
    fn visit_u64<E: de::Error>(self, number: u64) -> Result<Doc, E> {
        integer(number).map_err(|_| E::invalid_value(Unexpected::Unsigned(number), &self))
    }
    fn visit_f64<E: de::Error>(self, number: f64) -> Result<Doc, E> {
        Err(E::invalid_type(Unexpected::Float(number), &self))
    }
    fn visit_str<E: de::Error>(self, text: &str) -> Result<Doc, E> {
        Ok(Doc::Str(text.to_string()))
    }
    fn visit_string<E: de::Error>(self, text: String) -> Result<Doc, E> {
        Ok(Doc::Str(text))
    }
    fn visit_seq<A: de::SeqAccess<'de>>(self, mut access: A) -> Result<Doc, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = access.next_element()? {
            items.push(item);
        }
        Ok(Doc::Arr(items))
    }
    fn visit_map<A: de::MapAccess<'de>>(self, mut access: A) -> Result<Doc, A::Error> {
        let mut members: Vec<(String, Doc)> = Vec::new();
        while let Some((key, value)) = access.next_entry::<String, Doc>()? {
            if members.iter().any(|(seen, _)| *seen == key) {
                return Err(de::Error::custom(format!("the key {key:?} twice")));
            }
            members.push((key, value));
        }
        Ok(Doc::Obj(members))
    }
}

impl<'de> Deserialize<'de> for Doc {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Doc, D::Error> {
        deserializer.deserialize_any(DocVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Sample {
        name: String,
        count: i64,
        flag: bool,
        tags: Vec<String>,
        maybe: Option<u16>,
        nested: BTreeMap<String, i64>,
        kind: Kind,
        any: Doc,
    }

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    enum Kind {
        #[serde(rename = "plain")]
        Plain,
        Wrapped(i64),
        Pair(i64, String),
        Shaped { width: i64 },
    }

    fn sample() -> Sample {
        Sample {
            name: "é\"\n".to_string(),
            count: -EXACT_LIMIT,
            flag: true,
            tags: vec!["b".to_string(), "a".to_string()],
            maybe: None,
            nested: [("z".to_string(), 1), ("a".to_string(), 2)].into_iter().collect(),
            kind: Kind::Plain,
            any: Doc::Arr(vec![Doc::Null, Doc::Int(3)]),
        }
    }

    #[test]
    fn a_struct_writes_its_canonical_bytes_and_reads_back() {
        let bytes = to_bytes(&sample()).unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            "{\"any\":[null,3],\"count\":-9007199254740991,\"flag\":true,\"kind\":\"plain\",\"maybe\":null,\
             \"name\":\"é\\\"\\n\",\"nested\":{\"a\":2,\"z\":1},\"tags\":[\"b\",\"a\"]}"
        );
        assert_eq!(from_bytes::<Sample>(&bytes).unwrap(), sample());
    }

    #[test]
    fn every_enum_form_round_trips() {
        for kind in [Kind::Plain, Kind::Wrapped(4), Kind::Pair(1, "x".to_string()), Kind::Shaped { width: 2 }] {
            let bytes = to_bytes(&kind).unwrap();
            assert_eq!(from_bytes::<Kind>(&bytes).unwrap(), kind);
        }
        assert_eq!(to_bytes(&Kind::Wrapped(4)).unwrap(), b"{\"Wrapped\":4}");
    }

    #[test]
    fn a_member_missing_or_extra_or_of_another_kind_is_a_shape_error() {
        let doc = to_doc(&sample()).unwrap();
        let Doc::Obj(members) = doc else { panic!("an object") };
        let without: Vec<_> = members.iter().filter(|(key, _)| key != "count").cloned().collect();
        assert!(matches!(from_doc::<Sample>(Doc::Obj(without)), Err(Error::Shape(_))));
        let mut extra = members.clone();
        extra.push(("note".to_string(), Doc::Null));
        assert!(matches!(from_doc::<Sample>(Doc::Obj(extra)), Err(Error::Shape(_))));
        let mut flag_as_int = members.clone();
        for member in flag_as_int.iter_mut().filter(|(key, _)| key == "flag") {
            member.1 = Doc::Int(1);
        }
        assert!(matches!(from_doc::<Sample>(Doc::Obj(flag_as_int)), Err(Error::Shape(_))));
        let mut count_as_bool = members;
        for member in count_as_bool.iter_mut().filter(|(key, _)| key == "count") {
            member.1 = Doc::Bool(true);
        }
        assert!(matches!(from_doc::<Sample>(Doc::Obj(count_as_bool)), Err(Error::Shape(_))));
    }

    #[test]
    fn a_struct_never_reads_from_an_array() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Two {
            left: i64,
            right: i64,
        }
        assert!(matches!(from_bytes::<Two>(b"[1,2]"), Err(Error::Shape(_))));
        assert!(matches!(from_bytes::<Vec<i64>>(b"{\"a\":1}"), Err(Error::Shape(_))));
        assert!(matches!(from_bytes::<(i64, i64)>(b"[1,2,3]"), Err(Error::Shape(_))));
    }

    #[test]
    fn the_strict_reader_runs_before_the_type() {
        assert!(from_bytes::<Doc>(b"{\"b\":1,\"a\":2}").unwrap_err().is_not_canonical());
        assert_eq!(from_bytes::<Doc>(b"1.5"), Err(Error::Canon2(Canon2Error::Float)));
        assert_eq!(from_bytes::<i64>(b"{\"a\":1,\"a\":1}"), Err(Error::Canon2(Canon2Error::DuplicateKey)));
    }

    #[test]
    fn a_value_with_no_canon2_form_is_refused() {
        assert_eq!(to_bytes(&1.5f64), Err(Error::Canon2(Canon2Error::Float)));
        assert_eq!(to_bytes(&(1u64 << 53)), Err(Error::Canon2(Canon2Error::IntegerRange)));
        assert!(matches!(to_bytes(&serde_bytes_like()), Err(Error::Shape(_))));
        let keyed: BTreeMap<i64, i64> = [(1, 2)].into_iter().collect();
        assert!(matches!(to_bytes(&keyed), Err(Error::Shape(_))));
        let twice = Doc::Obj(vec![("a".to_string(), Doc::Null), ("a".to_string(), Doc::Null)]);
        assert_eq!(to_bytes(&twice), Err(Error::Canon2(Canon2Error::DuplicateKey)));
    }

    struct BytesValue;
    impl serde::Serialize for BytesValue {
        fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(b"raw")
        }
    }
    fn serde_bytes_like() -> BytesValue {
        BytesValue
    }

    #[test]
    fn a_doc_round_trips_through_its_own_serde_and_through_serde_json() {
        let doc = read(b"{\"a\":[1,{\"b\":null}],\"c\":\"d\",\"e\":false}").unwrap();
        assert_eq!(from_doc::<Doc>(to_doc(&doc).unwrap()).unwrap(), doc);
        let json: serde_json::Value = from_doc(doc.clone()).unwrap();
        assert_eq!(json, doc.to_json());
        assert!(matches!(to_doc(&json), Err(Error::Shape(_))), "a serde_json number goes through from_json");
    }
}
