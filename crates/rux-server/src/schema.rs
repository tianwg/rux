//! A small JSON Schema checker for the served Rex API catalog.
//!
//! It enforces the rules the public Server API page calls out: `type`,
//! `required`, and `additionalProperties: false`. Unknown schema keywords are
//! ignored. A JSON number is accepted for `integer` only when it has no
//! fraction.

use serde_json::Value;

pub fn validate(schema: &Value, value: &Value) -> Result<(), String> {
    validate_at(schema, value, None)
}

fn validate_at(schema: &Value, value: &Value, key: Option<&str>) -> Result<(), String> {
    let where_ = key.unwrap_or("input");
    if let Some(types) = schema.get("type") {
        if !type_matches(types, value) {
            return Err(format!("{where_} has the wrong type"));
        }
    }
    if value.is_object() {
        let obj = value.as_object().unwrap();
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (name, prop_schema) in properties {
                if let Some(child) = obj.get(name) {
                    if !child.is_null() || !type_allows_null(prop_schema.get("type")) {
                        validate_at(prop_schema, child, Some(name))?;
                    }
                }
            }
        }
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            let known = schema
                .get("properties")
                .and_then(Value::as_object)
                .map(|props| props.keys().collect::<Vec<_>>())
                .unwrap_or_default();
            for name in obj.keys() {
                if !known.iter().any(|known| *known == name) {
                    return Err(format!("unexpected property {name}"));
                }
            }
        }
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for name in required {
                let Some(name) = name.as_str() else { continue };
                if !obj.contains_key(name) {
                    return Err(format!("{name} is required"));
                }
            }
        }
    }
    if let Some(items) = schema.get("items") {
        if let Some(list) = value.as_array() {
            for (index, item) in list.iter().enumerate() {
                validate_at(items, item, Some(&format!("item {index}")))?;
            }
        }
    }
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_i64) {
        if let Some(number) = value.as_i64() {
            if number < minimum {
                return Err(format!("{where_} is below the minimum"));
            }
        }
    }
    if let Some(maximum) = schema.get("maximum").and_then(Value::as_i64) {
        if let Some(number) = value.as_i64() {
            if number > maximum {
                return Err(format!("{where_} is above the maximum"));
            }
        }
    }
    Ok(())
}

fn type_allows_null(types: Option<&Value>) -> bool {
    match types {
        Some(Value::String(text)) => text == "null",
        Some(Value::Array(list)) => list.iter().any(|item| item.as_str() == Some("null")),
        _ => false,
    }
}

fn type_matches(types: &Value, value: &Value) -> bool {
    match types {
        Value::String(text) => one_type(text, value),
        Value::Array(list) => list.iter().any(|item| {
            item.as_str()
                .map(|text| one_type(text, value))
                .unwrap_or(false)
        }),
        _ => true,
    }
}

fn one_type(text: &str, value: &Value) -> bool {
    match text {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        _ => true,
    }
}

pub fn reject(schema: &Value, value: &Value) -> Result<(), rux_proto::ApiError> {
    reject_as(schema, value, "input")
}

pub fn reject_as(schema: &Value, value: &Value, where_: &str) -> Result<(), rux_proto::ApiError> {
    validate(schema, value).map_err(|message| {
        rux_proto::ApiError::bad_request(format!("{where_}: validating: {message}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unexpected_properties_are_rejected() {
        let schema = json!({
            "type": "object",
            "properties": { "session_id": { "type": "string" }, "label": { "type": "string" } },
            "required": ["session_id"],
            "additionalProperties": false
        });
        let err = validate(&schema, &json!({"session_id": "session:x", "lable": "x"})).unwrap_err();
        assert!(err.contains("unexpected property lable"), "{err}");
    }

    #[test]
    fn missing_required_fields_are_rejected() {
        let schema = json!({
            "type": "object",
            "properties": { "block_id": { "type": ["string", "null"] } },
            "required": ["block_id"],
            "additionalProperties": false
        });
        let err = validate(&schema, &json!({})).unwrap_err();
        assert!(err.contains("block_id is required"), "{err}");
    }
}
