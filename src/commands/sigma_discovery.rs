use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SigmaPluginEntry {
    pub(crate) plugin_type: String,
    pub(crate) identifier: String,
    pub(crate) compatible: Option<bool>,
}

pub(crate) fn parse_plugin_list(stdout: &str) -> Result<Vec<SigmaPluginEntry>, String> {
    let mut parsed = parse_table(stdout);
    if parsed.is_empty() {
        parsed = parse_fallback(stdout);
    }
    if parsed.is_empty() {
        return Err("unable to parse sigma plugin list output".to_string());
    }

    let mut seen = BTreeSet::new();
    parsed.retain(|entry| {
        if seen.contains(&entry.identifier) {
            return false;
        }
        seen.insert(entry.identifier.clone());
        true
    });
    Ok(parsed)
}

fn parse_table(stdout: &str) -> Vec<SigmaPluginEntry> {
    let lines = stdout.lines().collect::<Vec<_>>();
    let mut header_idx = None;
    let mut header_cols = Vec::<String>::new();

    for (idx, line) in lines.iter().enumerate() {
        let cols = split_row(line);
        if cols.len() < 2 || is_separator_row(&cols) {
            continue;
        }
        let lowered = cols
            .iter()
            .map(|value| normalize_header(value))
            .collect::<Vec<_>>();
        if lowered.iter().any(|value| value.contains("type"))
            && lowered.iter().any(|value| {
                value == "id" || value.contains("identifier") || value.contains("name")
            })
        {
            header_idx = Some(idx);
            header_cols = lowered;
            break;
        }
    }

    let Some(start_idx) = header_idx else {
        return Vec::new();
    };

    let type_idx = header_cols.iter().position(|col| col.contains("type"));
    let id_idx = header_cols
        .iter()
        .position(|col| col == "id" || col.contains("identifier") || col.contains("name"));
    let compat_idx = header_cols
        .iter()
        .position(|col| col.contains("compatible"));
    let (Some(type_idx), Some(id_idx)) = (type_idx, id_idx) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for line in lines.iter().skip(start_idx + 1) {
        let cols = split_row(line);
        if cols.is_empty() || is_separator_row(&cols) {
            continue;
        }
        if cols.len() <= type_idx || cols.len() <= id_idx {
            continue;
        }
        let plugin_type = cols[type_idx].trim().to_ascii_lowercase();
        let identifier = normalize_identifier(&cols[id_idx]);
        if plugin_type.is_empty() || identifier.is_empty() {
            continue;
        }
        let compatible = compat_idx
            .and_then(|idx| cols.get(idx))
            .and_then(|value| parse_compatibility(value));
        out.push(SigmaPluginEntry {
            plugin_type,
            identifier,
            compatible,
        });
    }
    out
}

fn parse_fallback(stdout: &str) -> Vec<SigmaPluginEntry> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let raw = line.trim();
        if raw.is_empty() {
            continue;
        }
        let tokens = raw.split_whitespace().collect::<Vec<_>>();
        if tokens.len() < 2 {
            continue;
        }
        if !tokens[0].eq_ignore_ascii_case("backend") {
            continue;
        }
        let identifier = normalize_identifier(tokens[1]);
        if identifier.is_empty() {
            continue;
        }
        let compatible = tokens.iter().find_map(|token| parse_compatibility(token));
        out.push(SigmaPluginEntry {
            plugin_type: "backend".to_string(),
            identifier,
            compatible,
        });
    }
    out
}

fn split_row(line: &str) -> Vec<String> {
    if !line.contains('|') {
        return Vec::new();
    }
    line.split('|')
        .map(|cell| cell.trim())
        .filter(|cell| !cell.is_empty())
        .map(|cell| cell.to_string())
        .collect()
}

fn is_separator_row(cols: &[String]) -> bool {
    cols.iter().all(|cell| {
        !cell.is_empty()
            && cell
                .chars()
                .all(|ch| matches!(ch, '-' | '+' | '=' | ':' | '.'))
    })
}

fn normalize_header(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '?')
        .collect::<String>()
}

fn normalize_identifier(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .collect::<String>()
}

fn parse_compatibility(value: &str) -> Option<bool> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized == "yes" || normalized == "true" {
        return Some(true);
    }
    if normalized == "no" || normalized == "false" {
        return Some(false);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plugin_table_filters_backend_shape() {
        let sample = r#"
| Type     | Identifier     | Description         | Compatible? |
|----------|----------------|---------------------|-------------|
| backend  | splunk         | Splunk backend      | yes         |
| backend  | elasticsearch  | Elastic backend     | yes         |
| backend  | secops         | SecOps backend      | no          |
| pipeline | secops_udm     | SecOps pipeline     | yes         |
"#;
        let entries = parse_plugin_list(sample).expect("table parsed");
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].plugin_type, "backend");
        assert_eq!(entries[0].identifier, "splunk");
        assert_eq!(entries[0].compatible, Some(true));
    }

    #[test]
    fn parse_plugin_table_handles_missing_compatibility_column() {
        let sample = r#"
| Type     | ID        |
|----------|-----------|
| backend  | splunk    |
"#;
        let entries = parse_plugin_list(sample).expect("table parsed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].compatible, None);
    }

    #[test]
    fn parse_validated_sample_plugin_output() {
        let sample = r#"
| Type     | Identifier        | Compatible? |
|----------|-------------------|-------------|
| backend  | splunk            | yes         |
| backend  | elasticsearch     | yes         |
| backend  | opensearch        | yes         |
| backend  | loki              | yes         |
| backend  | crowdstrike       | yes         |
| backend  | kusto             | yes         |
| backend  | secops            | yes         |
| backend  | sqlite            | yes         |
| backend  | logpoint          | yes         |
| backend  | quickwit          | yes         |
| backend  | netwitness        | yes         |
| backend  | carbonblack       | yes         |
| backend  | cortexxdr         | yes         |
| backend  | sentinelone       | yes         |
| backend  | sentinelone-pq    | yes         |
| backend  | golangexpr        | yes         |
| backend  | disabled_backend  | no          |
| pipeline | ecs_windows       | yes         |
"#;
        let entries = parse_plugin_list(sample).expect("parsed");
        let identifiers = entries
            .iter()
            .map(|entry| entry.identifier.as_str())
            .collect::<Vec<_>>();
        assert!(identifiers.contains(&"splunk"));
        assert!(identifiers.contains(&"elasticsearch"));
        assert!(identifiers.contains(&"golangexpr"));
    }
}
