use anyhow::Result;

use crate::emulation::ability::Ability;
use crate::emulation::agents::AbilityExporter;
use crate::emulation::materialize;

pub struct BashExporter;

fn sh_single_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

impl AbilityExporter for BashExporter {
    fn export(&self, ability: &Ability) -> Result<String> {
        let plan = materialize::build_materialization_plan(ability)?;
        let mut out = String::new();
        out.push_str("#!/usr/bin/env bash\n");
        out.push_str("set -euo pipefail\n\n");
        out.push_str("# SPUC generated defensive emulation artifact\n");
        out.push_str(&format!("# ability_id: {}\n", ability.id));
        out.push_str(&format!("# schema_version: {}\n", ability.schema_version));
        out.push_str(&format!(
            "# source_pattern: {}\n\n",
            ability.source_pattern.replace('\n', " ")
        ));
        out.push_str("SPUC_USER_HOME=\"${HOME:-/tmp}\"\n");
        out.push_str("SPUC_ROOT=\"$SPUC_USER_HOME/spuc-emulation\"\n");
        out.push_str("mkdir -p \"$SPUC_ROOT\"\n");
        out.push_str("echo \"[spuc] running defensive emulation artifact\"\n");

        if plan.directories.is_empty()
            && plan.files.is_empty()
            && plan.processes.is_empty()
            && plan.registry.is_empty()
            && plan.network.is_empty()
        {
            for action in &ability.actions {
                out.push_str(&format!(
                    "echo \"[spuc] action {}: {} {} '{}'\"\n",
                    action.id,
                    action.observable,
                    action.operator,
                    action.value.replace('\"', "\\\"")
                ));
            }
            return Ok(out);
        }

        for dir in plan.directories {
            let dir_q = sh_single_quote(&dir.path);
            out.push_str(&format!(
                "DIR_PATH={dir_q}\nif [[ \"$DIR_PATH\" = /* ]]; then TARGET_DIR=\"$DIR_PATH\"; else TARGET_DIR=\"$SPUC_ROOT/$DIR_PATH\"; fi\nmkdir -p \"$TARGET_DIR\"\n"
            ));
            out.push_str("echo \"[spuc] materialized directory: $TARGET_DIR\"\n");
        }

        for (idx, file) in plan.files.iter().enumerate() {
            let file_q = sh_single_quote(&file.path);
            out.push_str(&format!(
                "FILE_PATH={file_q}\nif [[ \"$FILE_PATH\" = /* ]]; then TARGET_FILE=\"$FILE_PATH\"; else TARGET_FILE=\"$SPUC_ROOT/$FILE_PATH\"; fi\nmkdir -p \"$(dirname \"$TARGET_FILE\")\"\n"
            ));
            if let Some(content) = &file.content_literal {
                let heredoc_tag = format!("SPUC_CONTENT_{idx}");
                out.push_str(&format!("cat <<'{heredoc_tag}' > \"$TARGET_FILE\"\n"));
                out.push_str(content);
                out.push('\n');
                out.push_str(&format!("{heredoc_tag}\n"));
            } else {
                out.push_str(": > \"$TARGET_FILE\"\n");
            }
            if let Some(size) = file.size_bytes {
                out.push_str(&format!("TARGET_SIZE={size}\n"));
                out.push_str("if command -v truncate >/dev/null 2>&1; then truncate -s \"$TARGET_SIZE\" \"$TARGET_FILE\"; else dd if=/dev/zero of=\"$TARGET_FILE\" bs=1 count=\"$TARGET_SIZE\" status=none; fi\n");
            }
            out.push_str("echo \"[spuc] materialized file: $TARGET_FILE\"\n");
        }

        for process in plan.processes {
            if let Some(cwd) = &process.working_directory {
                let cwd_q = sh_single_quote(cwd);
                out.push_str(&format!(
                    "PROC_CWD={cwd_q}\nif [[ \"$PROC_CWD\" = /* ]]; then TARGET_CWD=\"$PROC_CWD\"; else TARGET_CWD=\"$SPUC_ROOT/$PROC_CWD\"; fi\nmkdir -p \"$TARGET_CWD\"\n"
                ));
            } else {
                out.push_str("TARGET_CWD=\"$SPUC_ROOT\"\n");
            }
            if let Some(name) = &process.process_name {
                let name_q = sh_single_quote(name);
                out.push_str(&format!(
                    "PROC_NAME={name_q}\n( cd \"$TARGET_CWD\" && bash -c \"exec -a \\\"$PROC_NAME\\\" sleep 1\" >/dev/null 2>&1 ) || true\n"
                ));
            }
            let cmd_q = sh_single_quote(&process.command_line);
            out.push_str(&format!(
                "PROC_CMD={cmd_q}\n( cd \"$TARGET_CWD\" && bash -lc \"$PROC_CMD\" ) >/dev/null 2>&1 || true\n"
            ));
            out.push_str("echo \"[spuc] executed process probe in $TARGET_CWD\"\n");
        }

        if !plan.registry.is_empty() {
            out.push_str(
                "echo \"[spuc] note: bash exporter skips windows registry materialization; use powershell for concrete registry actions\"\n",
            );
        }

        for net in plan.network {
            let destination_q = sh_single_quote(&net.destination);
            let port = net
                .port
                .unwrap_or(if net.protocol == "dns" { 53 } else { 443 });
            out.push_str(&format!(
                "NET_DEST={destination_q}\nNET_PORT={port}\nNET_PROTO={}\n",
                sh_single_quote(&net.protocol)
            ));
            if net.mode == "dns_query" || net.protocol == "dns" {
                out.push_str("if command -v dig >/dev/null 2>&1; then dig +time=2 +tries=1 \"$NET_DEST\" >/dev/null 2>&1 || true; elif command -v nslookup >/dev/null 2>&1; then nslookup \"$NET_DEST\" >/dev/null 2>&1 || true; elif command -v getent >/dev/null 2>&1; then getent ahosts \"$NET_DEST\" >/dev/null 2>&1 || true; fi\n");
                out.push_str("echo \"[spuc] executed dns probe to $NET_DEST:$NET_PORT\"\n");
                continue;
            }
            out.push_str("if [[ \"$NET_PROTO\" = \"udp\" ]]; then\n");
            out.push_str("  if command -v nc >/dev/null 2>&1; then printf 'spuc' | nc -u -w 2 \"$NET_DEST\" \"$NET_PORT\" >/dev/null 2>&1 || true; else bash -lc \"echo spuc >/dev/udp/$NET_DEST/$NET_PORT\" >/dev/null 2>&1 || true; fi\n");
            out.push_str("else\n");
            out.push_str(
                "  bash -lc \"echo >/dev/tcp/$NET_DEST/$NET_PORT\" >/dev/null 2>&1 || true\n",
            );
            out.push_str("fi\n");
            out.push_str(
                "echo \"[spuc] executed network probe to $NET_DEST:$NET_PORT/$NET_PROTO\"\n",
            );
        }

        for note in plan.notes {
            out.push_str(&format!(
                "echo \"[spuc] note: {}\"\n",
                note.replace('\"', "\\\"")
            ));
        }
        Ok(out)
    }
}
