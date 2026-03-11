use anyhow::Result;

use crate::emulation::ability::Ability;
use crate::emulation::agents::AbilityExporter;
use crate::emulation::materialize;

pub struct PowershellExporter;

impl AbilityExporter for PowershellExporter {
    fn export(&self, ability: &Ability) -> Result<String> {
        let plan = materialize::build_materialization_plan(ability)?;
        let mut out = String::new();
        out.push_str("# SPUC generated defensive emulation artifact\n");
        out.push_str(&format!("# ability_id: {}\n", ability.id));
        out.push_str(&format!("# schema_version: {}\n", ability.schema_version));
        out.push_str(&format!(
            "# source_pattern: {}\n\n",
            ability.source_pattern.replace('\n', " ")
        ));
        out.push_str("$ErrorActionPreference = 'Stop'\n");
        out.push_str("$SpucUserHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }\n");
        out.push_str("$SpucRoot = Join-Path $SpucUserHome 'spuc-emulation'\n");
        out.push_str("if (!(Test-Path -LiteralPath $SpucRoot)) { New-Item -ItemType Directory -Path $SpucRoot -Force | Out-Null }\n");
        out.push_str("Write-Host \"[spuc] running defensive emulation artifact\"\n");

        if plan.directories.is_empty()
            && plan.files.is_empty()
            && plan.processes.is_empty()
            && plan.registry.is_empty()
            && plan.network.is_empty()
        {
            for action in &ability.actions {
                out.push_str(&format!(
                    "Write-Host \"[spuc] action {}: {} {} '{}'\"\n",
                    action.id,
                    action.observable,
                    action.operator,
                    action.value.replace('\"', "`\"")
                ));
            }
            return Ok(out);
        }

        for dir in plan.directories {
            let path = dir.path.replace('\'', "''");
            out.push_str(&format!(
                "$DirPath = if ([System.IO.Path]::IsPathRooted('{path}')) {{ '{path}' }} else {{ Join-Path $SpucRoot '{path}' }}\n"
            ));
            out.push_str("if (!(Test-Path -LiteralPath $DirPath)) { New-Item -ItemType Directory -Path $DirPath -Force | Out-Null }\n");
            out.push_str("Write-Host \"[spuc] materialized directory: $DirPath\"\n");
        }

        for file in plan.files {
            let path = file.path.replace('\'', "''");
            out.push_str(&format!(
                "$FilePath = if ([System.IO.Path]::IsPathRooted('{path}')) {{ '{path}' }} else {{ Join-Path $SpucRoot '{path}' }}\n"
            ));
            out.push_str("$FileDir = Split-Path -Parent $FilePath\n");
            out.push_str("if ($FileDir -and !(Test-Path -LiteralPath $FileDir)) { New-Item -ItemType Directory -Path $FileDir -Force | Out-Null }\n");
            if let Some(content) = file.content_literal {
                let escaped = content.replace('\'', "''");
                out.push_str(&format!(
                    "[System.IO.File]::WriteAllText($FilePath, '{escaped}')\n"
                ));
            } else {
                out.push_str("if (!(Test-Path -LiteralPath $FilePath)) { [System.IO.File]::WriteAllText($FilePath, '') }\n");
            }
            if let Some(size) = file.size_bytes {
                out.push_str(&format!("$SizeBytes = {size}\n"));
                out.push_str("$Current = [System.IO.File]::ReadAllBytes($FilePath)\n");
                out.push_str("$Buffer = New-Object byte[] $SizeBytes\n");
                out.push_str(
                    "[Array]::Copy($Current, $Buffer, [Math]::Min($Current.Length, $SizeBytes))\n",
                );
                out.push_str("[System.IO.File]::WriteAllBytes($FilePath, $Buffer)\n");
            }
            out.push_str("Write-Host \"[spuc] materialized file: $FilePath\"\n");
        }

        for process in plan.processes {
            if let Some(cwd) = process.working_directory {
                let path = cwd.replace('\'', "''");
                out.push_str(&format!(
                    "$ProcCwd = if ([System.IO.Path]::IsPathRooted('{path}')) {{ '{path}' }} else {{ Join-Path $SpucRoot '{path}' }}\n"
                ));
                out.push_str("if (!(Test-Path -LiteralPath $ProcCwd)) { New-Item -ItemType Directory -Path $ProcCwd -Force | Out-Null }\n");
            } else {
                out.push_str("$ProcCwd = $SpucRoot\n");
            }
            if let Some(name) = process.process_name {
                let escaped = name.replace('\'', "''");
                out.push_str(&format!(
                    "if (Get-Command '{escaped}' -ErrorAction SilentlyContinue) {{ Start-Process -FilePath '{escaped}' -ArgumentList '--spuc-benign' -WorkingDirectory $ProcCwd -WindowStyle Hidden | Out-Null }} else {{ Write-Host \"[spuc] note: process:name hint '{escaped}' is not available on this host\" }}\n"
                ));
            }
            let cmd = process.command_line.replace('\'', "''");
            out.push_str(&format!(
                "$ProcCmd = '{cmd}'\nPush-Location $ProcCwd\ntry {{ & cmd /c $ProcCmd | Out-Null }} finally {{ Pop-Location }}\nWrite-Host \"[spuc] executed process probe in $ProcCwd\"\n"
            ));
        }

        for reg in plan.registry {
            let key_raw = reg.key_path.replace('\'', "''");
            out.push_str(&format!("$RegPathRaw = '{key_raw}'\n"));
            out.push_str("$RegPath = if ($RegPathRaw.StartsWith('Registry::')) { $RegPathRaw } elseif ($RegPathRaw.StartsWith('HKCU:\\') -or $RegPathRaw.StartsWith('HKLM:\\')) { $RegPathRaw } else { \"Registry::$RegPathRaw\" }\n");
            out.push_str("if (!(Test-Path -LiteralPath $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }\n");
            if let Some(count) = reg.subkey_count {
                out.push_str(&format!(
                    "1..{count} | ForEach-Object {{ $Sub = Join-Path $RegPath (\"subkey-{{0:D3}}\" -f $_); New-Item -Path $Sub -Force | Out-Null }}\n"
                ));
            }
            if let Some(value_name) = reg.value_name {
                let name_escaped = value_name.replace('\'', "''");
                let value_type = reg.value_type.unwrap_or_else(|| "REG_SZ".to_string());
                if value_type == "REG_DWORD" {
                    let value_raw = reg.value_data.unwrap_or_else(|| "1".to_string());
                    let parsed = value_raw.trim().parse::<i64>().unwrap_or(1);
                    out.push_str(&format!(
                        "New-ItemProperty -Path $RegPath -Name '{name_escaped}' -PropertyType DWord -Value {parsed} -Force | Out-Null\n"
                    ));
                } else {
                    let value_raw = reg
                        .value_data
                        .unwrap_or_else(|| "spuc-registry-data".to_string());
                    let value_escaped = value_raw.replace('\'', "''");
                    out.push_str(&format!(
                        "New-ItemProperty -Path $RegPath -Name '{name_escaped}' -PropertyType String -Value '{value_escaped}' -Force | Out-Null\n"
                    ));
                }
            }
            out.push_str("Write-Host \"[spuc] materialized registry key: $RegPath\"\n");
        }

        for net in plan.network {
            let destination = net.destination.replace('\'', "''");
            let port = net
                .port
                .unwrap_or(if net.protocol == "dns" { 53 } else { 443 });
            if net.mode == "dns_query" || net.protocol == "dns" {
                out.push_str(&format!(
                    "try {{ Resolve-DnsName -Name '{destination}' -Type A -ErrorAction Stop | Out-Null }} catch {{ [System.Net.Dns]::GetHostAddresses('{destination}') | Out-Null }}\nWrite-Host \"[spuc] executed dns probe to {destination}:{port}\"\n"
                ));
                continue;
            }
            if net.protocol == "udp" {
                out.push_str(&format!(
                    "$Udp = New-Object System.Net.Sockets.UdpClient\n$Bytes = [System.Text.Encoding]::UTF8.GetBytes('spuc')\n$Udp.Send($Bytes, $Bytes.Length, '{destination}', {port}) | Out-Null\n$Udp.Close()\nWrite-Host \"[spuc] executed network probe to {destination}:{port}/udp\"\n"
                ));
            } else {
                out.push_str(&format!(
                    "Test-NetConnection -ComputerName '{destination}' -Port {port} -InformationLevel Quiet | Out-Null\nWrite-Host \"[spuc] executed network probe to {destination}:{port}/tcp\"\n"
                ));
            }
        }

        for note in plan.notes {
            out.push_str(&format!(
                "Write-Host \"[spuc] note: {}\"\n",
                note.replace('\"', "`\"")
            ));
        }
        Ok(out)
    }
}
