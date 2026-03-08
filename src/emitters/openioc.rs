#![allow(dead_code)]

use anyhow::{Result, bail};

use crate::emitters::EmitResult;
use crate::ir::{IrExpr, IrOp, IrPredicate, IrValue};

pub fn emit(ir: &IrExpr, _description: Option<&str>) -> Result<EmitResult> {
    let predicates = match ir {
        IrExpr::Predicate(p) => vec![p.clone()],
        IrExpr::All(exprs) => collect_predicates(exprs)?,
        IrExpr::Any(_) => {
            return Ok(EmitResult::unsupported(
                "OpenIOC emitter does not support OR yet",
            ));
        }
        IrExpr::FollowedBy(_) => {
            return Ok(EmitResult::unsupported(
                "OpenIOC emitter does not support FOLLOWEDBY sequence semantics yet",
            ));
        }
        IrExpr::Qualified(_, _) => {
            return Ok(EmitResult::unsupported(
                "OpenIOC emitter does NOT support observation qualifiers yet",
            ));
        }
    };

    let mut items = Vec::new();
    for p in predicates {
        items.push(lower_predicate(&p)?);
    }

    let items_xml = items.join("\n");
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ioc>
  <definition>
    <Indicator operator="OR">
{items_xml}
    </Indicator>
  </definition>
</ioc>"#
    );

    Ok(EmitResult::exact(xml))
}

fn lower_predicate(p: &IrPredicate) -> Result<String> {
    if p.op != IrOp::Eq {
        bail!("OpenIOC emitter only supports equality comparisons");
    }

    let (context, content_type, content) = match (p.target.as_str(), p.field.as_str(), &p.value) {
        ("ipv4-addr", "value", IrValue::String(v))
        | ("network-traffic", "src_ref.value", IrValue::String(v))
        | ("network-traffic", "dst_ref.value", IrValue::String(v)) => {
            ("PortItem/remoteIP", "string", v.clone())
        }
        ("network-traffic", "src_port", IrValue::Integer(v)) => {
            ("PortItem/localPort", "int", v.to_string())
        }
        ("network-traffic", "dst_port", IrValue::Integer(v)) => {
            ("PortItem/remotePort", "int", v.to_string())
        }
        ("artifact", "hashes.MD5", IrValue::String(v)) => ("FileItem/MD5sum", "string", v.clone()),
        ("artifact", "hashes.SHA-1", IrValue::String(v)) => {
            ("FileItem/SHA1sum", "string", v.clone())
        }
        ("artifact", "hashes.SHA-256", IrValue::String(v)) => {
            ("FileItem/Sha256sum", "string", v.clone())
        }
        ("artifact", "hashes.SHA-512", IrValue::String(v)) => {
            ("FileItem/Sha512sum", "string", v.clone())
        }
        ("artifact", field, IrValue::String(v)) if field.starts_with("hashes.SHA3-256") => {
            ("FileItem/SHA3_256", "string", v.clone())
        }
        ("artifact", field, IrValue::String(v)) if field.starts_with("hashes.SHA3-512") => {
            ("FileItem/SHA3_512", "string", v.clone())
        }
        ("artifact", field, IrValue::String(v)) if field.starts_with("hashes.SSDEEP") => {
            ("FileItem/ssdeep", "string", v.clone())
        }
        ("artifact", field, IrValue::String(v)) if field.starts_with("hashes.TLSH") => {
            ("FileItem/TLSH", "string", v.clone())
        }
        ("file", "hashes.MD5", IrValue::String(v)) => ("FileItem/MD5sum", "string", v.clone()),
        ("file", "hashes.SHA-1", IrValue::String(v)) => ("FileItem/SHA1sum", "string", v.clone()),
        ("file", "hashes.SHA-256", IrValue::String(v)) => {
            ("FileItem/Sha256sum", "string", v.clone())
        }
        ("file", "hashes.SHA-512", IrValue::String(v)) => {
            ("FileItem/Sha512sum", "string", v.clone())
        }
        ("file", field, IrValue::String(v)) if field.starts_with("hashes.SHA3-256") => {
            ("FileItem/SHA3_256", "string", v.clone())
        }
        ("file", field, IrValue::String(v)) if field.starts_with("hashes.SHA3-512") => {
            ("FileItem/SHA3_512", "string", v.clone())
        }
        ("file", field, IrValue::String(v)) if field.starts_with("hashes.SSDEEP") => {
            ("FileItem/ssdeep", "string", v.clone())
        }
        ("file", field, IrValue::String(v)) if field.starts_with("hashes.TLSH") => {
            ("FileItem/TLSH", "string", v.clone())
        }
        ("file", "name", IrValue::String(v)) => ("FileItem/FileName", "string", v.clone()),
        _ => {
            bail!(
                "OpenIOC emitter does not support predicate {}:{}",
                p.target,
                p.field
            )
        }
    };

    Ok(format!(
        r#"      <IndicatorItem condition="is">
        <Context document="PortItem" search="{context}" type="mir" />
        <Content type="{content_type}">{content}</Content>
      </IndicatorItem>"#
    ))
}

fn collect_predicates(exprs: &[IrExpr]) -> Result<Vec<IrPredicate>> {
    let mut predicates = Vec::new();
    for expr in exprs {
        match expr {
            IrExpr::Predicate(p) => predicates.push(p.clone()),
            IrExpr::All(nested) => predicates.extend(collect_predicates(nested)?),
            IrExpr::Any(_) => bail!("OpenIOC emitter does not support OR inside AND"),
            IrExpr::FollowedBy(_) => {
                bail!("OpenIOC emitter does not support FOLLOWEDBY sequence semantics")
            }
            IrExpr::Qualified(_, _) => {
                bail!("OpenIOC emitter does NOT support observation qualifiers")
            }
        }
    }
    Ok(predicates)
}
