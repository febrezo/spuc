#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputBlock {
    Summary,
    Canonical,
    Artifact,
    Manifest,
}

#[derive(Debug, Clone)]
pub struct OutputSection {
    pub block: OutputBlock,
    pub title: String,
    pub body: String,
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const BLUE: &str = "\x1b[34m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const PURPLE: &str = "\x1b[35m";

pub fn normalize_blocks(mut blocks: Vec<OutputBlock>) -> Vec<OutputBlock> {
    if blocks.is_empty() {
        return vec![OutputBlock::Summary];
    }
    let order = [
        OutputBlock::Summary,
        OutputBlock::Canonical,
        OutputBlock::Artifact,
        OutputBlock::Manifest,
    ];
    blocks.sort_by_key(|b| {
        order
            .iter()
            .position(|x| x == b)
            .expect("output block must exist")
    });
    blocks.dedup();
    blocks
}

pub fn render_sections(sections: &[OutputSection]) -> String {
    let mut out = String::new();
    let mut first = true;
    for section in sections {
        if section.body.trim().is_empty() {
            continue;
        }
        if !first {
            out.push('\n');
        }
        first = false;
        let (color, bar) = block_style(section.block);
        out.push_str(&format!(
            "{BOLD}{color}{bar} {} {bar}{RESET}\n{}\n",
            section.title, section.body
        ));
    }
    out
}

fn block_style(block: OutputBlock) -> (&'static str, &'static str) {
    match block {
        OutputBlock::Summary => (BLUE, "===="),
        OutputBlock::Canonical => (GREEN, "===="),
        OutputBlock::Artifact => (YELLOW, "===="),
        OutputBlock::Manifest => (PURPLE, "===="),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_blocks_deduplicates_and_orders() {
        let blocks = normalize_blocks(vec![
            OutputBlock::Artifact,
            OutputBlock::Summary,
            OutputBlock::Summary,
            OutputBlock::Canonical,
        ]);
        assert_eq!(
            blocks,
            vec![
                OutputBlock::Summary,
                OutputBlock::Canonical,
                OutputBlock::Artifact,
            ]
        );
    }

    #[test]
    fn render_sections_prints_clear_headers() {
        let rendered = render_sections(&[
            OutputSection {
                block: OutputBlock::Summary,
                title: "Summary".to_string(),
                body: "Card".to_string(),
            },
            OutputSection {
                block: OutputBlock::Canonical,
                title: "Canonical JSON".to_string(),
                body: "{\"id\":\"abl-1\"}".to_string(),
            },
        ]);
        assert!(rendered.contains("Summary"));
        assert!(rendered.contains("Canonical JSON"));
        assert!(rendered.contains("{\"id\":\"abl-1\"}"));
    }
}
