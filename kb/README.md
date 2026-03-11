# Knowledge Base Layout

This folder contains analyst knowledge, standards references, and visual/data assets.

## Structure

- `kb/standards/`
  - immutable standards/reference artifacts
  - must not be edited during normal development
- `kb/guides/`
  - analyst-oriented interpretation guides
  - human-readable support material for STIX understanding
- `kb/assets/`
  - diagrams and generated/sample data used in docs and examples

## Immutable Files

The following files are immutable in this repository workflow and must remain untouched:

- `kb/standards/STIXPattern.g4`
- `kb/standards/stix-v2.1-cs01.html`

## Notes

- English/Spanish guides are preserved as authoritative interpretation aids:
  - `kb/guides/GUIDE_EN.md`
  - `kb/guides/GUIDE_ES.md`
- Visual/data assets currently used in docs:
  - `kb/assets/semantic-fidelity.svg`
  - `kb/assets/spuc_output.csv`
