# SPUC Workflow Example

This folder demonstrates a practical analyst workflow from STIX pattern to intrusion-set manifest.

## 1) Build an ability from a STIX pattern

```bash
spuc emulate \
  --rule "[process:command_line MATCHES '^.*echo.*$']" \
  --to spuc-agent \
  --id abl-example-001 \
  --name "Echo command-line trace" \
  --show summary,canonical
```

## 2) Explore catalog

```bash
spuc catalog abilities
spuc catalog search echo --platform linux
```

## 3) Plan intrusion set from selected abilities

```bash
spuc plan \
  --name "Validation intrusion set" \
  --ability abl-example-001 \
  --show summary,manifest
```

## 4) Interactive mode

```bash
spuc explore
```

Then run:

- `emulate`
- `plan`

## Files in This Folder

- `ability-sample.json`: example canonical ability payload.
- `intrusion-set-sample.yaml`: example intrusion-set manifest structure.
