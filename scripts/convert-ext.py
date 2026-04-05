#!/usr/bin/env python3
"""
Convert pattern extension files (specificityScore format) into pattern-engine.ts extensions.
Handles:  pattern-ng-*.ts  (new groups)
          pattern-tu-*.ts  (top-up existing groups)
Outputs TypeScript const arrays using p() helper and MASTER_PATTERNS spreads.
"""
import re, sys, os, json

SCAM_DIR = r"c:\Users\moham\OneDrive\Documents\claude code\scamshield\src\lib\algorithms"

def score_to_weight(score):
    """Convert 0.0-1.0 specificityScore to integer weight (6-20 scale)."""
    return max(6, min(20, round(float(score) * 20)))

def parse_ext_file(filepath):
    """Parse a pattern extension file. Returns list of (const_name, entries[]) tuples."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    results = []
    # Find all exported const declarations
    const_pattern = re.compile(
        r'export\s+const\s+(\w+)[^=]*=\s*\[([^\]]*(?:\[[^\]]*\][^\]]*)*)\]',
        re.DOTALL
    )

    for m in const_pattern.finditer(content):
        const_name = m.group(1)
        body = m.group(2)

        entries = []
        # Match object literals
        obj_pattern = re.compile(
            r'\{[^}]*?group:\s*[\'"]([^\'"]+)[\'"][^}]*?category:\s*[\'"]([^\'"]+)[\'"][^}]*?text:\s*[\'"]([^\'"]+)[\'"][^}]*?specificityScore:\s*([\d.]+)[^}]*?severity:\s*[\'"]([^\'"]+)[\'"][^}]*?\}',
            re.DOTALL
        )

        for obj_m in obj_pattern.finditer(body):
            group = obj_m.group(1)
            category = obj_m.group(2)
            text = obj_m.group(3)
            score = obj_m.group(4)
            severity = obj_m.group(5)
            weight = score_to_weight(score)
            entries.append((group, category, text, weight, severity))

        if entries:
            results.append((const_name, entries))

    return results

def generate_typescript(all_consts):
    """Generate TypeScript code for all const arrays."""
    lines = []
    const_names = []

    for const_name, entries in all_consts:
        lines.append(f'const {const_name}: PatternEntry[] = [')
        for group, category, text, weight, severity in entries:
            text_escaped = text.replace("'", "\\'")
            lines.append(f"  p('{group}', '{category}', '{text_escaped}', {weight}, '{severity}'),")
        lines.append('];')
        lines.append('')
        const_names.append(const_name)

    return '\n'.join(lines), const_names

def main():
    # Match pattern-ng-*.ts, pattern-tu-*.ts, and pattern-p200-*.ts files
    files = sorted([
        os.path.join(SCAM_DIR, f)
        for f in os.listdir(SCAM_DIR)
        if re.match(r'pattern-(ng|tu|p200)-[\w]+\.ts$', f)
    ])

    if not files:
        print("No pattern-ng-*.ts, pattern-tu-*.ts, or pattern-p200-*.ts files found", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(files)} file(s):", file=sys.stderr)

    all_consts = []
    for fpath in files:
        parsed = parse_ext_file(fpath)
        total_entries = sum(len(e) for _, e in parsed)
        print(f"  {os.path.basename(fpath)}: {len(parsed)} const(s), {total_entries} entries", file=sys.stderr)
        all_consts.extend(parsed)

    ts_code, const_names = generate_typescript(all_consts)

    total_entries = sum(len(e) for _, e in all_consts)
    print(f"\nTotal: {len(all_consts)} const arrays, {total_entries} patterns", file=sys.stderr)

    # Write output files
    ts_output = os.path.join(SCAM_DIR, "_ext_generated.ts")
    with open(ts_output, 'w', encoding='utf-8') as f:
        f.write("// AUTO-GENERATED — do not edit by hand\n\n")
        f.write(ts_code)

    names_output = os.path.join(SCAM_DIR, "_ext_names.json")
    with open(names_output, 'w', encoding='utf-8') as f:
        json.dump(const_names, f)

    print(f"\nWrote: {ts_output}", file=sys.stderr)
    print(f"Wrote: {names_output}", file=sys.stderr)

if __name__ == '__main__':
    main()
