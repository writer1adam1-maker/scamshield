#!/usr/bin/env python3
"""
Inject generated extension patterns into pattern-engine.ts.
Handles both new groups and top-ups for existing groups.
"""
import re, os, json

ALGORITHMS_DIR = r"c:\Users\moham\OneDrive\Documents\claude code\scamshield\src\lib\algorithms"
ENGINE_FILE = os.path.join(ALGORITHMS_DIR, "pattern-engine.ts")
GENERATED_FILE = os.path.join(ALGORITHMS_DIR, "_ext_generated.ts")
NAMES_FILE = os.path.join(ALGORITHMS_DIR, "_ext_names.json")

def main():
    with open(GENERATED_FILE, 'r', encoding='utf-8') as f:
        generated = f.read()

    with open(NAMES_FILE, 'r', encoding='utf-8') as f:
        const_names = json.load(f)

    with open(ENGINE_FILE, 'r', encoding='utf-8') as f:
        content = f.read()

    # Find which names are already in the engine file
    already_in_file = set(re.findall(r'\bconst\s+(\w+)\s*:', content))
    already_in_master = set(re.findall(r'\.\.\.([\w]+)', content))

    new_consts = [n for n in const_names if n not in already_in_file]
    new_spreads = [n for n in const_names if n not in already_in_master]

    print(f"Total const arrays: {len(const_names)}")
    print(f"New to insert: {len(new_consts)}")
    print(f"New spreads: {len(new_spreads)}")

    if not new_consts and not new_spreads:
        print("Nothing new to inject.")
        return

    # 1. Insert const declarations before the last pattern extension section
    if new_consts:
        # Filter generated content to only include new consts
        gen_lines = generated.split('\n')
        filtered_lines = []
        in_new_const = False
        current_const = None

        i = 0
        while i < len(gen_lines):
            line = gen_lines[i]
            # Check if this line starts a new const
            const_match = re.match(r'^const\s+(\w+)\s*:', line)
            if const_match:
                current_const = const_match.group(1)
                in_new_const = current_const in new_consts
            if in_new_const:
                filtered_lines.append(line)
            i += 1

        if filtered_lines:
            gen_content = '\n'.join(filtered_lines).strip() + '\n\n'

            # Find insertion point — before MASTER_PATTERNS assembly
            # Look for the last "// Pattern extensions" marker or TOPUP_EXT
            insertion_candidates = [
                '// ═══════════════════════════════════════════════════════════════════════════\n// ROUND 3 EXTENSIONS',
                '// ═══════════════════════════════════════════════════════════════════════════\n// ROUND 2 EXTENSIONS',
                '// ═══════════════════════════════════════════════════════════════════════════\n// TOP-UP EXTENSIONS',
                '// ═══════════════════════════════════════════════════════════════════════════\n// PATTERN EXTENSIONS (auto-generated)',
                '// ═══════════════════════════════════════════════════════════════════════════\n// MASTER PATTERNS',
            ]

            insert_pos = -1
            for candidate in insertion_candidates:
                pos = content.find(candidate)
                if pos != -1:
                    insert_pos = pos
                    break

            if insert_pos == -1:
                # Fallback: find export const MASTER_PATTERNS
                insert_pos = content.find('export const MASTER_PATTERNS')
                if insert_pos == -1:
                    insert_pos = content.find('const MASTER_PATTERNS')

            if insert_pos != -1:
                inject_header = (
                    "// ═══════════════════════════════════════════════════════════════════════════\n"
                    "// ROUND 3 EXTENSIONS — all groups to 200+, important groups to 250+\n"
                    "// ═══════════════════════════════════════════════════════════════════════════\n\n"
                )
                content = content[:insert_pos] + inject_header + gen_content + content[insert_pos:]
                print(f"Inserted {len(new_consts)} new const declarations.")
            else:
                print("ERROR: Could not find insertion point in engine file")
                return

    # 2. Add spread operators to MASTER_PATTERNS
    if new_spreads:
        # Find the closing ]; of MASTER_PATTERNS
        # Look for the last spread before ];
        # Find TOPUP_EXT or IMPERSONATION_B8 as last known spread
        last_spread_anchors = [
            '  ...ATO_TU,\n];',
            '  ...TOPUP_EXT,\n];',
            '  ...IMPERSONATION_B8,\n];',
            '  ...ACCOUNT_TAKEOVER,\n];',
        ]

        inserted = False
        for anchor in last_spread_anchors:
            if anchor in content:
                spreads_block = '\n'.join(f'  ...{n},' for n in new_spreads)
                content = content.replace(
                    anchor,
                    anchor.rstrip('\n;]') + f'\n  // Round 3 extensions (200+/250+)\n{spreads_block}\n];'
                )
                print(f"Added {len(new_spreads)} spreads to MASTER_PATTERNS.")
                inserted = True
                break

        if not inserted:
            # Find MASTER_PATTERNS array end via bracket matching
            mp_match = re.search(r'(export\s+)?const\s+MASTER_PATTERNS[^=]*=\s*\[', content)
            if mp_match:
                start = mp_match.end()
                depth = 1
                pos = start
                while pos < len(content) and depth > 0:
                    if content[pos] == '[': depth += 1
                    elif content[pos] == ']': depth -= 1
                    pos += 1
                closing = pos - 1
                spreads_block = '\n'.join(f'  ...{n},' for n in new_spreads)
                content = (content[:closing] +
                    '\n  // Round 2 extensions\n' + spreads_block + '\n' +
                    content[closing:])
                print(f"Added {len(new_spreads)} spreads (fallback method).")
            else:
                print("ERROR: Could not find MASTER_PATTERNS array")
                return

    with open(ENGINE_FILE, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\nDone! Run: npx tsc --noEmit to verify")

if __name__ == '__main__':
    main()
