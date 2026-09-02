#!/usr/bin/env python3
"""Convert SAML V2.0 PDF to per-chapter markdown files."""
import os, re

RAW = "/tmp/saml_raw.txt"
CHAPTERS = [
    (1, "Introduction"),
    (2, "SAML Assertions"),  
    (3, "SAML Protocols"),
    (4, "SAML Versioning"),
    (5, "SAML and XML Signature Syntax and Processing"),
    (6, "SAML and XML Encryption Syntax and Processing"),
    (7, "SAML Extensibility"),
    (8, "SAML-Defined Identifiers"),
    (9, "References"),
]

def find_chapter(raw_text, ch_num, title):
    """Find chapter heading line number (1-indexed) in raw text."""
    lines = raw_text.split('\n')
    for i, line in enumerate(lines):
        clean = re.sub(r'[\s\x0c]+', ' ', line).strip()
        if '.' in clean:
            continue  # Skip TOC dotted entries
        if re.match(r'^' + str(ch_num) + r'\s+' + re.escape(title), clean):
            return i + 1  # 1-indexed line number
    return None

def main():
    base = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(base, "saml-chapters")
    
    if not os.path.exists(RAW):
        import subprocess
        pdf = os.path.join(base, "saml-core-2-0-os.pdf")
        subprocess.run(["pdftotext", pdf, RAW], check=True)
    
    raw_text = open(RAW).read()
    lines = raw_text.split('\n')
    
    os.makedirs(out_dir, exist_ok=True)
    
    # Find all chapter starts
    starts = {}
    for ch_num, title in CHAPTERS:
        line_no = find_chapter(raw_text, ch_num, title)
        if line_no:
            starts[ch_num] = (line_no - 1, title)  # Convert to 0-indexed
            print(f"Chapter {ch_num}: '{title}' at raw line {line_no}")
        else:
            print(f"WARNING: Chapter {ch_num} not found!")
    
    # Sort by chapter number
    sorted_chs = sorted(starts.items())
    
    for idx, (ch_num, (start_line, chap_title)) in enumerate(sorted_chs):
        # End of this chapter = start of next
        next_line = starts.get(ch_num + 1, (len(lines), ""))[1] if ch_num < 9 else len(lines)
        
        # Actually get the actual line number from sorted list
        end_line_idx = sorted_chs[idx+1][1][0] if idx + 1 < len(sorted_chs) else len(lines)
        title_for_md = f"{ch_num} {chap_title.strip()}"
        
        print(f"\n[Writing ch{ch_num}] => lines {start_line+1} to {end_line_idx}")
        
        # Build markdown output
        md = [f"# Chapter {title_for_md}\n", ""]
        para = []
        
        for i in range(start_line + 1, end_line_idx):
            s = re.sub(r'[\s\x0c]+', ' ', lines[i]).strip()
            
            if not s:
                if para:
                    md.append(' '.join(para))
                    md.append("")
                    para = []
            elif re.match(r'^\d+$', s) or '15 March' in s or ('Page ' in s and '/' in s):
                # Skip header noise - flush current paragraph
                if para:
                    md.append(' '.join(para))
                    md.append("")
                    para = []
            else:
                # Clean content line (remove dotted leaders)
                s_clean = re.sub(r'\.{3,}', '', s).strip()
                if s_clean and len(s_clean) > 2:
                    para.append(s_clean)
        
        if para:
            md.append(' '.join(para))
        md.append("")
        
        output = '\n'.join(md).strip() + '\n'
        
        # Filename
        safe = re.sub(r'[^a-z0-9]+', '_', title_for_md.lower())[:50]
        fn = f"ch{ch_num}_{safe}.md"
        
        with open(os.path.join(out_dir, fn), 'w', encoding='utf-8') as f:
            f.write(output)
        
        print(f"  -> {fn} ({end_line_idx - start_line - 1} lines)")
    
    # List output files
    print(f"\n{'='*60}")
    for f in sorted(os.listdir(out_dir)):
        fp = os.path.join(out_dir, f)
        if os.path.isfile(fp):
            size = os.path.getsize(fp)
            print(f"  {f}: {size:>10,} bytes")
    
    print(f"\nDone! {len(sorted_chs)} chapters in {out_dir}")

if __name__ == '__main__':
    main()
