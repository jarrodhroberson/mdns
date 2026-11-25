#!/usr/bin/env python3
"""Convert RFC-text documents to Markdown.

Usage:
  rfc_to_markdown.py                  # convert the default assembled document
  rfc_to_markdown.py FILE [FILE...]   # convert specific files -> FILE.md
  rfc_to_markdown.py DIR [DIR...]     # convert every *.txt in DIR -> .md alongside

rfc8766-with-references.txt -> rfc8766-with-references.md

Transforms:
- banner blocks (====/RFC n — title/====)  -> "# RFC n — title"
- page furniture (xml2rfc v2 footers, form feeds, running headers) -> removed
- numbered headings (1. / 11.1. / 9.1 / Appendix A.) -> ## / ### / #### by depth
- inlined-full-text markers -> "### RFC nnn — full text (inlined)"
- reference entries (   [TAG] ...) inside References subsections -> bullets
- body paragraphs kept verbatim (line wrapping preserved, so tables/figures
  survive; Markdown renders wrapped lines as one paragraph).
- ASCII diagrams (box-anchored blocks like +---+ / | | layouts) wrapped in ``` fences.
- --unwrap: join hard-wrapped paragraphs indented with 3 spaces onto one line,
  keeping the indent and single-spacing (page-seam fragments joined too).
"""
import pathlib
import re
import sys

DEFAULT_SRC = pathlib.Path("/home/jhr/git/mdns/rfc8766-with-references.txt")

BANNER = re.compile(r"^={76}$")
PAGE_FOOTER = re.compile(r"^\S.*\[Page \d+\]\s*$")
PAGE_ONLY = re.compile(r"^\s*\[Page \d+\]\s*$")
OLD_HEADER_DATE = re.compile(r"^\s*(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{4}\s*$")
OLD_HEADER_RFC = re.compile(r"^RFC \d{3,4}\s*$")
PAGE_HEADER = re.compile(r"^RFC \d+\s{2,}\S.*\s(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? \d{4}\s*$")
HEADING = re.compile(r"^(\d+(?:\.\d+)*)\.?\s{1,3}([A-Z0-9\"].{0,66}?)\s*$")
APPENDIX = re.compile(r"^Appendix ([A-Z])\.\s{1,3}(\S.{0,66}?)\s*$")
INLINE_START = re.compile(r"^\s*\[RFC(\d{3,4})\]\s*--\s*full text inlined:\s*$")
INLINE_END = re.compile(r"^\s*--\s*end of RFC \d+\s*--\s*$")
REF_ENTRY = re.compile(r"^\s{3,4}\[([A-Z][A-Z0-9-]*)\]\s+(.*)$")
TOC_LEADER = re.compile(r"^\s*\d+(?:\.\d+)*\.?\s+.*\.\s*\.{2,}\s*\d+\s*$")
FIG_ANCHOR = re.compile(r"[-=]{3,}|_{3,}|<\+>|^\s*\+(?:-\+)+\s*$|^\s*\+(?:-{1,3}\+){3,}")
DATA_GAP = re.compile(r"\S\s{3,}\S")


def is_data_block(block: list[str]) -> bool:
    """Fixed-width data/list block: uniformly indented lines."""
    if len(block) < 2:
        return False
    indents = [len(l) - len(l.lstrip()) for l in block]
    if min(indents) < 2 or max(indents) - min(indents) > 1:
        return False
    if any(l.lstrip().startswith(("#", "-", "*")) for l in block):
        return False
    gaps = sum(1 for l in block if DATA_GAP.search(l))
    # column-aligned data, OR blocks indented deep beyond body prose (>=8 cols)
    return gaps >= max(2, len(block) * 3 // 4) or min(indents) >= 8
FIG_STRUCT = re.compile(r"[|+/\\-]|^\s*[\dA-Fa-f][\dA-Fa-f ]*[\dA-Fa-f]\s*$")


def is_grid_line(line: str) -> bool:
    """A line made only of +, -, | and spaces (e.g. +--+--+--|) with >=3 corners."""
    s = line.strip()
    return len(s) >= 10 and set(s) <= set("+-|_") and (s.count("+") >= 3 or "_" in s)


def collect_files(args: list[str]) -> list[pathlib.Path]:
    """Expand CLI args: a directory contributes every .txt in it."""
    files: list[pathlib.Path] = []
    for a in args:
        p = pathlib.Path(a)
        if p.is_dir():
            files += sorted(x for x in p.glob("*.txt") if not x.name.endswith(".md"))
        else:
            files.append(p)
    return files


def is_figure(block: list[str]) -> bool:
    """A block is an ASCII diagram if box-anchored and structurally dense."""
    if len(block) < 3:
        return False
    anchors = sum(1 for l in block if FIG_ANCHOR.search(l) or is_grid_line(l))
    struct = sum(1 for l in block if FIG_STRUCT.search(l))
    return anchors >= 2 and struct >= max(3, len(block) // 2)


def fence_figures(text_lines: list[str]) -> list[str]:
    """Wrap contiguous non-blank blocks that look like diagrams in ``` fences."""
    res: list[str] = []
    i = 0
    while i < len(text_lines):
        if text_lines[i].strip():
            start = i
            while i < len(text_lines) and text_lines[i].strip():
                i += 1
            block = text_lines[start:i]
            if is_figure(block) or is_data_block(block):
                res += ["```"] + block + ["```"]
            else:
                res += block
        else:
            res.append(text_lines[i])
            i += 1
    return res


def unwrap_paragraphs(text_lines: list[str]) -> list[str]:
    """Join hard-wrapped paragraphs indented with exactly 3 spaces onto one
    line, keeping the indent. Fragments of the same paragraph separated by
    blank lines (page seams) are joined too, so paragraphs stay single
    spaced. Fenced blocks, bullets, and non-uniform blocks are untouched.
    """
    res: list[str] = []
    i = 0
    n = len(text_lines)

    def block_end(j: int) -> int:
        while j < n and text_lines[j].strip() and text_lines[j].strip() != "```":
            j += 1
        return j

    def para3(lines_: list[str]) -> bool:
        return all(len(l) - len(l.lstrip(" ")) == 3 for l in lines_)

    while i < n:
        line = text_lines[i]
        if not line.strip() or line.strip() == "```":
            res.append(line)
            i += 1
            continue
        start = i
        i = block_end(i)
        block = text_lines[start:i]
        if len(block) >= 2 and para3(block) and not block[0].lstrip().startswith(("- ", "* ")):
            joined = "   " + " ".join(l.strip() for l in block)
            # continue across page seams: next 3-space paragraph, if this ends mid-sentence
            while not joined.rstrip().endswith((".", "!", "?", ":", '"')):
                j = i
                while j < n and not text_lines[j].strip():
                    j += 1
                if j >= n or text_lines[j].strip() == "```":
                    break
                e = block_end(j)
                nxt = text_lines[j:e]
                if para3(nxt) and not nxt[0].lstrip().startswith(("- ", "* ")):
                    joined += " " + " ".join(l.strip() for l in nxt)
                    i = e
                else:
                    break
            res.append(joined)
        else:
            res += block
    return res


def convert(src: pathlib.Path, unwrap: bool = False) -> pathlib.Path:
    """Convert one RFC-text file to Markdown alongside it (same name, .md)."""
    lines = src.read_text(encoding="utf-8").replace("\ufeff", "").splitlines()

    # Standalone RFC files have no banner block: synthesize an H1 from the header.
    if not any(BANNER.match(l) for l in lines[:5]):
        mnum = None
        hdr_idx = None
        for idx, l in enumerate(lines[:10]):
            mnum = re.search(r"Request\s+F\w+\s+Comments:\s*(\d{3,4})", l, re.I)
            if mnum:
                hdr_idx = idx
                break
        if mnum:
            k = hdr_idx + 1
            while k < len(lines) and lines[k].strip():
                k += 1
            while k < len(lines) and not lines[k].strip():
                k += 1
            title: list[str] = []
            while k < len(lines) and lines[k].strip():
                title.append(lines[k].strip())
                k += 1
            lines.insert(0, f"# RFC {mnum.group(1)} — {' '.join(title)}")
            lines.insert(1, "")

    def heading_ok(idx: int) -> bool:
        """Heading must be surrounded by blank lines (or file edges)."""
        prev_blank = idx == 0 or not lines[idx - 1].strip()
        nxt_blank = idx + 1 >= len(lines) or not lines[idx + 1].strip()
        return prev_blank and nxt_blank

    out: list[str] = []
    i = 0
    in_refs = False  # inside a "References" subsection (normative/informative)

    while i < len(lines):
        ln = lines[i]

        if BANNER.match(ln):
            if i + 2 < len(lines) and BANNER.match(lines[i + 2]):
                out.append("# " + lines[i + 1].strip())
                out.append("")
                i += 3
            else:
                i += 1
            continue

        if not ln.strip() or ln.strip() == "\f":
            out.append("")
            i += 1
            continue
        if PAGE_FOOTER.match(ln) or PAGE_HEADER.match(ln) or PAGE_ONLY.match(ln) or OLD_HEADER_DATE.match(ln) or OLD_HEADER_RFC.match(ln):
            i += 1
            continue
        if TOC_LEADER.match(ln):
            i += 1
            continue
        if INLINE_END.match(ln):
            out.append("")
            i += 1
            continue

        m = INLINE_START.match(ln)
        if m:
            out += [f"### RFC {m.group(1)} — full text (inlined)", ""]
            i += 1
            continue

        m = APPENDIX.match(ln)
        if m and heading_ok(i):
            out += [f"## Appendix {m.group(1)} — {m.group(2)}", ""]
            i += 1
            continue

        m = HEADING.match(ln)
        if m and heading_ok(i):
            depth = m.group(1).count(".") + 1
            level = min(depth + 1, 5)
            out += ["#" * level + f" {m.group(1)}. {m.group(2)}", ""]
            in_refs = "References" in m.group(2)
            i += 1
            continue

        if in_refs and REF_ENTRY.match(ln):
            start = i
            i += 1
            while i < len(lines) and lines[i].strip() and not REF_ENTRY.match(lines[i]):
                i += 1
            entry = " ".join(s.strip() for s in lines[start:i])
            tag = REF_ENTRY.match(lines[start]).group(1)
            body = entry.split("]", 1)[1].strip()
            out.append(f"- **[{tag}]** {body}")
            continue

        out.append(ln.rstrip())
        i += 1

    fenced = fence_figures(out)
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(
        unwrap_paragraphs(fenced) if unwrap else fenced
    ).strip() + "\n")
    dst = src.with_suffix(".md")
    dst.write_text(text, encoding="utf-8")
    h1 = text.count("\n# ") + (1 if text.startswith("# ") else 0)
    print(f"wrote {dst} ({len(text)} chars)  H1={h1}  "
          f"H2={text.count(chr(10) + '## ')}  "
          f"H3={text.count(chr(10) + '### ')}")
    return dst


def main() -> None:
    unwrap = any(a == "--unwrap" for a in sys.argv[1:])
    args = [a for a in sys.argv[1:] if a != "--unwrap"]
    if args:
        files = collect_files(args)
    elif DEFAULT_SRC.exists():
        files = [DEFAULT_SRC]
    else:
        raise SystemExit(
            "usage: rfc_to_markdown.py [--unwrap] FILE|DIR [FILE|DIR...] "
            f"(default {DEFAULT_SRC} not present)"
        )
    for src in files:
        convert(src, unwrap=unwrap)


if __name__ == "__main__":
    main()
