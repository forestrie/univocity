#!/usr/bin/env python3
"""
Wrap comments in Solidity files per .cursorrules:
- Soft wrap at 79 chars (prefer punctuation).
- Hard wrap at 100 chars (first word beyond 100 goes on next line).
- URLs exempt if they start on or before column 40.
- @param, @return, @notice, @dev: continuation lines indented 4 chars relative to the introducing line.
"""
import re
import sys
from pathlib import Path

SOFT = 79
HARD = 100
URL_EXEMPT_COL = 40

# URL pattern; we only care where it starts
URL_START = re.compile(r'https?://[^\s]+')
# NatSpec tag: do not break between @ and end of tag name (e.g. @custom:throws)
NATSPEC_TAG = re.compile(r'@\w+(?::\w+)?')


def url_starts_at_or_before_40(line: str) -> bool:
    """True if line contains a URL that starts at column <= 40 (1-based)."""
    m = URL_START.search(line)
    if not m:
        return False
    return m.start() + 1 <= URL_EXEMPT_COL


def min_break_after_natspec_tag(content: str) -> int:
    """Do not break inside a NatSpec tag (e.g. @custom:throws). Return min break offset."""
    content_stripped = content.lstrip()
    if not content_stripped.startswith('@'):
        return 0
    m = NATSPEC_TAG.match(content_stripped)
    if not m:
        return 0
    # Return position in original content: after the tag and any immediate space
    tag_end = m.end()
    # Include one trailing space so we don't break " @custom:throws " before "throws"
    after = content_stripped[tag_end:]
    if after.startswith(' '):
        tag_end += 1
    return len(content) - len(content_stripped) + tag_end


def find_soft_break(text: str, max_len: int, min_break: int = 0) -> int:
    """Prefer last punctuation (.,;:) at or before max_len, else last space. Never break before min_break."""
    if len(text) <= max_len:
        return len(text)
    search = text[: max_len + 1]
    for p in ('.', ',', ';', ':', ' '):
        idx = search.rfind(p)
        if idx > 0 and idx >= min_break:
            return idx + 1
    return max(max_len, min_break)


def find_hard_break(text: str, max_len: int, min_break: int = 0) -> int:
    """Break so the first word extending beyond max_len starts the next line. Never break before min_break."""
    if len(text) <= max_len:
        return len(text)
    before = text[: max_len + 1]
    last_space = before.rfind(' ')
    if last_space > 0 and last_space >= min_break:
        return last_space
    return max(max_len, min_break)


PARAM_CONTINUATION_INDENT = "    "  # 4 spaces for @param / @return continuation lines


def wrap_comment_content(content: str, prefix: str, param_continuation: bool = False) -> list[str]:
    """Wrap content to SOFT/HARD; return list of lines (each with prefix applied).
    When param_continuation is True (@param / @return), continuation lines use prefix + 4 spaces.
    """
    lines_out = []
    remaining = content.strip()
    prefix_len = len(prefix)

    while remaining:
        if url_starts_at_or_before_40(prefix + remaining):
            lines_out.append(prefix + remaining)
            break

        if len(remaining) + prefix_len <= HARD and len(remaining) + prefix_len <= SOFT:
            lines_out.append(prefix + remaining)
            break

        min_break = min_break_after_natspec_tag(remaining)
        if len(remaining) + prefix_len > HARD:
            max_content = HARD - prefix_len
            break_at = find_hard_break(remaining, max_content, min_break)
        else:
            max_content = SOFT - prefix_len
            break_at = find_soft_break(remaining, max_content, min_break)

        first_line = remaining[:break_at].rstrip()
        lines_out.append(prefix + first_line)
        remaining = remaining[break_at:].lstrip()
        if remaining and not prefix.strip().startswith('*'):
            if param_continuation:
                prefix = prefix.rstrip() + PARAM_CONTINUATION_INDENT
            else:
                prefix = prefix.rstrip() + ' ' if prefix.rstrip() else prefix

    return lines_out


def _fix_param_continuation_indent(lines: list[str]) -> list[str]:
    """Replace 1-space with 4-space after /// for lines that continue @param/@return/@notice/@dev."""
    # Previous line starts a tag block: /// @param|@return|@notice|@dev ...
    tag_start_re = re.compile(r'^(\s*///)\s+(@param|@return|@notice|@dev)\s+')
    # Previous line is already a continuation (4+ spaces after ///)
    continuation_re = re.compile(r'^(\s*///) {4,}\S')
    # Current line: /// + 1–3 spaces + content (needs fix to 4 spaces)
    curr_under_re = re.compile(r'^(\s*///) {1,3}(\S.*)$')
    # Current line: /// + 5+ spaces (over-indented; normalize to 4)
    curr_over_re = re.compile(r'^(\s*///) {5,}(\S.*)$')

    out = []
    for i, line in enumerate(lines):
        if i > 0 and line.endswith('\n'):
            prev = out[-1].rstrip('\n')
            stripped_line = line.rstrip('\n')
            prev_is_tag_start = tag_start_re.match(prev) is not None
            prev_is_continuation = continuation_re.match(prev) is not None
            in_tag_block = prev_is_tag_start or prev_is_continuation

            curr_under = curr_under_re.match(stripped_line)
            curr_over = curr_over_re.match(stripped_line) if in_tag_block else None
            if curr_under and in_tag_block and not curr_under.group(2).strip().startswith('@'):
                line = curr_under.group(1) + PARAM_CONTINUATION_INDENT + curr_under.group(2) + '\n'
            elif curr_over and not curr_over.group(2).strip().startswith('@'):
                line = curr_over.group(1) + PARAM_CONTINUATION_INDENT + curr_over.group(2) + '\n'
        out.append(line)
    return out


def process_line(line: str) -> list[str] | None:
    """
    If line is a comment, return wrapped lines; else return None (leave line as-is).
    Handles: //, ///, and block comment lines ( * or * ).
    """
    stripped = line.rstrip('\n')
    if not stripped.strip():
        return None

    # Line comment (// or ///)
    m = re.match(r'^(\s*)(///?\s*)(.*)$', stripped)
    if m:
        indent, slashes, content = m.groups()
        prefix = indent + slashes
        if not content.strip():
            return [stripped + '\n']
        content_stripped = content.strip()
        tag_continuation = (
            content_stripped.startswith('@param ') or content_stripped.startswith('@param\t') or
            content_stripped.startswith('@return ') or content_stripped.startswith('@return\t') or
            content_stripped.startswith('@notice ') or content_stripped.startswith('@notice\t') or
            content_stripped.startswith('@dev ') or content_stripped.startswith('@dev\t')
        )
        wrapped = wrap_comment_content(content, prefix, param_continuation=tag_continuation)
        return [w + '\n' for w in wrapped]

    # Block comment continuation ( * or  *)
    m = re.match(r'^(\s*\*\s?)(.*)$', stripped)
    if m and stripped.strip().startswith('*'):
        prefix = m.group(1)
        content = m.group(2)
        if content.strip() == '' or content.strip() == '*/':
            return [stripped + '\n']
        wrapped = wrap_comment_content(content, prefix)
        return [w + '\n' for w in wrapped]

    return None


def process_file(path: Path) -> bool:
    """Process one file; return True if changed."""
    text = path.read_text(encoding='utf-8')
    lines = text.splitlines(keepends=True)
    out = []
    in_block = False
    block_indent = ''

    i = 0
    while i < len(lines):
        line = lines[i]
        if '/*' in line and '*/' not in line:
            in_block = True
            # Start of block: output until we have the opening
            start_idx = line.find('/*')
            out.append(line[: start_idx + 2])
            rest = line[start_idx + 2:].lstrip()
            if rest.startswith('*/'):
                out.append(' ' + rest)
                in_block = False
            elif rest:
                block_indent = line[: len(line) - len(line.lstrip())] + ' * '
                wrapped = wrap_comment_content(rest.rstrip(), block_indent)
                for w in wrapped:
                    out.append(w + '\n')
            i += 1
            continue
        if in_block:
            if '*/' in line:
                out.append(line)
                in_block = False
                i += 1
                continue
            stripped = line.strip()
            if stripped.startswith('*'):
                content = stripped.lstrip('*').strip()
                if not content or content == '/':
                    out.append(line)
                else:
                    prefix = line[: len(line) - len(line.lstrip())] + '* '
                    wrapped = wrap_comment_content(content, prefix)
                    for w in wrapped:
                        out.append(w + '\n')
            else:
                out.append(line)
            i += 1
            continue

        result = process_line(line)
        if result is not None:
            out.extend(result)
        else:
            out.append(line)
        i += 1

    # Post-pass: fix continuations of @param/@return that were already split (1 space -> 4 space)
    out = _fix_param_continuation_indent(out)

    new_text = ''.join(out)
    if new_text != text:
        path.write_text(new_text, encoding='utf-8')
        return True
    return False


def main():
    root = Path(__file__).resolve().parent.parent
    dirs = [root / 'src', root / 'script', root / 'test']
    changed = []
    for d in dirs:
        if not d.is_dir():
            continue
        for path in sorted(d.rglob('*.sol')):
            if process_file(path):
                changed.append(str(path.relative_to(root)))
    if changed:
        print('Wrapped comments in:', ', '.join(changed))
    else:
        print('No files needed changes.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
