#!/usr/bin/env python3
"""Reflow text documents to <= WIDTH columns. Only lines longer than WIDTH (and the lines that continue them) are touched.
Two shapes: prose / bullets (hanging indent) and two-column rows (label ...... text, hanging at the text column)."""
import re, sys, textwrap
W = 100
BUL = re.compile(r'^(\s*)([*•\-+]|\d+[.)]|[A-Za-z][.)])(\s+)(\S.*)$')
KV = re.compile(r'^(\s*)(\S.*?\S|\S)(\s{3,})(\S.*)$')
RULE = re.compile(r'^\s*([=\-_])\1{4,}\s*$')
BOX = re.compile(r'[─-╿←-⇿■-◿]|^\s*[+|].*[+|]\s*$')
def wrap(text, first, hang):
    return textwrap.wrap(text, width=W, initial_indent=first, subsequent_indent=hang,
                         break_long_words=False, break_on_hyphens=False) or [first.rstrip()]
def indent(l): return len(l) - len(l.lstrip(' '))
def process(lines):
    out = []; i = 0; n = len(lines); left = 0
    while i < n:
        l = lines[i]
        if len(l) <= W or not l.strip() or RULE.match(l) or BOX.search(l):
            if len(l) > W: left += 1
            out.append(l); i += 1; continue
        # a long line: find the item it belongs to (it may continue on following lines)
        lab = re.match(r'^(\s*[A-Za-z][A-Za-z ]{0,14}\s*: +)(\S.*)$', l)
        if lab and len(lab.group(1)) <= 24:
            col = len(lab.group(1)); txt = re.sub(r' {2,}', '  ', lab.group(2)); j = i + 1
            while j < n and lines[j].strip() and indent(lines[j]) == col and not RULE.match(lines[j]):
                txt += '  ' + lines[j].strip(); j += 1
            w = wrap(txt, ' ' * col, ' ' * col); w[0] = lab.group(1) + w[0][col:]
            out += w; i = j; continue
        m = BUL.match(l); k = KV.match(l)
        gaps = len(re.findall(r'\S {3,}\S', l))
        if k and gaps == 1 and (len(k.group(1)) + len(k.group(2)) + len(k.group(3))) <= 72 and not m and len(k.group(4).split()) >= 8 and not re.match(r'^\d+\s{1,3}[A-Z]', k.group(4)) and not re.match(r'^\d+\s{1,3}[A-Z]', k.group(2)):
            col = len(k.group(1)) + len(k.group(2)) + len(k.group(3))
            txt = k.group(4); j = i + 1
            while j < n and lines[j].strip() and indent(lines[j]) == col and not RULE.match(lines[j]) and not KV.match(lines[j][col:] or 'x'):
                txt += ' ' + lines[j].strip(); j += 1
            first = k.group(1) + k.group(2) + k.group(3)
            w = wrap(txt, ' ' * col, ' ' * col); w[0] = first + w[0][col:]
            out += w; i = j; continue
        if m:
            hang = len(m.group(1)) + len(m.group(2)) + len(m.group(3)); txt = m.group(4); j = i + 1
            while j < n and lines[j].strip() and indent(lines[j]) == hang and not BUL.match(lines[j]) and not RULE.match(lines[j]) and not re.search(r'\S {3,}\S', lines[j]):
                txt += ' ' + lines[j].strip(); j += 1
            first = m.group(1) + m.group(2) + m.group(3)
            if re.search(r'\S {3,}\S', txt):  # looks like a table row: leave
                out.append(l); left += 1; i += 1; continue
            out += wrap(txt, first, ' ' * hang); i = j; continue
        lastgap = list(re.finditer(r'\S( {3,})(?=\S)', l))
        if len(lastgap) >= 2:
            g = lastgap[-1]; col = g.end(); txt = l[col:]
            if col <= 72 and len(txt.split()) >= 6 and not re.match(r'^\d+\s{1,3}[A-Z]', txt):
                w = wrap(txt, ' ' * col, ' ' * col); w[0] = l[:col] + w[0][col:]
                out += w; i += 1; continue
        # plain prose line
        ind = indent(l)
        if re.search(r'\S {2,}\S', l.strip()) or re.match(r'^\s*(\.\\|\./|PS>|\$ |pwsh |bash |sudo |openssl |curl )', l):
            out.append(l); left += 1; i += 1; continue
        txt = l.strip(); j = i + 1
        while j < n and lines[j].strip() and (ind - 1) <= indent(lines[j]) <= (ind + 3) and not BUL.match(lines[j]) and not RULE.match(lines[j]) and not re.search(r'\S {3,}\S', lines[j].strip()) and len(lines[j-1]) >= 60:
            txt += ' ' + lines[j].strip(); j += 1
        out += wrap(txt, ' ' * ind, ' ' * ind); i = j
    return out, left
if __name__ == '__main__':
    tot = 0
    for p in sys.argv[1:]:
        src = open(p, encoding='utf-8').read().split('\n')
        out, left = process(src)
        open(p, 'w', encoding='utf-8').write('\n'.join(out))
        rest = sum(1 for x in out if len(x) > W)
        print(f'{p}: {len(src)} -> {len(out)} lines, still >{W}: {rest}')
