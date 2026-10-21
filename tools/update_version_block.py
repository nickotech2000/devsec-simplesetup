#!/usr/bin/env python3
# Author : Nicko Satria Utama   Company: Agantra Inovatif OÜ (NextMantra)   Email: nicko@nextmantra.com   Version: 7.6.5
# Developer tool: puts tools/version-block.sh into the given .sh scripts (after the header comments and
# after "set -..." if present), so --version works first. Safe to run again (old block cut by its markers).
import re, sys, os
here = os.path.dirname(os.path.abspath(__file__))
block = open(os.path.join(here, 'version-block.sh'), encoding='utf-8').read().rstrip('\n') + '\n'
for f in sys.argv[1:]:
    t = open(f, encoding='utf-8', newline='').read()
    t = re.sub(r'# >>> PKI-VERSION-INFO.*?# <<< PKI-VERSION-INFO\n', '', t, flags=re.S)
    lines = t.split('\n'); i = 0
    while i < len(lines) and (lines[i].startswith('#') or lines[i].strip() == ''): i += 1
    if i < len(lines) and re.match(r'set\s+-', lines[i]): i += 1
    lines[i:i] = block.rstrip('\n').split('\n')
    open(f, 'w', encoding='utf-8', newline='').write('\n'.join(lines))
    print('ok:', f)
