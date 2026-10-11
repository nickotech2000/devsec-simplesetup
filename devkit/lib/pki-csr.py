#!/usr/bin/env python3
# ============================================================
# PKI Script - CSR specification checker (used by SignCsr.sh; the same rules as scripts/22_CsrSigning.ps1)
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# usage: pki-csr.py --openssl FILE --csr FILE --level DV|OV|EV --track Classic|Quantum --purpose P [--days N] [--no-color] [--emit FILE]
# Prints the report (red ERROR, yellow WARN, green OK, cyan INFO) and writes shell variables to --emit.
# Exit code: 0 follows the spec (maybe warnings), 2 does not follow the spec, 1 tool error.
import argparse, os, re, shlex, subprocess, sys, ipaddress

ATTRS = {
    'DV': ['CN'],
    'OV': ['C', 'ST', 'L', 'street', 'postalCode', 'O', 'OU', 'CN', 'name', 'emailAddress', 'telephoneNumber'],
}
ATTRS['EV'] = ATTRS['OV'] + ['businessCategory', 'serialNumber', 'jurisdictionC', 'jurisdictionST', 'jurisdictionL', 'organizationIdentifier']
BIZ = ['Private Organization', 'Government Entity', 'Business Entity', 'Non-Commercial Entity']
INTERNAL = ['internal', 'local', 'localhost', 'lan', 'corp', 'home', 'intranet', 'private', 'test', 'invalid', 'developer', 'api', 'ldap']
EXAMPLE = {'C': 'C=EE', 'O': 'O=Your Company OU', 'OU': 'OU=IT Department', 'ST': 'ST=Harju', 'L': 'L=Tallinn', 'serialNumber': 'serialNumber=17344131',
           'businessCategory': 'businessCategory=Private Organization', 'jurisdictionC': 'jurisdictionC=EE', 'jurisdictionST': 'jurisdictionST=Harju', 'postalCode': 'postalCode=15199'}
DNS_RE = re.compile(r'^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
MAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

F = []   # findings: (severity, code, field, message, fix)
def add(sev, code, field, msg, fix=''): F.append((sev, code, field, msg, fix))

def run(openssl, args):
    p = subprocess.run([openssl] + args, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def dns_ok(n):
    return bool(DNS_RE.match(n[2:] if n.startswith('*.') else n))

def read_csr(openssl, path):
    rc_v, _, _ = run(openssl, ['req', '-in', path, '-noout', '-verify'])
    rc, text, err = run(openssl, ['req', '-in', path, '-noout', '-text'])
    if 'Certificate Request' not in text:
        print('[ERROR] %s is not a PKCS#10 certificate request (PEM). OpenSSL says: %s' % (path, (err.splitlines() or [''])[0]), file=sys.stderr); sys.exit(1)
    _, sj, _ = run(openssl, ['req', '-in', path, '-noout', '-subject', '-nameopt', 'multiline,utf8,sname'])
    subj = []
    for line in sj.splitlines():
        m = re.match(r'^\s+(\S+)\s*=\s?(.*)$', line)
        if m: subj.append((m.group(1), m.group(2).rstrip()))
    alg = 'OTHER'; bits = 0; curve = ''; ml = 0
    m = re.search(r'Public Key Algorithm:\s*(.+)', text); algtext = m.group(1).strip() if m else ''
    if algtext == 'rsaEncryption':
        alg = 'RSA'; m = re.search(r'Public-Key: \((\d+) bit\)', text); bits = int(m.group(1)) if m else 0
    elif re.search(r'id-ecPublicKey|^EC$', algtext):
        alg = 'ECDSA'; m = re.search(r'ASN1 OID:\s*(\S+)', text); oid = m.group(1) if m else ''
        curve = {'prime256v1': 'P-256', 'secp256r1': 'P-256', 'secp384r1': 'P-384', 'secp521r1': 'P-521'}.get(oid, oid or 'unknown')
    elif re.match(r'(?i)^ML-?DSA-?(\d+)', algtext):
        alg = 'MLDSA'; ml = int(re.match(r'(?i)^ML-?DSA-?(\d+)', algtext).group(1))
    elif re.search(r'(?i)ED25519|ED448|DSA|RSASSA-PSS|X25519|SLH|ML-KEM', algtext):
        alg = algtext.upper()
    m = re.search(r'Signature Algorithm:\s*(\S+)', text); sig = m.group(1) if m else ''
    san = {'dns': [], 'ip': [], 'email': [], 'other': []}; reqext = []; ca = False
    m = re.search(r'Requested Extensions:(.*?)\n\s*Signature Algorithm:', text, re.S)
    if m:
        lines = m.group(1).split('\n')
        for i, ln in enumerate(lines):
            h = re.match(r'^\s+(X509v3 [^:]+|[A-Za-z0-9. ]+):\s*(critical)?\s*$', ln)
            if not h: continue
            name = h.group(1).strip(); reqext.append(name)
            val = lines[i + 1].strip() if i + 1 < len(lines) else ''
            if 'Subject Alternative Name' in name:
                for tk in re.split(r',\s*(?=(?:DNS|IP Address|email|URI|othername|DirName|Registered ID):)', val):
                    tk = tk.strip()
                    if tk.startswith('DNS:'): san['dns'].append(tk[4:])
                    elif tk.startswith('IP Address:'): san['ip'].append(tk[11:])
                    elif tk.startswith('email:'): san['email'].append(tk[6:])
                    elif tk: san['other'].append(tk)
            if 'Basic Constraints' in name and 'CA:TRUE' in val: ca = True
    return dict(verify=(rc_v == 0), subject=subj, alg=alg, bits=bits, curve=curve, ml=ml, algtext=algtext, sig=sig, san=san, reqext=reqext, ca=ca)

def keydesc(c):
    return {'RSA': 'RSA-%d' % c['bits'], 'ECDSA': 'ECDSA-%s' % c['curve'].replace('-', ''), 'MLDSA': 'ML-DSA-%d' % c['ml']}.get(c['alg'], c['algtext'])

def check_key(c, track, strong, ca_key=False):
    d = keydesc(c)
    why = 'a CA key' if ca_key else ('a code signing key' if strong else 'a leaf key')
    if not c['verify']:
        add('ERROR', 'KEY-SIGNATURE', 'signature', 'The signature of the request is not valid (the file was changed, or it is not signed with its own key).', 'Make the request again: openssl req -new -key <his.key> -out <his.csr>')
    else:
        add('OK', 'KEY-SIGNATURE', 'signature', 'The signature of the request is valid (proof that he holds the private key).')
    ok = False
    if c['alg'] == 'RSA':
        if track == 'Quantum': add('ERROR', 'KEY-QUANTUM-REQUIRED', 'public key', 'The key is %s, but Quadrant 3 / 4 (Quantum) issues ML-DSA keys only.' % d, 'Make an ML-DSA key (openssl genpkey -algorithm ML-DSA-65) or ask for the Classic track (no --quantum).')
        elif c['bits'] < 2048: add('ERROR', 'KEY-RSA-SMALL', 'public key', 'RSA %d bit is too small: the minimum is 2048.' % c['bits'], 'openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 (4096 for code signing and CA keys)')
        elif c['bits'] not in (2048, 3072, 4096, 8192): add('ERROR', 'KEY-RSA-ODD', 'public key', 'RSA %d bit is not a size of this PKI (2048, 3072, 4096 or 8192).' % c['bits'], 'Use rsa_keygen_bits:2048, 3072 or 4096.')
        elif ca_key and c['bits'] < 4096: add('ERROR', 'KEY-CA-RSA', 'public key', 'RSA %d bit is too small for %s: 4096 or more (equal strength: ECDSA P-384).' % (c['bits'], why), 'openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096')
        elif strong and c['bits'] < 4096: add('ERROR', 'KEY-CS-RSA', 'public key', 'RSA %d bit is too small for %s: this PKI needs 4096 or more (the generator raises it too).' % (c['bits'], why), 'openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096')
        else: ok = True
    elif c['alg'] == 'ECDSA':
        if track == 'Quantum': add('ERROR', 'KEY-QUANTUM-REQUIRED', 'public key', 'The key is %s, but Quadrant 3 / 4 (Quantum) issues ML-DSA keys only.' % d, 'Make an ML-DSA key (openssl genpkey -algorithm ML-DSA-65) or ask for the Classic track (no --quantum).')
        elif c['curve'] not in ('P-256', 'P-384', 'P-521'): add('ERROR', 'KEY-CURVE', 'public key', "The curve '%s' is not accepted: P-256, P-384 or P-521 only." % c['curve'], 'openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve')
        elif strong and c['curve'] == 'P-256': add('ERROR', 'KEY-CA-CURVE' if ca_key else 'KEY-CS-CURVE', 'public key', 'ECDSA P-256 is too weak for %s: P-384 or P-521.' % why, 'Use ec_paramgen_curve:P-384')
        else: ok = True
    elif c['alg'] == 'MLDSA':
        if track == 'Classic': add('ERROR', 'KEY-CLASSIC-REQUIRED', 'public key', 'The key is %s (quantum), but this is a Classic request (Quadrant 1 / 2: RSA or ECDSA).' % d, 'Ask for the Quantum track (--quantum) or send an RSA / ECDSA request.')
        elif c['ml'] not in (44, 65, 87): add('ERROR', 'KEY-MLDSA', 'public key', 'ML-DSA-%d is not a parameter set of this PKI (44, 65 or 87).' % c['ml'])
        elif strong and c['ml'] < 65: add('ERROR', 'KEY-CS-MLDSA', 'public key', 'ML-DSA-44 is too weak for %s: ML-DSA-65 or 87.' % why, 'openssl genpkey -algorithm ML-DSA-65')
        else: ok = True
    else:
        add('ERROR', 'KEY-ALG', 'public key', "The key type '%s' is not accepted (RSA, ECDSA P-256 / P-384 / P-521, ML-DSA)." % c['algtext'], 'Make a new key with openssl genpkey (RSA 2048+, EC P-256+, or ML-DSA).')
    if ok: add('OK', 'KEY-OK', 'public key', 'Key %s is accepted for %s on the %s track.' % (d, why, track))
    if c['alg'] != 'MLDSA' and re.search(r'(?i)md[245]|sha-?1(?!\d)|sha-?224|ripemd|whirlpool', c['sig']):
        add('ERROR', 'KEY-DIGEST', 'request signature', 'The request is signed with %s: SHA-256 or stronger is required.' % c['sig'], 'openssl req -new -sha256 (or -sha384) ...')
    elif c['sig']:
        add('OK', 'KEY-DIGEST', 'request signature', 'Request signature algorithm %s.' % c['sig'])

def check_subject(c, level, profile, codesign):
    pairs = c['subject']
    get = lambda k: [v for (n, v) in pairs if n == k]
    allowed = list(ATTRS[level])
    if codesign and level != 'DV':
        allowed = ['C', 'ST', 'L', 'O', 'OU', 'CN'] + (['businessCategory', 'serialNumber', 'jurisdictionC', 'jurisdictionST', 'jurisdictionL', 'organizationIdentifier', 'street', 'postalCode'] if level == 'EV' else [])
    if not pairs:
        add('ERROR', 'SUBJ-EMPTY', 'subject', 'The request has no subject.', 'Give the subject with -subj "/C=EE/O=.../CN=..." when you make the request.'); return
    seen = {}
    for n, _ in pairs: seen[n] = seen.get(n, 0) + 1
    for n, k in seen.items():
        if k > 1 and n != 'OU': add('ERROR', 'SUBJ-DUP-' + n, n, 'The attribute %s occurs %d times in the subject: once only.' % (n, k), 'Keep one %s.' % n)
    if level == 'DV':
        extra = sorted(set(n for n, _ in pairs if n != 'CN'), key=lambda x: [n for n, _ in pairs].index(x))
        if extra: add('WARN', 'SUBJ-DV-DROP', 'subject', 'A DV certificate carries the CN only: %s will NOT be in the certificate.' % ', '.join(extra), 'Ask for --ov or --ev if the organization must be in the certificate.')
    else:
        for a in dict.fromkeys(n for n, _ in pairs):
            if a not in allowed:
                if re.match(r'^\d', a): hint = 'an OID the PKI does not know'
                elif a in ('jurisdictionC', 'jurisdictionST', 'jurisdictionL', 'businessCategory', 'serialNumber', 'organizationIdentifier'): hint = 'it belongs to EV certificates only (this is %s)' % level
                else: hint = 'not in the subject of an %s%s certificate' % (level, ' code signing' if codesign else '')
                add('ERROR', 'SUBJ-ATTR-' + a, a, "The subject attribute '%s' is not allowed: %s. Allowed for %s: %s." % (a, hint, level, ', '.join(allowed)), 'Remove %s from the request subject.' % a)
    cn = get('CN')
    if not cn: add('ERROR', 'SUBJ-REQ-CN', 'CN', 'The subject has no CN (common name).', 'Add /CN=<name> to the subject.')
    elif len(cn[0]) > 64: add('ERROR', 'SUBJ-LEN-CN', 'CN', 'The CN is %d characters; the maximum is 64.' % len(cn[0]), 'Shorten the CN (put long names in O).')
    elif re.search(r'[/\\]', cn[0]): add('ERROR', 'SUBJ-CN-CHAR', 'CN', "The CN contains '/' or '\\': not accepted.", 'Use plain characters.')
    elif cn[0].strip() != cn[0]: add('WARN', 'SUBJ-CN-SPACE', 'CN', 'The CN has a space at the start or the end.', 'Remove it.')
    else: add('OK', 'SUBJ-CN', 'CN', 'CN = ' + cn[0])
    if level == 'DV': return
    req = []; rec = []
    if profile == 'Ca':
        req += ['C', 'O', 'OU']
        if level == 'EV': req += ['ST', 'L', 'serialNumber', 'businessCategory', 'jurisdictionC']; rec += ['jurisdictionST', 'postalCode']
        else: rec += ['ST', 'L']
    else:
        req += ['C', 'O']
        if level == 'EV' and not codesign: req += ['ST', 'L', 'serialNumber', 'businessCategory', 'jurisdictionC']; rec += ['jurisdictionST', 'postalCode']
        elif level == 'EV': req += ['ST', 'L', 'serialNumber', 'businessCategory', 'jurisdictionC']
        else: rec += ['ST', 'L']
    for a in req:
        v = get(a)
        if not v or not v[0].strip(): add('ERROR', 'SUBJ-REQ-' + a, a, 'The subject has no %s, required for %s%s%s.' % (a, 'a CA of level ' if profile == 'Ca' else '', level, ' code signing' if codesign else ''), 'Add /%s to the subject (the value is yours).' % EXAMPLE.get(a, a + '=...'))
    for a in rec:
        v = get(a)
        if not v or not v[0].strip(): add('WARN', 'SUBJ-REC-' + a, a, 'The subject has no %s (recommended for %s).' % (a, level), 'Add /%s (the value is yours).' % EXAMPLE.get(a, a + '=...'))
    for a in ('C', 'jurisdictionC'):
        v = get(a)
        if v and not re.match(r'^[A-Z]{2}$', v[0]): add('ERROR', 'SUBJ-FMT-' + a, a, "%s '%s' is not a 2-letter upper-case ISO 3166 country code." % (a, v[0]), 'Use e.g. %s=EE.' % a)
    bc = get('businessCategory')
    if bc and bc[0] not in BIZ: add('ERROR', 'SUBJ-FMT-businessCategory', 'businessCategory', "businessCategory '%s' is not one of: %s." % (bc[0], ', '.join(BIZ)), 'Use one of those four values exactly.')
    for a in ('O', 'OU', 'ST', 'L'):
        mx = 64 if a in ('O', 'OU') else 128
        for v in get(a):
            if len(v) > mx: add('ERROR', 'SUBJ-LEN-' + a, a, '%s is %d characters; the maximum is %d.' % (a, len(v), mx))
    if codesign:
        o = get('O')
        if o and cn and o[0] != cn[0]: add('WARN', 'SUBJ-CS-CN', 'CN', 'For a code signing certificate of this PKI the CN is the company name, equal to O.', 'Use CN = O.')
    for a in req + rec:
        if not any(f[2] == a for f in F) and get(a): add('OK', 'SUBJ-' + a, a, '%s = %s' % (a, get(a)[0]))

def check_names(c, level, purpose):
    web = purpose in ('ServerAuth', 'ServerClientAuth', 'ClientAuth')
    mail = purpose == 'EmailProtection'
    s = c['san']; dns = []; ip = []; em = []
    cn = next((v for n, v in c['subject'] if n == 'CN'), '')
    if not web and not mail:
        n = len(s['dns']) + len(s['ip']) + len(s['email']) + len(s['other'])
        if n: add('WARN', 'SAN-DROPPED', 'subjectAltName', 'A %s certificate carries no names: the %d name(s) of the request are NOT put in the certificate.' % (purpose, n), 'Nothing to do; or ask for a TLS / S/MIME purpose if names are needed.')
        return dns, ip, em
    if s['other']: add('WARN', 'SAN-OTHER', 'subjectAltName', 'Name types of the request that this PKI does not issue are dropped: %s (DNS, IP and e-mail only).' % '; '.join(s['other']))
    if web: dns = list(s['dns']); ip = list(s['ip'])
    if mail: em = list(s['email'])
    if web and s['email']: add('WARN', 'SAN-DROPPED', 'subjectAltName', 'E-mail name(s) %s are not put in a TLS certificate.' % ', '.join(s['email']), 'Ask for --purpose EmailProtection for an S/MIME certificate.')
    if mail and (s['dns'] or s['ip']): add('WARN', 'SAN-DROPPED', 'subjectAltName', 'DNS and IP names are not put in an S/MIME certificate (e-mail names only).')
    if web and not dns and not ip:
        if cn and dns_ok(cn) and not re.search(r'\s', cn):
            dns.append(cn); add('WARN', 'SAN-DERIVED', 'subjectAltName', "The request has no subjectAltName; the CN '%s' is used as the DNS name (browsers and TLS libraries only look at the SAN)." % cn, 'Put the names in the request: -addext "subjectAltName=DNS:www.example.com,DNS:example.com"')
        else: add('ERROR', 'SAN-NONE', 'subjectAltName', 'A TLS certificate needs at least one DNS name or IP address, and the request has none (the CN is not a host name either).', 'Make the request with -addext "subjectAltName=DNS:www.example.com".')
    if mail and not em:
        if cn and MAIL_RE.match(cn): em.append(cn); add('WARN', 'SAN-DERIVED', 'subjectAltName', "No e-mail name in the request; the CN '%s' is used." % cn, 'Put it in the request: -addext "subjectAltName=email:name@example.com"')
        else: add('ERROR', 'SAN-NONE', 'subjectAltName', 'An S/MIME certificate needs at least one e-mail address (SAN email:), and the request has none.', 'Make the request with -addext "subjectAltName=email:name@example.com".')
    for d in dns:
        if not dns_ok(d): add('ERROR', 'SAN-DNS-INVALID', 'DNS', "'%s' is not a valid DNS name." % d, 'Letters, digits, hyphens and dots; a wildcard only as *.name.'); continue
        if level == 'EV':
            if '*' in d: add('ERROR', 'SAN-EV-WILDCARD', 'DNS', "'%s': an EV certificate may not contain a wildcard name." % d, "Name every host: remove '%s' or ask for --ov." % d)
            labels = d.rstrip('.').split('.')
            if len(labels) < 2 or labels[-1].lower() in INTERNAL: add('ERROR', 'SAN-EV-INTERNAL', 'DNS', "'%s' is an internal name (no public domain): not allowed in an EV certificate." % d, 'Use a public domain name, or ask for --ov / --dv.')
        elif d.startswith('*.'): add('WARN', 'SAN-WILDCARD', 'DNS', "Wildcard name '%s': allowed in this private PKI (a public CA would refuse it for EV)." % d)
    for a in ip:
        try: ipaddress.ip_address(a)
        except ValueError: add('ERROR', 'SAN-IP-INVALID', 'IP', "'%s' is not a valid IP address." % a); continue
        if level == 'EV': add('ERROR', 'SAN-EV-IP', 'IP', "IP address '%s': an EV certificate may not contain an IP address." % a, 'Use a DNS name, or ask for --ov / --dv.')
    for m in em:
        if not MAIL_RE.match(m): add('ERROR', 'SAN-EMAIL-INVALID', 'email', "'%s' is not a valid e-mail address." % m)
        elif level == 'EV' and not mail: add('ERROR', 'SAN-EV-EMAIL', 'email', 'An EV TLS certificate may not contain an e-mail address.')
    if level == 'DV' and web and cn and (dns or ip) and not any(d.lower() == cn.lower() for d in dns) and cn not in ip:
        add('WARN', 'SUBJ-CN-NOT-SAN', 'CN', "The CN '%s' is not one of the names in the SAN (%s); a DV certificate is identified by its names." % (cn, ', '.join(dns + ip)), 'Make the CN the first DNS name.')
    names = dns + ip + em
    if names and not any(f[0] == 'ERROR' and f[1].startswith('SAN-') for f in F): add('OK', 'SAN-OK', 'subjectAltName', 'Names accepted: ' + ', '.join(names))
    return dns, ip, em

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--openssl', required=True); ap.add_argument('--csr', required=True)
    ap.add_argument('--level', default='DV'); ap.add_argument('--track', default='Classic'); ap.add_argument('--purpose', default='ServerAuth')
    ap.add_argument('--profile', default='Leaf'); ap.add_argument('--days', type=int, default=0)
    ap.add_argument('--no-color', action='store_true'); ap.add_argument('--emit'); ap.add_argument('--hide-ok', action='store_true')
    a = ap.parse_args()
    if not os.path.isfile(a.csr): print('[ERROR] CSR not found: ' + a.csr, file=sys.stderr); return 1
    c = read_csr(a.openssl, a.csr)
    codesign = a.purpose == 'CodeSigning'
    print('')
    print('REQUEST  ' + os.path.abspath(a.csr))
    print('  subject : ' + ', '.join('%s=%s' % p for p in c['subject']))
    print('  key     : %s    signature: %s' % (keydesc(c), c['sig']))
    print('  asked   : %s, %s track, purpose %s' % (a.level, a.track, a.purpose))
    print('')
    check_key(c, a.track, codesign)
    check_subject(c, a.level, a.profile, codesign)
    dns, ip, em = check_names(c, a.level, a.purpose)
    if c['ca']: add('ERROR', 'EXT-CA', 'basicConstraints', 'The request asks for CA:TRUE. A leaf request may not be a CA.', 'A CA of another department goes through SignExternalCa.ps1 (the original PKI owner signs it with a Quadrant Root).')
    ign = [x for x in c['reqext'] if re.search(r'Key Usage|Extended Key|Policies|Authority|Subject Key|CRL|Authority Information|Name Constraints', x)]
    if ign: add('INFO', 'EXT-IGNORED', 'extensions', 'The request asks for: %s. This PKI decides key usage, extended key usage, policies and revocation URLs itself; they are ignored.' % ', '.join(ign))
    if a.level == 'EV' and a.days > 397: add('ERROR', 'VAL-EV', 'validity', 'An EV certificate may not be valid longer than 397 days (asked %d).' % a.days, 'Use --days 397 or less.')
    col = {'ERROR': '31', 'WARN': '33', 'OK': '32', 'INFO': '36'}; tag = {'ERROR': '[ERROR]', 'WARN': '[WARN] ', 'OK': '[ OK ]', 'INFO': '[INFO]'}
    color = sys.stdout.isatty() and not a.no_color and not os.environ.get('NO_COLOR')
    def say(t, k):
        print('\033[%sm%s\033[0m' % (col[k], t) if color else t)
    for sev, code, field, msg, fix in F:
        if a.hide_ok and sev == 'OK': continue
        say('  %s %-22s %s%s' % (tag[sev], field, msg, ('  [%s]' % code) if sev in ('ERROR', 'WARN') else ''), sev)
        if fix and sev in ('ERROR', 'WARN'):
            print(('\033[90m' if color else '') + '           %s  fix: %s' % (' ' * 22, fix) + ('\033[0m' if color else ''))
    e = sum(1 for f in F if f[0] == 'ERROR'); w = sum(1 for f in F if f[0] == 'WARN')
    s = '  Result: %d error(s), %d warning(s).' % (e, w)
    if e: say(s + ' The request does NOT follow the specification of this PKI: nothing was signed.', 'ERROR')
    elif w: say(s + ' The request can be signed; read the warnings.', 'WARN')
    else: say(s + ' The request follows the specification.', 'OK')
    if a.emit:
        cn = next((v for n, v in c['subject'] if n == 'CN'), '')
        fam = {'RSA': 'rsa', 'ECDSA': 'ecdsa'}.get(c['alg'], 'pqc')
        subj = ','.join('%s=%s' % p for p in c['subject'])
        with open(a.emit, 'w') as fh:
            for k, v in (('CSR_CN', cn), ('CSR_KEYDESC', keydesc(c)), ('CSR_FAMILY', fam), ('SAN_DNS', ' '.join(dns)), ('SAN_IP', ' '.join(ip)), ('SAN_EMAIL', ' '.join(em)),
                         ('CSR_SUBJECT', subj), ('CSR_ERRORS', str(e)), ('CSR_WARNINGS', str(w)),
                         ('CSR_WARN_TEXT', ' | '.join(f[3] for f in F if f[0] == 'WARN'))):
                fh.write('%s=%s\n' % (k, shlex.quote(v)))
    return 2 if e else 0

if __name__ == '__main__':
    sys.exit(main())
