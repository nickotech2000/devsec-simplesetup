#!/usr/bin/env python3
# PKI Script - DevKit helper: reads the persons JSON file of GeneratePersonLeafCertificate.sh / GenerateOffice365LeafCertificate.sh
# Author : Nicko Satria Utama  <nicko@nextmantra.com>   Company: Agantra Inovatif OU (NextMantra)
# Python 3 standard library only. Prints one line per person; fields separated by the control character 0x1F:
#   OK|SKIP|ERR, label, folder, serialNumber, given, surname, cn, country, email, dns(space list), nocrl, noocsp,
#   level, quadrant, days, keytype, keybits, curve, password
import json, os, re, sys, unicodedata

SEP = "\x1f"
ALIASES = {
    'idcode': 'IdCode', 'id': 'IdCode', 'idnumber': 'IdCode', 'nationalid': 'IdCode', 'personalcode': 'IdCode', 'personalnumber': 'IdCode',
    'isikukood': 'IdCode', 'nik': 'IdCode', 'passport': 'IdCode', 'passportnumber': 'IdCode', 'licence': 'IdCode', 'license': 'IdCode',
    'drivinglicence': 'IdCode', 'driverlicense': 'IdCode', 'documentnumber': 'IdCode',
    'givenname': 'GivenName', 'given': 'GivenName', 'firstname': 'GivenName', 'forename': 'GivenName', 'gn': 'GivenName', 'g': 'GivenName',
    'surname': 'Surname', 'lastname': 'Surname', 'familyname': 'Surname', 'sn': 'Surname',
    'email': 'Email', 'emailaddress': 'Email', 'mail': 'Email', 'rfc822': 'Email', 'rfc822name': 'Email',
    'country': 'Country', 'c': 'Country', 'idtype': 'IdType', 'type': 'IdType',
    'days': 'Days', 'validity': 'Days', 'validitydays': 'Days', 'password': 'Password', 'pfxpassword': 'Password',
    'level': 'Level', 'quadrant': 'Quadrant', 'keytype': 'KeyType', 'keybits': 'KeyBits', 'curve': 'Curve', 'commonname': 'CommonName', 'cn': 'CommonName',
    'serialnumber': 'SerialNumber', 'serial': 'SerialNumber', 'name': 'Name', 'foldername': 'Name', 'policy': 'Policy',
    'isgenerate': 'IsGenerate', 'generate': 'IsGenerate', 'enabled': 'IsGenerate', 'dnsfromemail': 'DnsFromEmail',
    'nocrl': 'NoCrl', 'noocsp': 'NoOcsp', 'norevocationinfo': 'NoRevocationInfo', 'norevocation': 'NoRevocationInfo',
}

def env(name, default=''):
    v = os.environ.get(name)
    return v if v not in (None, '') else default

def to_bool(v, default):
    if v is None or v == '': return default
    if isinstance(v, bool): return v
    s = str(v).strip().lower()
    if s in ('true', 'yes', 'y', '1', 'on'): return True
    if s in ('false', 'no', 'n', '0', 'off'): return False
    raise ValueError("'%s' is not true or false" % v)

def estonian_ok(code):
    if not re.fullmatch(r'[1-8]\d{10}', code): return False
    d = [int(x) for x in code]
    w1 = [1,2,3,4,5,6,7,8,9,1]; w2 = [3,4,5,6,7,8,9,1,2,3]
    r = sum(a*b for a, b in zip(d[:10], w1)) % 11
    if r == 10:
        r = sum(a*b for a, b in zip(d[:10], w2)) % 11
        if r == 10: r = 0
    return r == d[10]

def fs_name(s):
    s = unicodedata.normalize('NFD', s)
    s = ''.join(ch for ch in s if unicodedata.category(ch) != 'Mn')
    for a, b in (('ß','ss'),('ø','o'),('Ø','O'),('æ','ae'),('Æ','AE'),('đ','d'),('ł','l'),('Ł','L')): s = s.replace(a, b)
    return re.sub(r'[^A-Za-z0-9._-]+', '-', s).strip('-.')

def load(path):
    if not path.lower().endswith('.json'):
        raise ValueError('the person file must be a JSON file (.json); other formats such as CSV are not accepted: %s' % path)
    with open(path, 'r', encoding='utf-8-sig') as f:
        try: j = json.load(f)
        except Exception as e: raise ValueError('the person file is not valid JSON (%s): %s' % (path, e))
    items = j if isinstance(j, list) else (j['persons'] if isinstance(j, dict) and 'persons' in j else [j])
    out = []
    for n, it in enumerate(items, 1):
        rec = {'_Line': n}
        for k, v in it.items():
            key = re.sub(r'[\s_\-.]', '', str(k)).lower()
            if key == '' or str(k).startswith('_'): continue
            if key not in ALIASES: raise ValueError('Line %d: unknown column "%s"' % (n, k))
            if v is None: continue
            if isinstance(v, str):
                v = v.strip()
                if v == '': continue
            rec[ALIASES[key]] = v
        out.append(rec)
    return out

def main():
    a = sys.argv[1:]
    if len(a) < 2: print('usage: pki-persons.py FILE person|office365 [--opt value]...', file=sys.stderr); return 2
    path, profile = a[0], a[1]
    opt = {}
    i = 2
    while i < len(a):
        if a[i].startswith('--'):
            k = a[i][2:]
            if k in ('check-estonian-id', 'no-dns-from-email', 'dns-from-email'): opt[k] = True; i += 1
            else: opt[k] = a[i+1]; i += 2
        else: i += 1
    P = 'PERSON_' if profile == 'person' else 'OFFICE_'
    d = {
        'Days': int(env(P+'DAYS', '730')), 'Level': env(P+'LEVEL', 'OV'), 'Country': env(P+'COUNTRY', 'EE'),
        'KeyType': env(P+'KEY_TYPE', 'ECDSA' if profile == 'person' else 'RSA'), 'KeyBits': int(env(P+'KEY_BITS', '4096' if profile != 'person' else '0')),
        'Curve': env(P+'CURVE', 'P-384'), 'CnFormat': env(P+'COMMON_NAME_FORMAT', '{Surname},{Given},{IdCode}' if profile == 'person' else '{Given} {Surname}'),
        'SerialFormat': env(P+'SERIAL_NUMBER_FORMAT', '{IdCode}'),
        'DnsFromEmail': to_bool(env(P+'DNS_FROM_EMAIL', 'true' if profile == 'person' else 'false'), True),
        'NoCrl': to_bool(env(P+'NO_CRL', 'false'), False), 'NoOcsp': to_bool(env(P+'NO_OCSP', 'false'), False),
        'KeepCase': to_bool(env(P+'KEEP_CASE', 'true' if profile != 'person' else 'false'), profile != 'person'),
    }
    days_given = 'days' in opt
    for k, kk in (('days','Days'),('level','Level'),('country','Country'),('key-type','KeyType'),('key-bits','KeyBits'),('curve','Curve'),
                  ('cn-format','CnFormat'),('serial-format','SerialFormat')):
        if k in opt: d[kk] = type(d[kk])(opt[k]) if not isinstance(d[kk], str) else opt[k]
    if 'no-dns-from-email' in opt: d['DnsFromEmail'] = False
    if 'dns-from-email' in opt: d['DnsFromEmail'] = True
    if opt.get('no-crl') == '1': d['NoCrl'] = True
    if opt.get('no-ocsp') == '1': d['NoOcsp'] = True
    quad_default = int(opt.get('quadrant', '1'))
    try: recs = load(path)
    except ValueError as e:
        print(SEP.join(['ERR', str(e)] + [''] * 17)); return 0
    for r in recs:
        where = 'Person %d' % r['_Line']
        def g(k, dflt=''):
            return r[k] if k in r and str(r[k]) != '' else dflt
        try:
            if not to_bool(r.get('IsGenerate'), True):
                nm = ' '.join(x for x in (g('GivenName'), g('Surname')) if x)
                print(SEP.join(['SKIP', '%s (%s)' % (nm, g('IdCode'))] + [''] * 17)); continue
            id_req = (profile == 'person')
            for req in ('IdCode', 'GivenName', 'Surname', 'Email'):
                if req == 'IdCode' and not id_req: continue
                if str(g(req)) == '': raise ValueError('%s is missing' % req)
            idc = str(g('IdCode')).strip(); country = str(g('Country', d['Country'])).strip().upper()
            idtype = str(g('IdType')).strip().upper()
            given = re.sub(r'\s+', ' ', str(g('GivenName')).strip()); sur = re.sub(r'\s+', ' ', str(g('Surname')).strip())
            label = ('%s %s (%s)' % (sur, given, idc)) if idc else '%s %s' % (sur, given)
            if not re.fullmatch(r'[A-Z]{2}', country): raise ValueError('Country must be a two-letter ISO code, got %s' % country)
            if idc and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._/:+()\-]{0,62}[A-Za-z0-9]', idc): raise ValueError('the ID %s must be 2 to 64 characters: letters, digits and . _ / : + ( ) -' % idc)
            if opt.get('check-estonian-id') and country == 'EE' and not estonian_ok(idc): raise ValueError('%s is not a valid Estonian personal code' % idc)
            for nm, v in (('GivenName', given), ('Surname', sur)):
                if not 1 <= len(v) <= 64 or re.search(r'[\x00-\x1f\x7f=+"\\<>;]', v): raise ValueError('%s is not acceptable in a name' % nm)
            email = str(g('Email')).strip()
            if not re.fullmatch(r'[^@\s,;<>"]+@[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)+', email): raise ValueError('%s is not a valid e-mail address' % email)
            level = str(g('Level', d['Level'])).upper()
            if level == 'DV': raise ValueError('Level DV is not used for person certificates. Use OV (default) or EV.')
            if level not in ('OV', 'EV'): raise ValueError('Level must be OV or EV')
            q = int(g('Quadrant', quad_default))
            if q not in (1, 2): raise ValueError('Quadrant must be 1 (Classic non-FIPS) or 2 (Classic FIPS) in the shell generators')
            days = int(g('Days', d['Days']))
            if level == 'EV' and not (('Days' in r) or days_given): days = 397
            if days < 1 or days > 36500: raise ValueError('Days must be 1 to 36500')
            if level == 'EV' and days > 397: raise ValueError('an EV certificate may not be valid longer than 397 days')
            dnsf = to_bool(r.get('DnsFromEmail'), d['DnsFromEmail'])
            dns = ''
            if dnsf:
                dom = email.rsplit('@', 1)[1].lower(); dns = '%s *.%s' % (dom, dom)
            nocrl, noocsp = d['NoCrl'], d['NoOcsp']
            if 'NoCrl' in r: nocrl = to_bool(r['NoCrl'], False)
            if 'NoOcsp' in r: noocsp = to_bool(r['NoOcsp'], False)
            if 'NoRevocationInfo' in r: nocrl = noocsp = to_bool(r['NoRevocationInfo'], False)
            up = (lambda s: s) if d['KeepCase'] else (lambda s: s.upper())
            serial = str(g('SerialNumber')).strip()
            if not serial: serial = d['SerialFormat'].replace('{IdType}', idtype).replace('{Country}', country).replace('{IdCode}', idc)
            if len(serial) > 64: raise ValueError('the serial number is longer than 64 characters')
            cn = str(g('CommonName')).strip()
            if not cn: cn = up(d['CnFormat'].replace('{Surname}', sur).replace('{Given}', given).replace('{IdCode}', idc).replace('{Country}', country).replace('{SurnameFirst}', sur + ' ' + given))
            if len(cn) > 64: raise ValueError('the common name %s is longer than 64 characters' % cn)
            folder = str(g('Name')).strip() or fs_name('%s-%s-%s' % (idc, sur, given) if idc else '%s-%s' % (sur, given))
            kt = str(g('KeyType', d['KeyType'])).strip().lower()
            if kt not in ('rsa', 'ecdsa'): raise ValueError('KeyType must be RSA or ECDSA')
            kb = int(g('KeyBits', d['KeyBits'] or 0)); curve = str(g('Curve', d['Curve'])).upper()
            print(SEP.join(['OK', label, folder, serial, up(given), up(sur), cn, country, email, dns, '1' if nocrl else '0', '1' if noocsp else '0',
                            level, str(q), str(days), kt, str(kb), curve, str(g('Password'))]))
        except Exception as e:
            print(SEP.join(['ERR', '%s: %s' % (where, e)] + [''] * 17))
    return 0

if __name__ == '__main__':
    sys.exit(main())
