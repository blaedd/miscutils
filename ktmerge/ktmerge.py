#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Simple utility to merge multiple Kerberos keytabs into one.

This also cleans out duplicate and old keytab entries.
"""

import functools
import struct

# from http://pig.made-it.com/kerberos-etypes.html
ETYPES = {
    1: 'des-cbc-crc',
    2: 'des-cbc-md4',
    3: 'des-cbc-md5',
    4: None,
    5: 'des3-cbc-md5',
    6: None,
    7: 'des3-cbc-sha1',
    9: 'dsaWithSHA1-CmsOID',
    10: 'md5WithRSAEncryption-CmsOID',
    11: 'sha1WithRSAEncryption-CmsOID',
    12: 'rs2CBC-EnvOID',
    13: 'rsaEncryption-EnvOID',
    14: 'rsaES-OAEP-ENV-OID',
    15: 'des-ede3-cbc-Env-OID',
    16: 'des3-cbc-sha1-kd',
    17: 'aes128-cts-hmac-sha1-96',
    18: 'aes256-cts-hmac-sha1-96',
    23: 'rc4-hmac',
    24: 'rc4-hmac-exp',
    65: 'subkey-experimental',
}

NTYPES = {
    1: 'KRB5_NT_PRINCIPAL',
    2: 'KRB5_NT_SRV_INST',
    3: 'KRB5_NT_SRV_HST',
    4: 'KRB5_NT_SRV_XHST',
    5: 'KRB5_NT_UID',
    6: 'KRB5_NT_X500_PRINCIPAL',
    7: 'KRB5_NT_SMTP_NAME',
    10: 'KRB5_NT_ENTERPRISE_PRINCIPAL',
    11: 'KRB5_NT_WELLKNOWN',
    4294967166: 'KRB5_NT_ENT_PRINCIPAL_AND_ID',
    4294967167: 'KRB5_NT_MS_PRINCIPAL_AND_ID',
    4294967168: 'KRB5_NT_MS_PRINCIPAL',
}


class KeytabEntry(object):
    """An entry in the Keytab."""

    def __init__(self, data=None):
        self._data = data
        self._size = len(data)
        self._realm = None
        self._components = []
        self._name_type = None
        self._timestamp = None
        self._vno8 = None
        self._key = None
        self._vno = None
        self._i = 0
        if data:
            self._parse()

    def __base_check(self, other):
        if (self.name != other.name or
                    self.realm != other.realm or
                    self.keyblock['type'] != other.keyblock['type']):
            return False
        return True

    def __eq__(self, other):
        if not isinstance(other, KeytabEntry):
            return NotImplemented
        if self._data:
            return self._data.__eq__(other)
        return False

    def __hash__(self):
        return self._data.__hash__()

    def __str__(self):
        return '%s@%s/%s VNO:%d' % (self.name, self._realm, self.key_type,
                                    self.vno)

    def __repr__(self):
        return self.__str__()

    # The use of properties is mainly to reinforce that this is read-only
    @property
    def vno(self):
        return self._vno or self._vno8

    @property
    def realm(self):
        return self._realm

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def name(self):
        return '/'.join(self._components)

    @property
    def name_type(self):
        return NTYPES.get(self._name_type, self._name_type)

    @property
    def key(self):
        return self._key['key']

    @property
    def key_type(self):
        return ETYPES.get(self._key['type'], self._key['type'])

    @property
    def ts(self):
        return self._timestamp

    def loads(self, data):
        self._data = data
        self._size = len(data)
        self._parse()

    def _encode_size(self):
        return struct.pack('!i', self._size)

    def dumps(self):
        value = struct.pack('!i', self._size) + self._data
        return value

    def _unpack(self, fmt, size):
        value = struct.unpack(fmt, self._data[self._i:self._i + size])
        self._i += size
        return value[0]

    def _uint8(self):
        n = self._unpack('!B', 1)
        return n

    def _uint16(self):
        n = self._unpack('!H', 2)
        return n

    def _int32(self):
        n = self._unpack('!i', 4)
        return n

    def _uint32(self):
        n = self._unpack('!I', 4)
        return n

    def _counted_octet_string(self):
        size = self._uint16()
        counted_string = self._unpack('!%ds' % size, size)
        return counted_string

    def _keyblock(self):
        key = {
            'type': self._uint16(),
            'key': self._counted_octet_string()
        }
        return key

    def _parse(self):
        self._i = 0

        n_components = self._uint16()
        self._realm = self._counted_octet_string()

        for i in range(n_components):
            self._components.append(self._counted_octet_string())
        self._name_type = self._uint32()
        self._timestamp = self._uint32()
        self._vno8 = self._uint8()
        self._key = self._keyblock()
        # special case. may not be present
        if self._size - self._i >= 4:
            self._vno = self._uint32()


class Keytab(object):
    def __init__(self, f=None):
        self.entries = {}
        self.format_version = None
        if f:
            self.load(f)

    def load(self, f):
        entries = set()
        format_version = struct.unpack('!H', f.read(2))[0]
        if format_version != 0x502:
            raise Exception("Unsupport file format %x" % format_version)
        self.format_version = format_version
        size_packed = f.read(4)
        while size_packed != '':
            size = struct.unpack('!i', size_packed)[0]
            if size > 0:
                entries.add(KeytabEntry(f.read(size)))
            else:
                f.read(-size)
            size_packed = f.read(4)
        self.add_entries(entries)

    def add_entry(self, entry):
        r = self.entries.setdefault(entry.realm, {})
        n = r.setdefault(entry.name, {})
        if entry.key_type in n:
            old_entry = n[entry.key_type]
            if entry.vno > old_entry.vno:
                self.entries[entry.realm][entry.name][entry.key_type] = entry
        else:
            n[entry.key_type] = entry

    def add_entries(self, entries):
        for e in entries:
            self.add_entry(e)

    def save(self, f):
        f.write(struct.pack('!H', 0x502))
        for e in self.entry_list():
            f.write(e.dumps())

    def entry_list(self):
        entries = []
        for realm in self.entries:
            for name in self.entries[realm]:
                for keytype in self.entries[realm][name]:
                    entries.append(self.entries[realm][name][keytype])
        return entries


def main(main_args):
    merged_keytab = Keytab()
    for f in main_args.keytabs:
        merged_keytab.add_entries(Keytab(f).entry_list())
        f.close()
    outfile = open(main_args.outfile, 'w')
    merged_keytab.save(outfile)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Merge keytabs')
    parser.add_argument('keytabs', metavar='ktfile', type=file, nargs='+',
                        help='a kerberos keytab to read in')
    parser.add_argument('-o', '--outfile', dest='outfile', type=str,
                        help='output file')
    args = parser.parse_args()
    main(args)
