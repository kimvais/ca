# -*- coding: utf-8 -*-
#
# Copyright © 2014 Kimmo Parviainen-Jalanko <k@77.fi>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
import datetime
import subprocess

import OpenSSL
from OpenSSL.crypto import FILETYPE_PEM


def parse_dn_components(d):
    """
    Normalizes the Distinguished name in a sensible order and converts attribute name aliases to
    ones understood by OpenSSL
    :param d: a dictionary with attribute names as keys
    :returns: a list of 2-tuples
    """
    COMPONENTS = (
        ('CN', 'commonName'),
        ('OU', 'organizationalUnitName'),
        ('O', 'organizationName'),
        ('L', 'localityName'),
        ('ST', 'stateOrProvinceName'),
        ('C', 'countryName'),
        # ('GN', 'givenName'),
        # ('SN', 'surname'),
        # ('I', 'initials'),
        # ('T', 'title'),
        # ('D', 'description'),
        ('emailAddress', 'Email'),
        ('UID', 'uniqueIdentifier'),
    )
    ret = list()
    for a, b in COMPONENTS:
        v = d.pop(b) if b in d else d.pop(a, None)
        if v is None:
            continue
        ret.append((a, v))
    return ret


def set_name_from_dict(x509_name, name_d):
    for k, v in parse_dn_components(name_d):
        setattr(x509_name, k, v)


def create_cert_req(pk, dn):
    c = OpenSSL.crypto.X509Req()
    c.set_pubkey(pk)
    set_name_from_dict(c.get_subject(), dn)
    c.get_subject()
    c.sign(pk, 'SHA256')
    c.verify(pk)
    # csr = OpenSSL.crypto.dump_certificate_request(FILETYPE_PEM, c)
    return c


def convert_timestamp(now):
    TS_FMT = '%Y%m%d%H%M%SZ'
    return now.strftime(TS_FMT).encode('ascii')


def create_certificate_from_csr(csr, issuer):
    x = OpenSSL.crypto.X509()
    x.set_issuer(issuer.get_subject())
    x.set_subject(csr.get_subject())
    x.set_pubkey(csr.get_pubkey())
    x.set_serial_number(1)
    now = datetime.datetime.utcnow()
    not_before = convert_timestamp(now)
    not_after = convert_timestamp(now + datetime.timedelta(days=365 * 5))
    x.set_notBefore(not_before)
    x.set_notAfter(not_after)
    return x


def create_self_signed_cert(pk, dn):
    csr = create_cert_req(pk, dn)
    x = create_certificate_from_csr(csr, csr)
    x.sign(pk, 'SHA256')
    return x



