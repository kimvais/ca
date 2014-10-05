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
import logging
import os
import tempfile
import unittest
import subprocess

import OpenSSL
from OpenSSL.crypto import FILETYPE_PEM, TYPE_RSA


logger = logging.getLogger(__name__)

from ca import parse_dn_components, create_self_signed_cert, create_cert_req, create_certificate_from_csr


def _read_certificate_text(cert_obj):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(OpenSSL.crypto.dump_certificate(FILETYPE_PEM, cert_obj))
        output = subprocess.check_output(['openssl', 'x509', '-noout', '-text', '-in', f.name]).decode('ascii')
    finally:
        os.unlink(f.name)
    return output


class TestDNParsing(unittest.TestCase):
    files = list()

    def test_aliases(self):
        d1 = dict(
            countryName='fi',
            commonName="Example"
        )
        d2 = dict(
            C='fi',
            CN="Example"
        )
        self.assertEqual(parse_dn_components(d1), parse_dn_components(d2))


class TestSelfSignedRootCA(unittest.TestCase):
    def test_0001_root(self):
        dn = dict(CN='Kimmo Parviainen-Jalanko', L="Espoo", C='fi', emailAddress='k@77.fi', UID='kimvais')
        pk_text = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArKC07XzM1xYDCA+tRqTpysfoTeb95xUO6Xy/08bPXf3YN8YH
agA8PPTqFwuJ2PK9sOr8JHkxslijHJr2iCYgqq03uE/DZkGwEmWJphn2Ut4T2Gax
03Cc9+5a6eUrezH7J2YQU7Yu8O9b9AsAZ4crpj6gF51rvdwAw5HbbZpbdyk8mX1z
WRq52MzKIxF5VFFVm2fa24nOnWcUsDADrGRYQl7qqOFqNckSFk9KG+Ia2VpvIDn3
i2Kn+GPzjxoeL1fYNNz3iTHCe1NTIpaePDNlfs7rIiWJuvzXENXthx50o0D2Vtwh
UnVBH2bneNaafw7QZrbYzadsEO6R3b/yUE6MAwIDAQABAoIBAD4OO1wP+/bp08cn
E4wMpnqd6FVwzx8tw8GNdcvkcREBuqM6Ddo+IWlsRWZpYHFbuXMK1f8qjgHluSUE
U9FXm3CfeiNIkR6GSIwkchoCxTi+2nV1XUF7/wFlbssb9ciAjB96oi3llPRJp02Q
UuHkhn1pj9VNYrjKiH/FRBMfZPfthIO5kWaWzwSVebD1PfMmbCvnm/IVppk+/sfM
m3jSrGlBu8OnhmwZDVmewV7b25BXtekxym7a81HnFeCZKL+91+X19DRYlI1MYj1u
stvWIkxky+NnkYdW74tsY+/WNAZgzJlpT5FUjiVBP6EM8inMc0zJQYRZsLECPkAR
p7xcoDkCgYEA4GcgzETgwjGwuq0xBz9hVnpcYeZTbwgCoePDMp6CT4BN4kEgqV7+
mQTo3XG77cNltzhfQXQUOB6v+mGMR5ge8g4bcVnXiAWAcaJWTgfa8W6GRWH03Xor
O4OduW37KYckI1XAWDRxR2yy8RKoN0EdwvzMhgpbCBwNHY5TpXTyN/0CgYEAxO9I
e74LEpNF7669sjMkUIOuUShlsFfh6S26mEtwbJO1jIZcOlyBwutNNCy8/wr9IxTV
ViUoJF0SlsPVx81+QHxA/s8UPUlssuh7Vgisff1dTSIzEzZ1RxKl4mcR1/Pz2Pe4
k4Gzs1n5nfGk9XOHF/vuXL4RxuifyUgW3D+1E/8CgYAQ205YadgkXk0zSK1FKRqr
v1dPN1kPHx/rf0t7cvLA/BddppzIfE1Nu1OuxstiKeprH/3v0cNvD8cSXN+HxUKV
1j9zfVc2bYtffd1T0T0+I5pMffZB6Np0hweDFWLnlLI/QULInW/g+KZce5VNSUPu
EMVgUEjUTB8kGDvqUuWbFQKBgHysyASe8b+WwQXWaH2yZuEaHHeAza/wUzMeIi1c
RRZYBO2r+iNwgS33bW8Ei7ojKNLW06Cv8VPkIGqWHHdbnvwQLc2jJ7sNCuXQzJRQ
9XLlvfWhGxikt2aBZceJXQCMjunjGlU4HZ4D7kWRv88sjnAerG7GXdbBWrdBDkft
hSPdAoGAc6DsmHDELbhBbDeeSPeyWJ0KGJ3eGfVGvqWG/L3oz9k7S+QUnWrT/OU9
DDBEj7Z+9fcUD0nITBf5IKCaNI0Eu7IoWjzkCi1X2Hhju68HTHkg0Z75x6kx5uu/
VlkMGsPXn/qIz2CFLLil84YL848MurxzTLmq4eBMWSdyjWJTXuk=
-----END RSA PRIVATE KEY-----"""
        self.__class__.privatekey = OpenSSL.crypto.load_privatekey(FILETYPE_PEM, pk_text)
        self.__class__.root_ca = create_self_signed_cert(self.privatekey, dn)
        cert_obj = self.root_ca
        output = _read_certificate_text(cert_obj)
        self.assertRegex(output,
                         r'Subject: CN=Kimmo Parviainen-Jalanko, L=Espoo, C=fi/emailAddress=k@77.fi/UID=kimvais')
        self.assertRegex(output, r'Issuer: CN=Kimmo Parviainen-Jalanko, L=Espoo, C=fi/emailAddress=k@77.fi/UID=kimvais')

    def test_0002_issued_cert(self):
        pk1 = OpenSSL.crypto.PKey()
        pk1.generate_key(TYPE_RSA, 1024)
        csr = create_cert_req(pk1, dict(CN='foobar', C='FI'))
        crt = create_certificate_from_csr(csr, self.root_ca)
        crt.sign(self.privatekey, 'SHA256')
        output = _read_certificate_text(crt)
        self.assertRegex(output,
                         r'Subject: CN=foobar, C=FI')
        self.assertRegex(output, r'Issuer: CN=Kimmo Parviainen-Jalanko, L=Espoo, C=fi/emailAddress=k@77.fi/UID=kimvais')


