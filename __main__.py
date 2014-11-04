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
import base64
import math

from bottle import run, get, post, request
from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.codec.ber import decoder


def chunk_into(data, size):
    ret = list()
    for i in range(math.ceil(len(data) / size)):
        ret.append(data[i * size:(i + 1) * size])
    return ret


@get('/')
def main():
    return '''<!DOCTYPE html>
<html>
<body>

<form action="/" method="post" id="keygen-form">
  Username: <input type="text" name="usr_name">
   <keygen name="pubkey" challenge="246813579" keytype="RSA"
    keyparams="4096" id="keygen-form">
  <input type="submit">
</form>

<p><strong>Note:</strong> The keygen tag is not supported in Internet Explorer.</p>

</body>
</html>'''


@post('/')
def ajax():
    key_data = request.forms['pubkey']
    asn1 = base64.b64decode(key_data)
    # key = load_privatekey(FILETYPE_ASN1, asn1)
    t = decoder.decode(asn1)
    f = t[0][0][0][1]
    r = decoder.decode(bytes(int(__, 2) for __ in chunk_into(''.join([str(_) for _ in f]), 8)))[0]
    modulus = int(r[0])
    e = int(r[1])
    k = rsa.RSAPublicKey(e, modulus)
    return '{1}\n{0}'.format(modulus, e)


if __name__ == '__main__':
    run(host='localhost', port=8080, debug=True, server='gunicorn')
