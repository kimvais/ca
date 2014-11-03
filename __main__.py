from OpenSSL.crypto import load_privatekey, FILETYPE_PEM
from bottle import run, get, post, request


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
    key = load_privatekey(FILETYPE_PEM, key_data)
    return repr(key)


if __name__ == '__main__':
    run(host='localhost', port=8080, debug=True, server='gunicorn')
