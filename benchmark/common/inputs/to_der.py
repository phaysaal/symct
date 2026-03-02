import base64
with open("key.pem") as f:
    pem = f.read()

b64 = ''.join(line for line in pem.splitlines() if "PRIVATE" not in line and not line.startswith('-'))
der = base64.b64decode(b64)
with open("key.der", "wb") as f:
    f.write(der)
