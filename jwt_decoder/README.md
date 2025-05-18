# Decode JWT Tokens
- Decodes JWT tokens. This is useful for debugging JWT tokens and understanding their contents.
- This script was tested on Python version `3.13.3`

## Usage
```
python3 ./jwt_decoder.py --help                                                                                                                                                          
usage: jwt_decoder.py [-h] -jwt JWT

Takes a JWT token and decodes it.

options:
  -h, --help  show this help message and exit
  -jwt JWT    Provide the encoded JWT token
```

## Example
```
python3 ./jwt_decoder.py -jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

---Header---
alg: HS256
typ: JWT

---Payload---
sub: 1234567890
name: John Doe
iat: 1516239022

---Signature---
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```