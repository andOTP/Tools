#! /usr/bin/python3
#
# This script can be used to decrypt andOTP database files. But it can only be
# used if the andOTP database was encrypted using a Password / PIN, if the
# Android KeyStore was used this can't work.
#
# Dependencies:
#  * Python 3
#  * Pycryptodom (https://pypi.org/project/pycryptodome/)
#
# Usage:
#  * You will need three things in order to decrypt the database:
#     1) The password / PIN that was used to encrypt the database
#     2) The database file:     secrets.dat
#     3) The preferences file:  org.shadowice.flocke.andotp_preferences.xml
#
#  * Command to decrypt the database:
#     python3 decrypt_database.py secrets.dat org.shadowice.flocke.andotp_preferences.xml <password>
#

from Crypto.Cipher import AES
import base64
import hashlib
import json
import os.path
import sys
import xml.etree.ElementTree

if len(sys.argv) < 4:
    print("Usage: " + sys.argv[0] + ": <secrets.dat> <org.shadowice.flocke.andotp_preferences.xml> <password>")
    sys.exit(1)

dbFile = sys.argv[1]
prefFile = sys.argv[2]
password = sys.argv[3]

pbkdfLength = 32 # 256-bit
encIVLength = 12

if not os.path.exists(dbFile):
    print("File '" + dbFile + "' does not exist!")
    sys.exit(1)

if not os.path.exists(prefFile):
    print("File '" + prefFile + "' does not exist!")
    sys.exit(1)

xmlFile = xml.etree.ElementTree.parse(prefFile)
xmlRoot = xmlFile.getroot()

salt = ""
iterations = 0

for child in xmlRoot:
    if child.get('name') == 'pref_auth_salt':
        salt = child.text

    if child.get('name') == 'pref_auth_iterations':
        iterations = child.get('value')

saltBytes = base64.urlsafe_b64decode(salt.strip())

pbkdfKey = hashlib.pbkdf2_hmac('sha1', bytes(password, 'utf-8'), saltBytes, int(iterations), pbkdfLength)
halfKey = pbkdfLength // 2;
decryptKey = pbkdfKey[0:halfKey]

in_file = open(dbFile, "rb")
dbData = in_file.read()
in_file.close()

iv = dbData[0:encIVLength]
payload = dbData[encIVLength:-16]
tag = dbData[-16:]

aes = AES.new(decryptKey, AES.MODE_GCM, nonce=iv)
decryptedBytes = aes.decrypt_and_verify(payload, tag)
decrypted = str(decryptedBytes, "utf-8")

jsonData = json.loads(decrypted)

print(json.dumps(jsonData, indent=4, sort_keys=True))

