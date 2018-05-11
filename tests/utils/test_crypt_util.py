# Copyright 2018 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.6+ and Openssl 1.0+
#

import errno as errno
import glob
import random
import string
import tempfile
import uuid

import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from tests.tools import *


class TestCryptoUtilOperations(AgentTestCase):

    privateKeySuffix = "PrvTEST.pem"
    publicKeySuffix = "PubTEST.pem"
    encryptedCacheFile = None

    def encryptString(self, secret, pubKey):
        self.encryptedCacheFile = os.path.join(self.tmp_dir, "encrypted.enc")
        cmd = "echo '{0}' | openssl pkeyutl -encrypt -inkey {1} -pubin -out {2}".format(secret, pubKey, self.encryptedCacheFile)
        output = shellutil.run_get_output(cmd)

        encryptedText = ""
        try:
            with open(self.encryptedCacheFile, "r") as data:
                encryptedText = data.read()
        except Exception as e:
            pass
        return encryptedText

    
    def createKeys(self, baseKeyName):
        crypto = CryptUtil(conf.get_openssl_cmd)
        privateKey = os.path.join(self.tmp_dir, "{0}{1}".format(baseKeyName, self.privateKeySuffix))
        publicKey = os.path.join(self.tmp_dir, "{0}{1}".format(baseKeyName, self.publicKeySuffix))
        cert = os.path.join(self.tmp_dir, "{0}{1}".format(baseKeyName, ".cert"))
        try:
            cmd = "openssl req -x509 -nodes -subj /CN=LinuxTransport -days 730 -newkey rsa:2048 -keyout {0} -out {1}".format(privateKey, cert)
            rc = shellutil.run(cmd)

            # cmd = "openssl x509 -in {0} -pubkey -out {1} ".format(cert, publicKey)
            # pub = shellutil.run(cmd)
            cmd = "openssl pkey -in {0} -out {1} -outform PEM -pubout".format(privateKey, publicKey)
            shellutil.run(cmd)
        except Exception as e:
            pass

        return privateKey, publicKey
        
        # # Start fresh with new keys each time.
        # privateKey = os.path.join(self.tmp_dir, "{0}{1}".format(baseKeyName, self.privateKeySuffix))
        # publicKey = os.path.join(self.tmp_dir, "{0}{1}".format(baseKeyName, self.publicKeySuffix))
        # if os.path.isfile(privateKey):
        #     os.remove(privateKey)
        # if os.path.isfile(publicKey):
        #     os.remove(publicKey)

        # # generate private key
        # cmd = "openssl req -x509 -nodes -subj /CN=LinuxTransport -days 730 -newkey rsa:2048 -keyout {0} -out {1}".format(privateKey, publicKey)
        # shellutil.run(cmd)        

        # # generate public key
        # # cmd = "openssl pkey -in {0} -out {1} -outform PEM -pubout".format(privateKey, publicKey)
        # # shellutil.run(cmd)

        # return privateKey, publicKey

    def test_decrypt_encrypted_text(self):
        baseKeyName = "test"
        secret = "abc@123"
        keys = self.createKeys(baseKeyName)
        prvKey = keys[0]
        pubKey = keys[1]
        encryptedString = self.encryptString(secret, pubKey)

        crypto = CryptUtil(conf.get_openssl_cmd)
        decryptedString = crypto.decryptStringWithPrivateKey(str(encryptedString), prvKey)
        self.assertEquals(secret, decryptedString, "decrypted string does not match expected")

    def test_decrypt_encrypted_text_missing_private_key(self):
        baseKeyName = "test"
        secret = "abc@123"
        keys = self.createKeys(baseKeyName)
        prvKey = keys[0]
        pubKey = keys[1]
        encryptedString = self.encryptString(secret, pubKey)

        crypto = CryptUtil(conf.get_openssl_cmd)
        decryptedString = crypto.decryptStringWithPrivateKey(encryptedString, prvKey)
        self.assertTrue(False, "TODO: update when this flow is decded.")
    
    def test_decrypt_encrypted_text_wrong_private_key(self):
        baseKeyName = "test"
        secret = "abc@123"
        keys = self.createKeys(baseKeyName)
        prvKey = keys[0]
        pubKey = keys[1]
        encryptedString = self.encryptString(secret, pubKey)

        crypto = CryptUtil(conf.get_openssl_cmd)
        decryptedString = crypto.decryptStringWithPrivateKey(encryptedString, prvKey)
        self.assertTrue(False, "TODO: update when this flow is decded.")

    def test_decrypt_encrypted_text_text_not_encrypted(self):
        baseKeyName = "test"
        secret = "abc@123"
        keys = self.createKeys(baseKeyName)
        prvKey = keys[0]
        pubKey = keys[1]
        encryptedString = self.encryptString(secret, pubKey)

        crypto = CryptUtil(conf.get_openssl_cmd)
        decryptedString = crypto.decryptStringWithPrivateKey(encryptedString, prvKey)
        self.assertTrue(False, "TODO: update when this flow is decded.")

if __name__ == '__main__':
    unittest.main()
