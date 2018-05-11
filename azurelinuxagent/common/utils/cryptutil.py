# Microsoft Azure Linux Agent
#
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

import base64
import struct
import os.path
import subprocess

from azurelinuxagent.common.future import ustr, bytebuffer
from azurelinuxagent.common.exception import CryptError

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil

class DebugLogger():
    @staticmethod
    def dlogger(message):
       with open("/var/log/waagent.log", "a") as myFile:
            myFile.write("DEBUG: {0}\n".format(message)) 

class CryptUtil(object):
    def __init__(self, openssl_cmd):
        self.openssl_cmd = openssl_cmd

    def gen_transport_cert(self, prv_file, crt_file):
        """
        Create ssl certificate for https communication with endpoint server.
        """
        cmd = ("{0} req -x509 -nodes -subj /CN=LinuxTransport -days 730 "
               "-newkey rsa:2048 -keyout {1} "
               "-out {2}").format(self.openssl_cmd, prv_file, crt_file)
        rc = shellutil.run(cmd)
        if rc != 0:
            logger.error("Failed to create {0} and {1} certificates".format(
                prv_file, crt_file))

    def get_pubkey_from_prv(self, file_name):
        cmd = "{0} rsa -in {1} -pubout 2>/dev/null".format(self.openssl_cmd, 
                                                           file_name)
        pub = shellutil.run_get_output(cmd)[1]
        return pub

    def get_pubkey_from_crt(self, file_name):
        cmd = "{0} x509 -in {1} -pubkey -noout".format(self.openssl_cmd, 
                                                       file_name)
        pub = shellutil.run_get_output(cmd)[1]
        return pub

    def get_thumbprint_from_crt(self, file_name):
        cmd="{0} x509 -in {1} -fingerprint -noout".format(self.openssl_cmd, 
                                                          file_name)
        thumbprint = shellutil.run_get_output(cmd)[1]
        thumbprint = thumbprint.rstrip().split('=')[1].replace(':', '').upper()
        return thumbprint

    def decrypt_p7m(self, p7m_file, trans_prv_file, trans_cert_file, pem_file):
        cmd = ("{0} cms -decrypt -in {1} -inkey {2} -recip {3} "
               "| {4} pkcs12 -nodes -password pass: -out {5}"
               "").format(self.openssl_cmd, p7m_file, trans_prv_file, 
                          trans_cert_file, self.openssl_cmd, pem_file)
        shellutil.run(cmd)
        rc = shellutil.run(cmd)
        if rc != 0:
            logger.error("Failed to decrypt {0}".format(p7m_file))
    
    def decrypt_encrypted_file(self, privateKey, encryptedFile):
        cmd = "{0} cms -decrypt -inform DER -inkey {1} -in {2}".format(self.openssl_cmd, privateKey, encryptedFile)
        output = shellutil.run_get_output(cmd)
        #return output[1].decode('utf8').replace("\0", "")
        return output[1].replace("\0", "")

    def decryptStringWithPrivateKey(self, input_text, privateKey):
        dataCacheFile = "{0}.dat".format(privateKey)
        if os.path.isfile(privateKey):
            logger.verbose("criptutil: private key exists {0}".format(privateKey))
            #DebugLogger.dlogger("criptutil: private key exists {0}".format(privateKey))
            # write cache file.

            with open(dataCacheFile, "w") as dataWrite:
                dataWrite.write(input_text)
                
            try:
                cmd = "openssl pkeyutl -decrypt -inkey {0} -in {1}".format(privateKey, dataCacheFile)
                output = shellutil.run_get_output(cmd) 
                if output[0] == 0:
                    return output[1]
                else:
                    # TODO: check error handling flow in this scenario.
                    logger.error("cryptutil: Unable to decrypt password using {0}".format(privateKey))
                    return None
            finally:
                if os.path.isfile(dataCacheFile):
                    logger.verbose("cryptutil: Deleting cache file {0}".format(dataCacheFile))
                    os.remove(dataCacheFile)
                    logger.verbose("cryptutil: data cache file deleted {0}".format(dataCacheFile))
                else:
                    logger.warn("cryptutil: data cache file did not exist {0}".format(dataCacheFile))            
        else:
            logger.error("private key file does not exist: {0}".format(privateKey))
            #DebugLogger.dlogger("criptutil: private key file does not exist: {0}".format(privateKey))
            return None
    
    def RunSendStdin(self, cmd, input, chk_err=True):
        try:
            me = subprocess.Popen([cmd], shell=True, stdin=subprocess.PIPE,stderr=subprocess.STDOUT,stdout=subprocess.PIPE)
            output=me.communicate(input)
        except OSError as e:
            if chk_err :
                DebugLogger.dlogger('CalledProcessError.  Error Code is ' + str(me.returncode))
                DebugLogger.dlogger('CalledProcessError. Command string was ' + cmd)
                DebugLogger.dlogger('CalledProcessError.  Command result was ' + output[0].decode('latin-1'))
                return 1,output[0].decode('latin-1')
        if me.returncode is not 0 and chk_err is True:
                DebugLogger.dlogger('CalledProcessError.  Error Code is ' + str(me.returncode))
                DebugLogger.dlogger('CalledProcessError. Command string was ' + cmd)
                DebugLogger.dlogger('CalledProcessError.  Command result was ' + output[0].decode('latin-1'))
        return me.returncode,output[0].decode('latin-1')

    def crt_to_ssh(self, input_file, output_file):
        shellutil.run("ssh-keygen -i -m PKCS8 -f {0} >> {1}".format(input_file,
                                                                    output_file))

    def asn1_to_ssh(self, pubkey):
        lines = pubkey.split("\n")
        lines = [x for x in lines if not x.startswith("----")]
        base64_encoded = "".join(lines)
        try:
            #TODO remove pyasn1 dependency
            from pyasn1.codec.der import decoder as der_decoder
            der_encoded = base64.b64decode(base64_encoded)
            der_encoded = der_decoder.decode(der_encoded)[0][1]
            key = der_decoder.decode(self.bits_to_bytes(der_encoded))[0]
            n=key[0]
            e=key[1]
            keydata = bytearray()
            keydata.extend(struct.pack('>I', len("ssh-rsa")))
            keydata.extend(b"ssh-rsa")
            keydata.extend(struct.pack('>I', len(self.num_to_bytes(e))))
            keydata.extend(self.num_to_bytes(e))
            keydata.extend(struct.pack('>I', len(self.num_to_bytes(n)) + 1))
            keydata.extend(b"\0")
            keydata.extend(self.num_to_bytes(n))
            keydata_base64 = base64.b64encode(bytebuffer(keydata))
            return ustr(b"ssh-rsa " +  keydata_base64 + b"\n", 
                        encoding='utf-8')
        except ImportError as e:
            raise CryptError("Failed to load pyasn1.codec.der")

    def num_to_bytes(self, num):
        """
        Pack number into bytes.  Retun as string.
        """
        result = bytearray()
        while num:
            result.append(num & 0xFF)
            num >>= 8
        result.reverse()
        return result

    def bits_to_bytes(self, bits):
        """
        Convert an array contains bits, [0,1] to a byte array
        """
        index = 7
        byte_array = bytearray()
        curr = 0
        for bit in bits:
            curr = curr | (bit << index)
            index = index - 1
            if index == -1:
                byte_array.append(curr)
                curr = 0
                index = 7
        return bytes(byte_array)

    def base64_to_file(self, cacheFile, base64str):
        with open(cacheFile, "wb") as c:
            c.write(base64.b64decode(base64str))
            #c.write(base64.decodestring(base64str))

