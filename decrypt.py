#!/usr/bin/env python3

import argparse
import base64
import mimetypes
import os
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError

from hashlib import md5
from hashlib import sha256
from Crypto.Cipher import AES


class JenkinsDecrypt():
    def __init__(self, master_key, hudson_secret_key):
        # You can find the password format at
        # https://github.com/jenkinsci/jenkins/blob/master/core/src/main/java/hudson/util/Secret.java#L167-L216
        self.MAGIC = b"::::MAGIC::::"
        self.verbose = False
        self.load_master_key(master_key)
        self.load_credentials_confidential_key(hudson_secret_key, "hudson_secret")


    def load_master_key(self, master_key):
        """Read master.key which is used to decrypt instances of ConfidentialKey"""
        master_key = open(master_key, "rb").read().strip()
        self.hashed_master_key = sha256(master_key).digest()[:16]


    def load_credentials_confidential_key(self, path, key_name):
        """Read and decrypt an instance of ConfidentialKey"""
        secret_key_file = open(path, "rb").read().strip()
        o = AES.new(self.hashed_master_key, AES.MODE_ECB)
        secret = o.decrypt(secret_key_file)

        secret = secret[:-16]
        secret = secret[:16]
        setattr(self, key_name, secret)


    def decrypt_secret_bytes(self, data):
        """decrypt() function from credentials-plugin
        https://github.com/jenkinsci/credentials-plugin/blob/master/src/main/java/com/cloudbees/plugins/credentials/SecretBytes.java#L200
        """
        if not data:
            return None
        try:
            if self.credentials_secret is None:
                # The ciphertext doesn't have a newline. So let's at least improve output
                return data + "\n"
        except AttributeError:
            setattr(self, "credentials_secret", None)
            print("\nWARNING - Use --credentials-secret to specify path to Credentials plugin key\n")
            return data + "\n"

        salt_len = 8
        iv_len = 16
        key_len = 16

        data = data.strip("{}")
        p = base64.decodebytes(bytes(data, "utf-8"))

        # decrypt() from SecretBytes.java in credentials-plugin
        totalLen = len(p)
        salt = p[0:salt_len]
        padLen = p[salt_len]
        ct_len = totalLen - salt_len - 1 - (padLen & 0xff)
        encryptedBytes = p[salt_len+1:salt_len+1+ct_len]

        # createCipher() from CredentialsConfidentialKey.java in credentials-plugin
        m = sha256()
        m.update(self.credentials_secret)
        m.update(salt)
        message_digest = m.digest()
        real_key = message_digest[0:key_len]
        real_iv = message_digest[key_len:key_len+iv_len]
        o = AES.new(real_key, AES.MODE_CBC, real_iv)

        pt_bytes = o.decrypt(encryptedBytes)
        return pt_bytes.strip(b"\x0e").decode("utf-8")


    def decrypt_new_password(self, p):
        p = p[1:] #Strip the version

        # Get the length of the IV, almost certainly 16 bytes, but calculating for completeness sake
        iv_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)

        if iv_length != 16:
            self.vprint(f"WARN - {p} had invalid IV length of {iv_length}")
            return None

        # Strip the iv length
        p = p[4:]
        # Get the data length, not currently used
        #data_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)

        # Strip the data length
        p = p[4:]
        iv = p[:iv_length]
        p = p[iv_length:]
        o = AES.new(self.hudson_secret, AES.MODE_CBC, iv)
        decrypted_p = o.decrypt(p)

        # We may need to strip PKCS7 padding
        fully_decrypted_blocks = decrypted_p[:-16]
        possibly_padded_block = decrypted_p[-16:]
        padding_length = possibly_padded_block[-1]
        if padding_length < 16: # Less than size of one block, so we have padding
            possibly_padded_block = possibly_padded_block[:-padding_length]

        pw = fully_decrypted_blocks + possibly_padded_block
        pw = pw.decode("utf-8")
        return pw


    def decrypt_old_password(self, p):
        # Copying the old code, I have not verified if it works
        # pycrypto requires that values be a multiple of 16 in length
        if len(p) % 16 != 0:
            self.vprint(f"WARN - {base64.b64encode(p)} had invalid length")
            return None
        o = AES.new(self.hudson_secret, AES.MODE_ECB)
        x = o.decrypt(p)
        if self.MAGIC in x:
            pw = x.split(self.MAGIC)[0]
            return pw.decode("utf-8")
        self.vprint(f"WARN - Failed to decrypt {base64.b64encode(p)}")
        return None


    def decrypt(self, password, apiToken=False):
        if not password or not self.hudson_secret:
            return None
        password = password.strip("{}")
        try:
            p = base64.decodebytes(bytes(password, "utf-8"))
        except base64.binascii.Error as e:
            self.vprint(f"WARN - this value doesn't appear to be base64. Maybe it's plaintext?\n{password}")
            return password

        # Get payload version
        payload_version = p[0]
        if payload_version == 1:
            decrypted_value = self.decrypt_new_password(p)
        else:
            # Assuming we don't have a V2 payload, seeing as current crypto isn't
            # horrible that's a fair assumption
            decrypted_value = self.decrypt_old_password(p)
        if apiToken:
            if not decrypted_value:
                return decrypted_value
            # Return the md5 hex digest of the secret for the real apiToken
            if len(decrypted_value) != 48:
                self.vprint("WARN - apiToken has incorrect length")
                return decrypted_value

            # The secret value seems to consistently be padded with 16 extra bytes
            decrypted_bytes = bytes(decrypted_value, "utf-8")[:32]
            md5_obj = md5()
            md5_obj.update(decrypted_bytes)
            decrypted_value = md5_obj.hexdigest()
        return decrypted_value


    def get_tokens_from_node(self, node_name, root_element_tree):
        """Create key-value pairs from children of node_name. Return as dict."""
        nodes = root_element_tree.findall(f".//{node_name}")

        for node in nodes:
            creds = {}
            for child in node:
                creds[child.tag] = child.text
                # Only a couple plugins have one more level of nested children
                for subchild in child:
                    creds[subchild.tag] = subchild.text
            yield creds


    def add_attributes(self, base_str, plugin_tree, **kwargs):
        """Add values of other XML tags if they exist

        kwargs should be in the form of:
        xml_tag="printed description of tag"
        """
        for key in kwargs:
            attribute = plugin_tree.get(key, None)
            if attribute:
                base_str = base_str + f"\n{kwargs[key]}: {attribute}"
        return base_str


    def print_creds_from_plugins(self, file_tree):
        """Search a file for all plugins and associated values we're interested in."""
        # username / password
        output_fmt = "{} / {}"
        plugins = [
            "com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl",
            "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl",
            "com.cloudbees.jenkins.plugins.awscredentials.AWSCredentialsImpl",
            "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey",

            "hudson.plugins.ec2.EC2Cloud",
            "hudson.security.HudsonPrivateSecurityRealm_-Details",
            "hudson.scm.CVSSCM.xml",
            "hudson.tools.JDKInstaller.xml",

            "jenkins.security.ApiTokenProperty",
            "jenkins.security.plugins.ldap.LDAPConfiguration",

            "org.jenkinsci.main.modules.cli.auth.ssh.UserPropertyImpl",
            "org.jenkinsci.plugins.docker.commons.credentials.DockerServerCredentials",
            "org.jenkinsci.plugins.github__branch__source.GitHubAppCredentials",
            "org.jenkinsci.plugins.kubernetes.credentials.OpenShiftBearerTokenCredentialImpl",
            "org.jenkinsci.plugins.p4.credentials.P4PasswordImpl",
            "org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl",
            "org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl"
        ]

        # Find, decrypt, and print credentials for each plugin
        finding = False
        for plugin in plugins:
            creds = self.get_tokens_from_node(plugin, file_tree)

            if not creds:
                continue
            for cred in creds:
                try:
                    output = None
                    ## com.cloudbees ##
                    if plugin == "com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl":
                        output = output_fmt.format(
                            "Cert ID: " + cred.get("id", None),
                            self.decrypt_secret_bytes(cred.get("uploadedKeystoreBytes", None)))
                        output = self.add_attributes(output, cred, description="Description")
                    elif plugin == "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl":
                        output = output_fmt.format(
                            cred.get("username", None),
                            self.decrypt(cred.get("password", None)))
                        output = self.add_attributes(output, cred, description="Description")
                    elif plugin == "com.cloudbees.jenkins.plugins.awscredentials.AWSCredentialsImpl":
                        output = output_fmt.format(
                            cred.get("accessKey", None),
                            self.decrypt(cred.get("secretKey", None)))
                        output = self.add_attributes(output, cred, description="Description", iamRoleArn="IAM role")
                    elif plugin == "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey":
                        output = output_fmt.format(
                            cred.get("username", None),
                            self.decrypt(cred.get("privateKey", None)))
                        output = self.add_attributes(output, cred, description="Description")

                    ## hudson ##
                    elif plugin == "hudson.plugins.ec2.EC2Cloud":
                        output = "EC2 Cloud key:\n{}".format(
                            self.decrypt(cred.get("privateKey", None)))
                    elif plugin == "hudson.security.HudsonPrivateSecurityRealm_-Details":
                        output = "Password hash: {}".format(cred.get("passwordHash", None))
                    elif plugin == "hudson.scm.CVSSCM.xml":
                        output = output_fmt.format(
                            cred.get("privateKeyLocation", None),
                            self.decrypt(cred.get("privateKeyPassword", None)))
                    elif plugin == "hudson.tools.JDKInstaller.xml":
                        output = output_fmt.format(
                            cred.get("username", None),
                            self.decrypt(cred.get("password", None)))

                    ## jenkins.security ##
                    elif plugin == "jenkins.security.ApiTokenProperty":
                        # Starting in Jenkins 2.129 they changed the way API tokens are generated
                        # They now store a SHA256 hash on disk which means we can't recover the actual token
                        # https://www.jenkins.io/blog/2018/07/02/new-api-token-system/
                        output = "apiToken: {}".format(self.decrypt(cred.get("apiToken", None), apiToken=True))
                    elif plugin == "jenkins.security.plugins.ldap.LDAPConfiguration":
                        output = output_fmt.format(
                            cred.get("server", None),
                            self.decrypt(cred.get("managerPasswordSecret", None)))

                    ## org.jenkinsci ##
                    elif plugin == "org.jenkinsci.main.modules.cli.auth.ssh.UserPropertyImpl":
                        output = "Authorized keys: {}".format(cred.get("authorizedKeys", None))
                    elif plugin == "org.jenkinsci.plugins.docker.commons.credentials.DockerServerCredentials":
                        output = output_fmt.format(
                            "Docker Server ID: " + cred.get("id", None),
                            self.decrypt(cred.get("clientKey", None)))
                        output = self.add_attributes(output, cred, description="Description")
                    elif plugin == "org.jenkinsci.plugins.github__branch__source.GitHubAppCredentials":
                        output = output_fmt.format(
                            "GitHub App ID: " + cred.get("id", None),
                            self.decrypt(cred.get("privateKey", None)))
                    elif plugin == "org.jenkinsci.plugins.kubernetes.credentials.OpenShiftBearerTokenCredentialImpl":
                        output = output_fmt.format(
                            cred.get("username", None),
                            self.decrypt(cred.get("password", None)))
                        output = self.add_attributes(output, cred, description="Description")
                    elif plugin == "org.jenkinsci.plugins.p4.credentials.P4PasswordImpl":
                        output = output_fmt.format(
                            cred.get("username", None),
                            self.decrypt(cred.get("password", None)))
                    elif plugin == "org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl":
                        output = output_fmt.format(
                            cred.get("fileName", None),
                            self.decrypt_secret_bytes(cred.get("secretBytes", None)))
                        output = self.add_attributes(output, cred, description="Description")
                    elif plugin == "org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl":
                        output = "Secret string: {}".format(
                            self.decrypt(cred.get("secret", None)))
                        output = self.add_attributes(output, cred, description="Description")

                    # Only print plugin info if we find results
                    if output:
                        finding = True
                        section_label = "\n=== {} ===".format(plugin)
                        print(section_label)
                        print(output)
                except KeyError as e:
                    self.vprint(f"WARN - {cred} didn't have an attribute we need\n{e}")
        if finding:
            # If we have found something in this file, print a newline to
            # improve output with -v
            self.vprint("")


    def find_xml_files(self, directory):
        """Return all xml files from directory and subdirectories"""
        for dirpath, dirnames, filenames in os.walk(directory, topdown=True):
            # Modify dirnames in place to exclude plugins directory
            dirnames[:] = [d for d in dirnames if d != "plugins"]
            for filename in filenames:
                if mimetypes.guess_type(filename)[0] == "application/xml":
                    yield dirpath + "/" + filename


    def parse_xml_file(self, xml_file):
        try:
            return ET.parse(xml_file).getroot()
        except ParseError:
            self.vprint(f"WARN - {xml_file} contains improperly formatted XML")


    def vprint(self, print_string):
        """Verbose print. Only prints if -v is passed"""
        if self.verbose:
            print(print_string)


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("master_key", help="Path to master.key")
    parser.add_argument("hudson_util_secret", help="Path to hudson.util.Secret")
    parser.add_argument("-cs", "--credentials-secret", help="Path to credentials-plugin key (com.cloudbees.plugins.credentials.SecretBytes.KEY)")
    group.add_argument("-f", "--file", help="File with credentials")
    group.add_argument("-d", "--dir", help="Directory to search")
    parser.add_argument("-v", "--verbose", action="store_true", help="Include errors and warnings")
    args = parser.parse_args()

    jd = JenkinsDecrypt(args.master_key, args.hudson_util_secret)
    if args.verbose:
        jd.verbose = True
    if args.credentials_secret:
        jd.load_credentials_confidential_key(args.credentials_secret, "credentials_secret")

    if args.dir:
        all_xml_files = jd.find_xml_files(os.path.realpath(args.dir))
        for xml_file in all_xml_files:
            jd.vprint(f"{xml_file}...")
            credentials_file_tree = jd.parse_xml_file(xml_file)
            if not credentials_file_tree:
                continue
            jd.print_creds_from_plugins(credentials_file_tree)
    else:
        credentials_file_tree = jd.parse_xml_file(args.file)
        if credentials_file_tree:
            jd.print_creds_from_plugins(credentials_file_tree)


if __name__ == "__main__":
    main()
