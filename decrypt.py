#!/usr/bin/env python3

import argparse
import base64
import mimetypes
import os
import re
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError

from hashlib import md5
from hashlib import sha256
from Crypto.Cipher import AES

# You can find the password format at
# https://github.com/jenkinsci/jenkins/blob/master/core/src/main/java/hudson/util/Secret.java#L167-L216
MAGIC = b"::::MAGIC::::"


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
parser.add_argument("master_key", help="Path to master.key")
parser.add_argument("hudson_util_secret", help="Path to hudson.util.Secret")
group.add_argument("-f", "--file", help="File with credentials")
group.add_argument("-d", "--dir", help="Directory to search")
args = parser.parse_args()


def decrypt_new_password(secret, p):
    p = p[1:] #Strip the version

    # Get the length of the IV, almost certainly 16 bytes, but calculating for completeness sake
    iv_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)

    if iv_length != 16:
        print("WARN - {} had invalid IV length of {}".format(p, iv_length))
        return None

    # Strip the iv length
    p = p[4:]
    # Get the data length, not currently used
    #data_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)

    # Strip the data length
    p = p[4:]
    iv = p[:iv_length]
    p = p[iv_length:]
    o = AES.new(secret, AES.MODE_CBC, iv)
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


def decrypt_old_password(secret, p):
    # Copying the old code, I have not verified if it works
    o = AES.new(secret, AES.MODE_ECB)
    x = o.decrypt(p)
    if MAGIC in x:
        pw = re.findall(b"(.*)" + MAGIC, x)[0]
        return pw.decode("utf-8")
    print("WARN - Failed to decrypt {}".format(base64.b64encode(p)))
    return None


def decrypt(password, secret, apiToken=False):
    if not password or not secret:
        return None
    password = password.strip("{}")
    p = base64.decodebytes(bytes(password, "utf-8"))

    # Get payload version
    payload_version = p[0]
    if payload_version == 1:
        decrypted_value = decrypt_new_password(secret, p)
    else:
        # Assuming we don't have a V2 payload, seeing as current crypto isn't
        # horrible that's a fair assumption
        decrypted_value = decrypt_old_password(secret, p)
    if apiToken:
        if not decrypted_value:
            return decrypted_value
        # Return the md5 hex digest of the secret for the real apiToken
        if len(decrypted_value) != 48:
            print("WARN - apiToken has incorrect length")
            return decrypted_value

        # The secret value seems to consistently be padded with 16 extra bytes
        decrypted_bytes = bytes(decrypted_value, "utf-8")[:32]
        md5_obj = md5()
        md5_obj.update(decrypted_bytes)
        decrypted_value = md5_obj.hexdigest()
    return decrypted_value


def get_tokens_from_node(node_name, root_element_tree):
    """Create key-value pairs from children of node_name. Return as dict."""
    nodes = root_element_tree.findall(".//{}".format(node_name))

    for node in nodes:
        creds = {}
        for child in node:
            creds[child.tag] = child.text
            # Only a couple plugins have one more level of nested children
            for subchild in child:
                creds[subchild.tag] = subchild.text
        yield creds
    return


def add_attributes(base_str, plugin_tree, **kwargs):
    """Add values of other XML tags if they exist

    kwargs should be in the form of:
    xml_tag="printed description of tag"
    """
    for key in kwargs:
        attribute = plugin_tree.get(key, None)
        if attribute:
            base_str = base_str + "{}: {}\n".format(kwargs[key], attribute)
    return base_str


def print_creds_from_plugins(file_tree, secret):
    """Search a file for all plugins and associated values we're interested in."""

    plugins = [
        "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl",
        "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey",

        "hudson.security.HudsonPrivateSecurityRealm_-Details",
        "hudson.scm.CVSSCM.xml",
        "hudson.tools.JDKInstaller.xml",

        "jenkins.security.ApiTokenProperty",
        "jenkins.security.plugins.ldap.LDAPConfiguration",

        "org.jenkinsci.main.modules.cli.auth.ssh.UserPropertyImpl",
        "org.jenkinsci.plugins.p4.credentials.P4PasswordImpl",
        "org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl",
        "org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl"
    ]

    # Find, decrypt, and print credentials for each plugin
    for plugin in plugins:
        creds = get_tokens_from_node(plugin, file_tree)

        if not creds:
            continue
        for cred in creds:
            try:
                output = None
                ## com.cloudbees ##
                if plugin == "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl":
                    output = "{} / {}\n".format(
                        cred.get("username", None),
                        decrypt(cred.get("password", None), secret))
                    output = add_attributes(output, cred, description="Description")
                elif plugin == "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey":
                    output = "{} / {}\n".format(
                        cred.get("username", None),
                        decrypt(cred.get("privateKey", None), secret))
                    output = add_attributes(output, cred, description="Description")

                ## hudson ##
                elif plugin == "hudson.security.HudsonPrivateSecurityRealm_-Details":
                    output = "Password hash: {}".format(cred.get("passwordHash", None))
                elif plugin == "hudson.scm.CVSSCM.xml":
                    output = "{} / {}\n".format(
                        cred.get("privateKeyLocation", None),
                        decrypt(cred.get("privateKeyPassword", None), secret))
                elif plugin == "hudson.tools.JDKInstaller.xml":
                    output = "{} / {}\n".format(
                        cred.get("username", None),
                        decrypt(cred.get("password", None), secret))

                ## jenkins.security ##
                elif plugin == "jenkins.security.ApiTokenProperty":
                    output = "apiToken: {}".format(decrypt(cred.get("apiToken", None), secret, apiToken=True))
                elif plugin == "jenkins.security.plugins.ldap.LDAPConfiguration":
                    output = "{} / {}\n".format(
                        cred.get("server", None),
                        decrypt(cred.get("managerPasswordSecret", None), secret))

                ## org.jenkinsci ##
                elif plugin == "org.jenkinsci.main.modules.cli.auth.ssh.UserPropertyImpl":
                    output = "Authorized keys: {}".format(cred.get("authorizedKeys", None))
                elif plugin == "org.jenkinsci.plugins.p4.credentials.P4PasswordImpl":
                    output = "{} / {}\n".format(
                        cred.get("username", None),
                        decrypt(cred.get("password", None), secret))
                # TODO - debug this class.
                # Values stored by this class can't be decrypted by the standard
                # hudson.util.Secret.decrypt()
#                elif plugin == "org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl":
#                    import pdb; pdb.set_trace()
#                    output = "{} / {}\n".format(
#                        cred.get("fileName", None),
#                        decrypt(cred.get("secretBytes", None), secret))
#                    output = add_attributes(output, cred, description = "Description")
                elif plugin == "org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl":
                    output = "Secret string: {}\n".format(
                        decrypt(cred.get("secret", None), secret))
                    output = add_attributes(output, cred, description="Description")

                # Only print plugin info if we find results
                if output:
                    section_label = "=== {} ===".format(plugin)
                    sub_label = "\n" + "=" * len(section_label)
                    print(section_label, sub_label)
                    print(output, "\n")
            except KeyError:
                print("WARN - {} didn't have an attribute we need".format(cred))


def find_xml_files(directory):
    """Return all xml files from directory and subdirectories"""
    for dirpath, dirnames, filenames in os.walk(directory, topdown=True):
        # Modify dirnames in place to exclude plugins directory
        dirnames[:] = [d for d in dirnames if d != "plugins"]
        for filename in filenames:
            if mimetypes.guess_type(filename)[0] == "application/xml":
                yield dirpath + "/" + filename
    return


def parse_xml_file(xml_file):
    try:
        return ET.parse(xml_file).getroot()
    except ParseError:
        print("WARN - {} contains improperly formatted XML".format(xml_file))


def main():
    master_key = open(args.master_key, "rb").read()
    hudson_secret_key = open(args.hudson_util_secret, "rb").read()
    hashed_master_key = sha256(master_key).digest()[:16]
    o = AES.new(hashed_master_key, AES.MODE_ECB)
    secret = o.decrypt(hudson_secret_key)

    secret = secret[:-16]
    secret = secret[:16]

    if args.dir:
        all_xml_files = find_xml_files(os.path.realpath(args.dir))
        for xml_file in all_xml_files:
            print("{}...".format(xml_file))
            credentials_file_tree = parse_xml_file(xml_file)
            if not credentials_file_tree:
                continue
            print_creds_from_plugins(credentials_file_tree, secret)
    else:
        credentials_file_tree = parse_xml_file(args.file)
        if credentials_file_tree:
            print_creds_from_plugins(credentials_file_tree, secret)


if __name__ == "__main__":
    main()
