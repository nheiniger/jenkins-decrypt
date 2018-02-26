jenkins-decrypt
===============

Requires python 3

## About
The original `decrypt.py` focused on `credentials.xml`, but Jenkins is a magnet for credentials and stores them in places besides `credentials.xml`. This version adds:
* Support for additional credentials plugins
* Easier to read output (username / password)
* Support for decrypting user api tokens
* Ability to search many XML files for credentials
* XML parsing

## Known issues
* Decrypting values encrypted by the first encryption algorithm (before "V1") remains untested.
* Didn't do an exhaustive search for credential plugins so there are likely more
