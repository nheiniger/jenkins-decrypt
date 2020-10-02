jenkins-decrypt
===============

Requires Python 3

## About
The original `decrypt.py` focused on `credentials.xml`, but Jenkins is a magnet for credentials and stores them in places besides `credentials.xml`. This version adds:
* Support for additional plugins that store credentials
* Support for decryption routine in credentials-plugin 
* Support for decrypting user api tokens ([works until Jenkins 2.129](https://www.jenkins.io/blog/2018/07/02/new-api-token-system/))
* Easier to read output (username / password)
* Ability to search many XML files for credentials
* XML parsing

## Known issues
* Decrypting values encrypted by the first encryption algorithm (before "V1") remains untested.
* Didn't do an exhaustive search for credential plugins so there are likely more
