# export-apple-certs
A simple command-line utility for exporting an iTunes Connect user's Apple-supplied certificates.

Its main use case is to transfer certificates from one computer to another, 
for example from a developer's computer to a build machine.

The program reads the identities (ie, certificate + private key) from a given keychain, filters them according to specified criteria, 
then exports them to a PKCS#12 file. The program's arguments are as follows:

- **-k PATH** The path to the keychain to read from.
- **-o PATH** The path to the output (PKCS#12) file.
- **-p PASSWD** The password with which to encrypt the output file.
- **-t TEAMID** If present, filters the exported certificates according to the given iTunes Connect Team ID.
- **-u USER** If present, filters the exported certificates according to the given iTunes Connect user name.

### Things I haven't gotten around to doing yet

- Filtering according to target platform. For example, exporting macOS-related certificates only.
- Filtering according to environment. For example, exporting distribution certificates only.
- Validating that the certificates were actually issued by Apple.
