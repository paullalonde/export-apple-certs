# export-apple-certs
A command-line utility that extracts Apple-issued signing identities (i.e. certificates and private keys) from a keychain.

Its main use case is to transfer signing identities from one computer to another, 
for example from a developer's computer to a build machine.

The program reads the identities from a given keychain, 
filters them according to specified criteria, 
then copies them to a second keychain. 
Note that the newly-copied identities don't have any access control, 
therefore any application can access their private keys as long the the keychain is unlocked. 
This is useful in CI scenarios.

The program's arguments are as follows:

<dl>
	<dt>-c TYPE</dt>
	<dd>Filters the exported certificates according to their type. Allowed values are :
		<ul>
			<li><strong>all</strong> All certificates types (the default).</li>
			<li><strong>ios</strong> Certificates for iOS, tvOS and watchOS applications</li>
			<li><strong>mac</strong> Certificates for Mac App Store applications.</li>
			<li><strong>devid</strong> Certificates for Developer ID applications.</li>
		</ul>
	</dd>
	<dt>-e ENV</dt>
	<dd>Filters the exported certificates according to the environment. Allowed values are :
		<ul>
			<li><strong>all</strong> All environments (the default).</li>
			<li><strong>dev</strong> Development environment</li>
			<li><strong>prod</strong> Production environment.</li>
		</ul>
	</dd>
	<dt>-f</dt>
	<dd>Remove any existing destination keychain.</dd>
	<dt>-k PATH</dt>
	<dd>The path to the source keychain.</dd>
	<dt>-o PATH</dt>
	<dd>The path to the destination keychain.</dd>
	<dt>-p PASSWD</dt>
	<dd>The password with which to protect the destination keychain.</dd>
	<dt>-t TEAMID</dt>
	<dd>Filters the exported certificates according to the given Apple Developer Program (ADP) Team ID.</dd>
	<dt>-u USER</dt>
	<dd>Filters the exported certificates according to the given ADP user name.</dd>
</dl>

### Things I haven't gotten around to doing yet

- Validating that the certificates were actually issued by Apple.
- Validating that the certificates are valid and haven't been revoked.
- Validating the key usage.
