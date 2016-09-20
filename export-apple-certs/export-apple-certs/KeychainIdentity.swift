//
//  KeychainIdentity.swift
//  export-apple-certs
//
//  Created by Paul Lalonde on 16-09-04.
//  Copyright © 2016 Paul Lalonde enrg. All rights reserved.
//

import Foundation


struct KeychainIdentity
{
	fileprivate let _identity: SecIdentity
	
	init(identity: SecIdentity)
	{
		_identity = identity;
	}
	
	var Ref: SecIdentity
	{
		get { return _identity }
	}
	
	var ItemRef: SecKeychainItem
	{
		get { return unsafeBitCast(_identity, to: SecKeychainItem.self) }
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getCertificate() throws -> KeychainCertificate
	{
		var certificate: SecCertificate?
		let err = withUnsafeMutablePointer(to: &certificate) { SecIdentityCopyCertificate(_identity, $0) }
		
		if err != errSecSuccess {
			throw make_sec_error(err, "Cannot retrieve identity's certificate")
		}
		
		return KeychainCertificate(certificate: certificate!)
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getKey() throws -> KeychainKey
	{
		var privateKey: SecKey?
		let err = withUnsafeMutablePointer(to: &privateKey) { SecIdentityCopyPrivateKey(_identity, $0) }
		
		if err != errSecSuccess {
			throw make_sec_error(err, "Cannot retrieve identity's private key")
		}
		
		return KeychainKey(key: privateKey!)
	}
}
