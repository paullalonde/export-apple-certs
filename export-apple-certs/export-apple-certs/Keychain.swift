//
//  Keychain.swift
//  export-apple-certs
//
//  Created by Paul Lalonde on 16-09-04.
//  Copyright © 2016 Paul Lalonde enrg. All rights reserved.
//

import Foundation



enum KeychainSearchClass
{
	case internetPassword
	case genericPassword
	case certificate
	case key
	case identity
}

enum KeychainSearchResult
{
	case certificate(KeychainCertificate)
	case key(KeychainKey)
	case identity(KeychainIdentity)
}

struct Keychain
{
	fileprivate let _keychain: SecKeychain
	
	static func Open(path: String) throws -> Keychain
	{
		var keychain: SecKeychain?
		let err = withUnsafeMutablePointer(to: &keychain) { SecKeychainOpen(path, $0) }
		
		if err != errSecSuccess {
			throw make_sec_error(err, "Cannot open keychain '\(path)'")
		}
		
		return Keychain(keychain: keychain!)
	}
	
	static func Create(path: String, password: String) throws -> Keychain
	{
		var keychain: SecKeychain?
		let err = withUnsafeMutablePointer(to: &keychain) { (unsafeKeychain) -> OSStatus in
			let buffer = [UInt8](password.utf8)
			let unsafeBuffer = UnsafePointer<UInt8>(buffer)
			let unsafeRaw = UnsafeRawPointer(unsafeBuffer)
			let buflen = UInt32(buffer.count)
			
			return SecKeychainCreate(path, buflen, unsafeRaw, false, nil, unsafeKeychain)
		}
		
		if err != errSecSuccess {
			throw make_sec_error(err, "Cannot create keychain '\(path)'")
		}
		
		return Keychain(keychain: keychain!)
	}
	
	init(keychain: SecKeychain)
	{
		_keychain = keychain
	}
	
	func Delete() throws
	{
		let err = SecKeychainDelete(_keychain)
		
		if err != errSecSuccess {
			throw make_sec_error(err, "Cannot delete keychain '\(_keychain)'")
		}
	}
	
	func SearchIdentities(maxResults: UInt? = 1) throws -> [KeychainIdentity]
	{
		let results = try Search(keychain: self, searchClass: .identity, maxResults: maxResults)
		
		return try results.map {
			switch ($0)
			{
			case .identity(let identity):
				return identity
			default:
				throw ExportError.unsupportedKeychainItemType
			}
		}
	}
	
	func SearchCertificates(maxResults: UInt? = 1) throws -> [KeychainCertificate]
	{
		let results = try Search(keychain: self, searchClass: .certificate, maxResults: maxResults)
		
		return try results.map {
			switch ($0)
			{
			case .certificate(let certificate):
				return certificate
			default:
				throw ExportError.unsupportedKeychainItemType
			}
		}
	}
	
	func SearchKeys(maxResults: UInt? = 1) throws -> [KeychainKey]
	{
		let results = try Search(keychain: self, searchClass: .key, maxResults: maxResults)
		
		return try results.map {
			switch ($0)
			{
			case .key(let key):
				return key
			default:
				throw ExportError.unsupportedKeychainItemType
			}
		}
	}
	
	fileprivate func Search(keychain: Keychain?, searchClass: KeychainSearchClass?, maxResults: UInt?) throws -> [KeychainSearchResult]
	{
		var query: [String: AnyObject] = [
			kSecReturnRef as String: kCFBooleanTrue,
		]
		
		// Filter by keychain.
		
		if let itemKeychain = keychain
		{
			let itemKeychainFilter = [itemKeychain._keychain] as NSArray
			
			query[kSecMatchSearchList as String] = itemKeychainFilter
		}
		
		// Filter by item class.
		
		if let itemClass = searchClass
		{
			var classValue: CFString
			
			switch itemClass
			{
			case .internetPassword:
				classValue = kSecClassInternetPassword
			case .genericPassword:
				classValue = kSecClassGenericPassword
			case .certificate:
				classValue = kSecClassCertificate
			case .key:
				classValue = kSecClassKey
			case .identity:
				classValue = kSecClassIdentity
			}
			
			query[kSecClass as String] = classValue
		}
		
		// Limit the number of results.
		
		let limitKey = kSecMatchLimit as String
		
		if let itemLimit = maxResults
		{
			if itemLimit == 1
			{
				query[limitKey] = kSecMatchLimitOne
			}
			else
			{
				query[limitKey] = itemLimit as NSNumber
			}
		}
		else
		{
			query[limitKey] = kSecMatchLimitAll
		}
		
		// Perform the search.
		
		var foundItemsAny: AnyObject?
		let err = withUnsafeMutablePointer(to: &foundItemsAny) { SecItemCopyMatching(query as CFDictionary, $0) }
		
		if err != errSecSuccess {
			throw make_sec_error(err, "Cannot query keychain items")
		}
		
		if let foundItems = foundItemsAny as! [AnyObject]?
		{
			return try foundItems.map { try Keychain.MakeSearchResult(obj: $0) }
		}
		
		return []
	}
	
	private static func MakeSearchResult(obj: AnyObject) throws -> KeychainSearchResult
	{
		let objType = CFGetTypeID(obj)
		var value: KeychainSearchResult
		
		switch (objType)
		{
		case SecCertificateGetTypeID():
			value = KeychainSearchResult.certificate(KeychainCertificate(certificate: obj as! SecCertificate))
		case SecKeyGetTypeID():
			value = KeychainSearchResult.key(KeychainKey(key: obj as! SecKey))
		case SecIdentityGetTypeID():
			value = KeychainSearchResult.identity(KeychainIdentity(identity: obj as! SecIdentity))
		default:
			throw ExportError.unsupportedKeychainItemType
		}
		
		return value
	}
	
	func Export(identity: KeychainIdentity, password: String) throws -> Data
	{
		return try Export(item: identity.ItemRef, password: password)
	}
	
	func Export(item: SecKeychainItem, password: String) throws -> Data
	{
		let exportFlags = SecItemImportExportFlags.pemArmour
		let unmanagedPassword = Unmanaged<AnyObject>.passRetained(password as AnyObject)
		let unmanagedAlertTitle = Unmanaged<CFString>.passRetained("dummy alert title" as CFString)
		let unmanagedAlertPrompt = Unmanaged<CFString>.passRetained("dummy alert prompt" as CFString)
		
		var parameters = SecItemImportExportKeyParameters(version: UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION),
		                                                  flags: .noAccessControl, passphrase: unmanagedPassword,
		                                                  alertTitle: unmanagedAlertTitle, alertPrompt: unmanagedAlertPrompt,
		                                                  accessRef: nil, keyUsage: nil, keyAttributes: nil)
		
		var dataOpt: CFData? = nil
		let err = withUnsafeMutablePointer(to: &dataOpt) { SecItemExport(item, .formatPKCS12, exportFlags, &parameters, $0) }
		
		if err != errSecSuccess {
			throw make_sec_error(err, "Cannot export identities")
		}
		
		let data = dataOpt!
		
		return data as Data;
	}
	
	func Import(data: Data, password: String) throws -> [KeychainSearchResult]
	{
		let unmanagedPassword = Unmanaged<AnyObject>.passRetained(password as AnyObject)
		let unmanagedAlertTitle = Unmanaged<CFString>.passRetained("dummy alert title" as CFString)
		let unmanagedAlertPrompt = Unmanaged<CFString>.passRetained("dummy alert prompt" as CFString)
		
		var parameters = SecItemImportExportKeyParameters(version: UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION),
		                                                  flags: .noAccessControl, passphrase: unmanagedPassword,
		                                                  alertTitle: unmanagedAlertTitle, alertPrompt: unmanagedAlertPrompt,
		                                                  accessRef: nil, keyUsage: nil, keyAttributes: nil)
		
		var itemsOpt: CFArray?
		let err = withUnsafeMutablePointer(to: &itemsOpt)
		{
			(items) -> OSStatus in
			var inputFormatArg: SecExternalFormat = .formatPKCS12
			
			return withUnsafeMutablePointer(to: &inputFormatArg)
			{
				(inputFormat) -> OSStatus in
				
				return SecItemImport(data as CFData, nil, inputFormat, nil, .pemArmour, &parameters, _keychain, items)
			}
		}
		
		if err != errSecSuccess {
			throw make_sec_error(err, "Cannot import keychain items")
		}
		
		if let importedItems = itemsOpt as [AnyObject]?
		{
			return try importedItems.map { try Keychain.MakeSearchResult(obj: $0) }
		}
		
		return []
	}
}
