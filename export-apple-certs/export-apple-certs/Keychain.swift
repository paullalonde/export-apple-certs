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
	
	init(path: String) throws
	{
		var keychain: SecKeychain?
		let err = withUnsafeMutablePointer(to: &keychain) { SecKeychainOpen(path, UnsafeMutablePointer($0)) }
		
		if err != errSecSuccess {
			throw make_sec_error(err, "Cannot open keychain '\(path)'")
		}
		
		_keychain = keychain!
	}
	
	func SearchIdentities(maxResults: UInt? = 1) throws -> [KeychainIdentity]
	{
		let results = try Search(self, searchClass: .identity, maxResults: maxResults)
		
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
		let results = try Search(self, searchClass: .certificate, maxResults: maxResults)
		
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
		let results = try Search(self, searchClass: .key, maxResults: maxResults)
		
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
	
	fileprivate func Search(_ keychain: Keychain?, searchClass: KeychainSearchClass?, maxResults: UInt?) throws -> [KeychainSearchResult]
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
		let err = withUnsafeMutablePointer(to: &foundItemsAny) { SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0)) }
		
		if err != errSecSuccess {
			throw make_sec_error(err, "Cannot query keychain items")
		}
		
		if let foundItems = foundItemsAny as! [AnyObject]?
		{
			return try foundItems.map { foundItem -> KeychainSearchResult in
				let foundItemType = CFGetTypeID(foundItem)
				var value: KeychainSearchResult
				
				switch (foundItemType)
				{
				case SecCertificateGetTypeID():
					value = KeychainSearchResult.certificate(KeychainCertificate(foundItem as! SecCertificate))
				case SecKeyGetTypeID():
					value = KeychainSearchResult.key(KeychainKey(foundItem as! SecKey))
				case SecIdentityGetTypeID():
					value = KeychainSearchResult.identity(KeychainIdentity(foundItem as! SecIdentity))
				default:
					throw ExportError.unsupportedKeychainItemType
				}
				
				return value
			}
		}
		
		return []
	}
}
