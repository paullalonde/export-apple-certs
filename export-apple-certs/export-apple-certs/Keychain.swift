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
	case InternetPassword
	case GenericPassword
	case Certificate
	case Key
	case Identity
}

enum KeychainSearchResult
{
	case Certificate(KeychainCertificate)
	case Key(KeychainKey)
	case Identity(KeychainIdentity)
}

struct Keychain
{
	private let _keychain: SecKeychain
	
	init(path: String) throws
	{
		var keychain: SecKeychainRef?
		let err = withUnsafeMutablePointer(&keychain) { SecKeychainOpen(path, UnsafeMutablePointer($0)) }
		
		if err != errSecSuccess {
			throw make_sec_error(err, "Cannot open keychain '\(path)'")
		}
		
		_keychain = keychain!
	}
	
	func SearchIdentities(maxResults maxResults: UInt? = 1) throws -> [KeychainIdentity]
	{
		let results = try Search(self, searchClass: .Identity, maxResults: maxResults)
		
		return try results.map {
			switch ($0)
			{
			case .Identity(let identity):
				return identity
			default:
				throw ExportError.UnsupportedKeychainItemType
			}
		}
	}
	
	func SearchCertificates(maxResults maxResults: UInt? = 1) throws -> [KeychainCertificate]
	{
		let results = try Search(self, searchClass: .Certificate, maxResults: maxResults)
		
		return try results.map {
			switch ($0)
			{
			case .Certificate(let certificate):
				return certificate
			default:
				throw ExportError.UnsupportedKeychainItemType
			}
		}
	}
	
	func SearchKeys(maxResults maxResults: UInt? = 1) throws -> [KeychainKey]
	{
		let results = try Search(self, searchClass: .Key, maxResults: maxResults)
		
		return try results.map {
			switch ($0)
			{
			case .Key(let key):
				return key
			default:
				throw ExportError.UnsupportedKeychainItemType
			}
		}
	}
	
	private func Search(keychain: Keychain?, searchClass: KeychainSearchClass?, maxResults: UInt?) throws -> [KeychainSearchResult]
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
			case .InternetPassword:
				classValue = kSecClassInternetPassword
			case .GenericPassword:
				classValue = kSecClassGenericPassword
			case .Certificate:
				classValue = kSecClassCertificate
			case .Key:
				classValue = kSecClassKey
			case .Identity:
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
		let err = withUnsafeMutablePointer(&foundItemsAny) { SecItemCopyMatching(query, UnsafeMutablePointer($0)) }
		
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
					value = KeychainSearchResult.Certificate(KeychainCertificate(foundItem as! SecCertificate))
				case SecKeyGetTypeID():
					value = KeychainSearchResult.Key(KeychainKey(foundItem as! SecKey))
				case SecIdentityGetTypeID():
					value = KeychainSearchResult.Identity(KeychainIdentity(foundItem as! SecIdentity))
				default:
					throw ExportError.UnsupportedKeychainItemType
				}
				
				return value
			}
		}
		
		return []
	}
}