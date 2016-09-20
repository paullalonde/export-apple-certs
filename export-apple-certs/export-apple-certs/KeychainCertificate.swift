//
//  KeychainCertificate.swift
//  export-apple-certs
//
//  Created by Paul Lalonde on 16-09-04.
//  Copyright © 2016 Paul Lalonde enrg. All rights reserved.
//

import Foundation


struct KeychainCertificate
{
	fileprivate let _certificate: SecCertificate
	
	fileprivate static let IOSAppDevelopmentOID         = "1.2.840.113635.100.6.1.2"
	fileprivate static let AppStoreOID                  = "1.2.840.113635.100.6.1.4"
	fileprivate static let MacDevelopmentOID            = "1.2.840.113635.100.6.1.12"
	fileprivate static let MacAppDistributionOID        = "1.2.840.113635.100.6.1.7"
	fileprivate static let MacInstallerDistributionOID  = "1.2.840.113635.100.6.1.8"
	fileprivate static let DeveloperIdOID               = "1.2.840.113635.100.6.1.13"
	fileprivate static let DeveloperIdInstallerOID      = "1.2.840.113635.100.6.1.14"
	
	init(certificate: SecCertificate)
	{
		_certificate = certificate;
	}
	
	var ItemRef: SecKeychainItem
	{
		get { return unsafeBitCast(_certificate, to: SecKeychainItem.self) }
	}
	
	var SubjectSummary : String
	{
		get {
			return SecCertificateCopySubjectSummary(_certificate) as String
		}
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getSubjectName() throws -> KeychainCertificateSubjectName?
	{
		if let property = try ReadProperty(key: kSecOIDX509V1SubjectName)
		{
			return KeychainCertificateSubjectName(property: property)
		}
		
		return nil
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getIsDevelopment() throws -> Bool
	{
		return try (getIsAppStoreDevelopment() ||
					getIsMacAppStoreDevelopment())
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getIsProduction() throws -> Bool
	{
		return try (getIsAppStoreDistribution()     ||
					getIsMacAppStoreDistribution()  ||
					getIsMacInstallerDistribution() ||
					getIsDeveloperId()              ||
					getIsDeveloperIdInstaller())
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getIsAppStore() throws -> Bool
	{
		return try (getIsAppStoreDevelopment() ||
					getIsAppStoreDistribution())
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getIsMacAppStore() throws -> Bool
	{
		return try (getIsMacAppStoreDevelopment()  ||
					getIsMacAppStoreDistribution() ||
					getIsMacInstallerDistribution())
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getIsNonMacAppStore() throws -> Bool
	{
		return try (getIsDeveloperId() ||
					getIsDeveloperIdInstaller())
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getIsAppStoreDevelopment() throws -> Bool
	{
		return try ReadProperty(key: KeychainCertificate.IOSAppDevelopmentOID as CFString) != nil
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getIsAppStoreDistribution() throws -> Bool
	{
		return try ReadProperty(key: KeychainCertificate.AppStoreOID as CFString) != nil
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getIsMacAppStoreDevelopment() throws -> Bool
	{
		return try ReadProperty(key: KeychainCertificate.MacDevelopmentOID as CFString) != nil
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getIsMacAppStoreDistribution() throws -> Bool
	{
		return try ReadProperty(key: KeychainCertificate.MacAppDistributionOID as CFString) != nil
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getIsMacInstallerDistribution() throws -> Bool
	{
		return try ReadProperty(key: KeychainCertificate.MacInstallerDistributionOID as CFString) != nil
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getIsDeveloperId() throws -> Bool
	{
		return try ReadProperty(key: KeychainCertificate.DeveloperIdOID as CFString) != nil
	}
	
	// TODO: this should be a computed property, but they can't throw (yet)
	func getIsDeveloperIdInstaller() throws -> Bool
	{
		return try ReadProperty(key: KeychainCertificate.DeveloperIdInstallerOID as CFString) != nil
	}
	
	fileprivate func ReadProperty(key: CFString) throws -> KeychainCertificateProperty?
	{
		let keys: [CFString] = [ key ]
		var unmanagedErrorOpt: Unmanaged<CFError>?
		let certValuesAnyOpt = withUnsafeMutablePointer(to: &unmanagedErrorOpt) { SecCertificateCopyValues(_certificate, keys as CFArray?, $0) }
		
		if let unmanagedError = unmanagedErrorOpt
		{
			let cfError : CFError = unmanagedError.takeRetainedValue()
			
			throw make_error(cfError)
		}
		
		if let certValuesAny = certValuesAnyOpt
		{
			let certValuesNS = certValuesAny as NSDictionary
			let certValues = certValuesNS as! [String: AnyObject]
			let valueAnyOpt = certValues[key as String]
			
			if let valueAny = valueAnyOpt
			{
				if let valueNS = valueAny as? NSDictionary
				{
					if let value = valueNS as? [String: AnyObject]
					{
						return KeychainCertificateProperty(entry: value)
					}
				}
			}
		}
		
		return nil
	}
}

struct KeychainCertificateSubjectName
{
	fileprivate let _properties: [KeychainCertificateProperty]
	
	init(property: KeychainCertificateProperty)
	{
		let subjectValueArrayNS = property.Value as! NSArray
		let subjectValueArray = subjectValueArrayNS as! [NSDictionary]
		
		_properties = subjectValueArray.map {
			let subjectItem = $0 as! [String: AnyObject]
			
			return KeychainCertificateProperty(entry: subjectItem)
		}
	}
	
	var OrganizationName: String?
	{
		get
		{
			return FindString(label: kSecOIDOrganizationName)
		}
	}
	
	var OrganizationalUnitName: String?
	{
		get
		{
			return FindString(label: kSecOIDOrganizationalUnitName)
		}
	}
	
	fileprivate func FindString(label: CFString) -> String?
	{
		if let property = Find(label: label)
		{
			if let value = property.Value as? String
			{
				return value
			}
		}
		
		return nil
	}
	
	fileprivate func Find(label: CFString) -> KeychainCertificateProperty?
	{
		let labelString = label as String
		let foundIndexOpt = _properties.index { $0.Label == labelString }
		
		if let foundIndex = foundIndexOpt
		{
			return _properties[foundIndex]
		}
		
		return nil
	}
}

struct KeychainCertificateProperty
{
	fileprivate let _entry: [String: AnyObject]
	
	init(entry: [String: AnyObject])
	{
		_entry = entry;
	}
	
	var Label: String
	{
		get
		{
			return _entry[kSecPropertyKeyLabel as String] as! String
		}
	}
	
	var LocalizedLabel: String
	{
		get
		{
			return _entry[kSecPropertyKeyLocalizedLabel as String] as! String
		}
	}
	
	var Value: AnyObject
	{
		get
		{
			return _entry[kSecPropertyKeyValue as String]!
		}
	}
}
