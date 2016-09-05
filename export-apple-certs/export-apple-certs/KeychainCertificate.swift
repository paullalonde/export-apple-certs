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
	
	init(certificate: SecCertificate)
	{
		_certificate = certificate;
	}
	
	var SubjectSummary : String
	{
		get {
			return SecCertificateCopySubjectSummary(_certificate) as String
		}
	}
	
	// note: this should be a computed property, but they can't throw (yet)
	func getSubjectName() throws -> KeychainCertificateSubjectName?
	{
		if let property = try ReadProperty(key: kSecOIDX509V1SubjectName)
		{
			return KeychainCertificateSubjectName(property: property)
		}
		
		return nil
	}
	
	fileprivate func ReadProperty(key: CFString) throws -> KeychainCertificateProperty?
	{
		let keys: [CFString] = [ key ]
		var unmanagedErrorOpt: Unmanaged<CFError>?
		let certValuesAnyOpt = withUnsafeMutablePointer(to: &unmanagedErrorOpt) { SecCertificateCopyValues(_certificate, keys as CFArray?, UnsafeMutablePointer($0)) }
		
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
