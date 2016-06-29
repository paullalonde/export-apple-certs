//
//  main.swift
//  export-apple-certs
//
//  Created by Paul Lalonde on 16-06-27.
//  Copyright © 2016 Paul Lalonde enrg. All rights reserved.
//

import CoreFoundation
import Foundation
import Security



var program_name = ""
var keychain_name = ""
var output_path = ""
var password = ""
var teamid = ""
var username = ""

private func main()
{
	var good = false
	
	do
	{
		parse_args()
		
		let keychain = try open_keychain(keychain_name)
		let identities = try read_identities(keychain)
		let exportedData = try export_identities(identities)
		
		try write_export_file(output_path, data: exportedData)
		
		good = true
	}
	catch let err as NSError
	{
		print("Error \(err.code) in \(err.domain) : \(err.localizedDescription)", terminator: "", toStream: &standardError)
		
		if let reason = err.localizedFailureReason
		{
			print(" : \(reason)", terminator: "", toStream: &standardError)
		}
		
		print("", toStream: &standardError)
	}
	
	if !good { exit(1) }
}

private func read_identities(keychain: SecKeychain) throws -> [SecIdentity]
{
	var filteredIdentities = [SecIdentity]()
	let keychainFilter = [keychain] as NSArray;
	
	let query: [String: AnyObject] = [
		kSecClass as String: kSecClassIdentity,
		kSecMatchLimit as String: kSecMatchLimitAll,
		kSecMatchSearchList as String: keychainFilter,
		//kSecReturnAttributes as String: kCFBooleanTrue,
		kSecReturnRef as String: kCFBooleanTrue,
		kSecReturnData as String: kCFBooleanTrue,
		]
	
	let foundIdentities = try query_keychain_items(query)
	
	for foundIdentityAny in foundIdentities
	{
		let foundIdentityNS = foundIdentityAny as! NSDictionary
		let foundIdentity = foundIdentityNS as! [String: AnyObject]
		
		if let identity = read_identity(foundIdentity) {
			filteredIdentities.append(identity)
		}
	}
	
	return filteredIdentities
}

private func read_identity(foundIdentity: [String: AnyObject?]) -> SecIdentity?
{
	let identity = foundIdentity[kSecValueRef as String] as! SecIdentity;
	
	if let certificate = try? read_certificate(identity)
	{
		if let privateKey = try? read_private_key(identity)
		{
			let certValueKeys: [CFString] = [
				//kSecOIDCommonName,
				//kSecOIDX509V1IssuerName,
				kSecOIDX509V1SubjectName,
			]
			
			// NB: If we get an error while reading the cert values, just skip this cert.
			
			if let certValues = try? read_certificate_values(certificate, keys: certValueKeys)
			{
				var goodSubjectName = true
				
				if let subjectName = read_sec_dict_key(certValues, key: kSecOIDX509V1SubjectName)
				{
					goodSubjectName = false
					
					if filter_subject_name(subjectName)
					{
						goodSubjectName = true
					}
				}
				
				if goodSubjectName
				{
					let summary = SecCertificateCopySubjectSummary(certificate) as String
					
					print("Exporting certificate : \(summary)")
					
					return identity
				}
			}
		}
	}
	
	return nil
}

private func filter_subject_name(subject: [String: AnyObject]) -> Bool
{
	let kOrganizationCase = kSecOIDOrganizationName as String
	let kOrganizationalUnitCase = kSecOIDOrganizationalUnitName as String
	var goodOrganization = false
	var goodOrganizationalUnit = false
	
	if username.isEmpty { goodOrganization = true }
	if teamid.isEmpty { goodOrganizationalUnit = true }
	
	if let subjectValueAny = subject[kSecPropertyKeyValue as String]
	{
		let subjectValueArrayNS = subjectValueAny as! NSArray
		let subjectValueArray = subjectValueArrayNS as! [NSDictionary]
		
		for subjectItemNS in subjectValueArray
		{
			let subjectItem = subjectItemNS as! [String: AnyObject]
			let itemLabel = subjectItem[kSecPropertyKeyLabel as String] as! String
			
			switch itemLabel
			{
			case kOrganizationCase:
				if !username.isEmpty
				{
					let organization = subjectItem[kSecPropertyKeyValue as String] as! String
					
					if organization == username
					{
						goodOrganization = true
					}
				}
				break
				
			case kOrganizationalUnitCase:
				if !teamid.isEmpty
				{
					let orgUnit = subjectItem[kSecPropertyKeyValue as String] as! String
					
					if orgUnit == teamid
					{
						goodOrganizationalUnit = true
					}
				}
				
			default:
				// There's nothing to do
				break
			}
		}
	}
	
	return goodOrganization && goodOrganizationalUnit
}

private func export_identities(identities: [SecIdentity]) throws -> NSData
{
	let identitiesArray = identities as NSArray
	let exportFlags = SecItemImportExportFlags.PemArmour
	let unmanagedPassword = Unmanaged<AnyObject>.passRetained(password)
	let unmanagedAlertTitle = Unmanaged<CFString>.passRetained("dummy alert title")
	let unmanagedAlertPrompt = Unmanaged<CFString>.passRetained("dummy alert prompt")
	
	var parameters = SecItemImportExportKeyParameters(version: UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION),
	                                                  flags: .NoAccessControl, passphrase: unmanagedPassword,
	                                                  alertTitle: unmanagedAlertTitle, alertPrompt: unmanagedAlertPrompt,
	                                                  accessRef: nil, keyUsage: nil, keyAttributes: nil)
	
	var dataOpt: CFData? = nil
	let err = withUnsafeMutablePointer(&dataOpt) { SecItemExport(identitiesArray, .FormatPKCS12, exportFlags, &parameters, UnsafeMutablePointer($0)) }
	
	if err != errSecSuccess {
		throw make_sec_error(err, "Cannot export identities")
	}
	
	let data = dataOpt!
	
	return data as NSData;
}

private func open_keychain(path: String) throws -> SecKeychain
{
	var keychain: SecKeychainRef?
	let err = withUnsafeMutablePointer(&keychain) { SecKeychainOpen(path, UnsafeMutablePointer($0)) }
	
	if err != errSecSuccess {
		throw make_sec_error(err, "Cannot open keychain '\(path)'")
	}
	
	return keychain!
}

private func query_keychain_items(query: [String: AnyObject]) throws -> [AnyObject]
{
	var foundIdentitiesAny: AnyObject?
	let err = withUnsafeMutablePointer(&foundIdentitiesAny) { SecItemCopyMatching(query, UnsafeMutablePointer($0)) }
	
	if err != errSecSuccess {
		throw make_sec_error(err, "Cannot query keychain items")
	}
	
	if let foundIdentities = foundIdentitiesAny as! [AnyObject]? {
		return foundIdentities
	} else {
		return []
	}
}

private func read_certificate(identity: SecIdentity) throws -> SecCertificate
{
	var certificate: SecCertificate?
	let err = withUnsafeMutablePointer(&certificate) { SecIdentityCopyCertificate(identity, UnsafeMutablePointer($0)) }
	
	if err != errSecSuccess {
		throw make_sec_error(err, "Cannot retrieve identity's certificate")
	}
	
	return certificate!
}

private func read_private_key(identity: SecIdentity) throws -> SecKey
{
	var privateKey: SecKey?
	let err = withUnsafeMutablePointer(&privateKey) { SecIdentityCopyPrivateKey(identity, UnsafeMutablePointer($0)) }
	
	if err != errSecSuccess {
		throw make_sec_error(err, "Cannot retrieve identity's private key")
	}
	
	return privateKey!
}

private func read_certificate_values(certificate: SecCertificate, keys: [CFString]) throws -> [String: AnyObject]
{
	var unmanagedErrorOpt: Unmanaged<CFError>?
	let certValuesAnyOpt = withUnsafeMutablePointer(&unmanagedErrorOpt) { SecCertificateCopyValues(certificate, keys, UnsafeMutablePointer($0)) }
	
	if let unmanagedError = unmanagedErrorOpt
	{
		let cfError : CFError = unmanagedError.takeRetainedValue()
		
		throw make_error(cfError)
	}
	
	if let certValuesAny = certValuesAnyOpt
	{
		let certValuesNS = certValuesAny as NSDictionary
		let certValues = certValuesNS as! [String: AnyObject]
		
		return certValues;
	}
	
	return [:]
}

private func read_sec_dict_key(dict: [String: AnyObject], key: CFString) -> [String: AnyObject]?
{
	let valueAnyOpt = dict[key as String]
	
	if let valueAny = valueAnyOpt
	{
		if let valueNS = valueAny as? NSDictionary
		{
			if let value = valueNS as? [String: AnyObject]
			{
				return value
			}
		}
	}
	
	return nil
}

func write_export_file(path: String, data: NSData) throws
{
	try data.writeToFile(path, options: .DataWritingAtomic)
}

func make_sec_error(err: OSStatus, _ message: String) -> NSError
{
	var userInfo: [NSObject : AnyObject] = [
		kCFErrorLocalizedDescriptionKey: message,
	]
	
	if let reason = SecCopyErrorMessageString(err, UnsafeMutablePointer<Void>(bitPattern: 0))
	{
		userInfo[kCFErrorLocalizedFailureReasonKey] = reason
	}
	
	let error = NSError(domain: kCFErrorDomainOSStatus as String, code: Int(err), userInfo: userInfo)
	
	return error
}

func make_error(err: CFError) -> NSError
{
	let domain = CFErrorGetDomain(err) as String
	let code = CFErrorGetCode(err)
	let userInfoNS = CFErrorCopyUserInfo(err) as NSDictionary
	let userInfo = userInfoNS as! [NSObject : AnyObject]
	
	let error = NSError(domain: domain as String, code: code, userInfo: userInfo)
	
	return error
}

private func parse_args()
{
	program_name = Process.arguments[0]
	
	var longopts = [option]()
	
	longopts.append(make_option_with_arg("keychain", letter: "k"))
	longopts.append(make_option_with_arg("output",   letter: "o"))
	longopts.append(make_option_with_arg("password", letter: "p"))
	longopts.append(make_option_with_arg("teamid",   letter: "t"))
	longopts.append(make_option_with_arg("user",     letter: "u"))
	longopts.append(option())

	while true
	{
		let c = getopt_long(Process.argc, Process.unsafeArgv, "k:o:p:t:u:", longopts, nil)
		
		if c < 0 { break }
		
		switch String(UnicodeScalar(UInt32(c))) {
		case "k":
			keychain_name = fetch_required_arg()
			
		case "o":
			output_path = fetch_required_arg()
			
		case "p":
			password = fetch_required_arg()
			
		case "t":
			teamid = fetch_required_arg()
			
		case "u":
			username = fetch_required_arg()
			
		default:
			usage()
		}
	}
	
	if keychain_name.isEmpty { usage(); }
	if output_path.isEmpty { usage(); }
	if password.isEmpty { usage(); }
	if teamid.isEmpty && username.isEmpty { usage(); }
}

private func make_option_with_arg(name: String, letter: String) -> option
{
	let value = Int32(letter.unicodeScalars.first!.value)
	
	return option(name: name, has_arg: required_argument, flag: nil, val: value)
}

private func fetch_required_arg() -> String
{
	let arg = String.fromCString(UnsafePointer<CChar>(optarg))
	
	if arg == nil { usage(); }
	
	// Since usage() doesn't return, then if we got here it means that arg isn't nil.
	
	return arg!
}

private func usage()
{
	print("Usage: export-apple-certs <options>")
	print("Options:")
	print(" -k, --keychain FILE    The path to the keychain to export from.")
	print(" -o, --output FILE      The path to the file into which to export the certificates.")
	print(" -p, --password PASSWD  The password with which to protect the exported certificate file.")
	print(" -t, --teamid STRING    Filters the exported certificates according to the given iTunes Connect Team ID.")
	print(" -u, --user USER        Filters the exported certificates according to the given iTunes Connect user name.")
	
	exit(2)
}

public struct StderrOutputStream: OutputStreamType {
	public static let stream = StderrOutputStream()
	public func write(string: String) {fputs(string, stderr)}
}

public var standardError = StderrOutputStream.stream

main()
