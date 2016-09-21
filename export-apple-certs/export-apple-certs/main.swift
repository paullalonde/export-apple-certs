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


enum CertificateTypeFilter
{
	case all
	case iosAppStore
	case macAppStore
	case developerId
}

enum EnvironmentFilter
{
	case all
	case development
	case production
}

var program_name = ""
var source_keychain_path = ""
var force_destination = false
var dest_keychain_path = ""
var dest_keychain_password = ""
var teamid = ""
var username = ""
var certificateTypeFilter = CertificateTypeFilter.all
var environmentFilter = EnvironmentFilter.all


private func main()
{
	var good = false
	
	do
	{
		parse_args()
		
		let sourceKeychain = try Keychain.Open(path: source_keychain_path)
		
		if force_destination
		{
			if let existingKeychain = try? Keychain.Open(path: dest_keychain_path)
			{
				try? existingKeychain.Delete()
			}
		}
		
		let destKeychain = try Keychain.Create(path: dest_keychain_path, password: dest_keychain_password)
		
		let identities = try sourceKeychain.SearchIdentities(maxResults: nil)
		let filteredIdentities = try identities.filter { try filter_identity(identity: $0) }
		
		let newIdentities = try filteredIdentities.map { try copy_identity(source: $0, from: sourceKeychain, to: destKeychain) }
		
		good = true
	}
	catch let err as NSError
	{
		print("Error \(err.code) in \(err.domain) : \(err.localizedDescription)", terminator: "", to: &standardError)
		
		if let reason = err.localizedFailureReason
		{
			print(" : \(reason)", terminator: "", to: &standardError)
		}
		
		print("", to: &standardError)
	}
	
	if !good { exit(1) }
}

private func filter_identity(identity: KeychainIdentity) throws -> Bool
{
	if let certificate = try? identity.getCertificate()
	{
		if (try? identity.getKey()) != nil
		{
			if try !filter_certificate_type(certificate: certificate, certificateTypeFilter: certificateTypeFilter)
			{
				return false
			}
			
			if try !filter_environment(certificate: certificate, environmentFilter: environmentFilter)
			{
				return false
			}
			
			if try !filter_organization(certificate: certificate, orgName: username)
			{
				return false
			}
			
			if try !filter_orgunit(certificate: certificate, orgUnit: teamid)
			{
				return false
			}
			
			return true
		}
	}
	
	return false
}

private func filter_certificate_type(certificate: KeychainCertificate, certificateTypeFilter: CertificateTypeFilter) throws -> Bool
{
	switch certificateTypeFilter {
	case .iosAppStore:
		return try certificate.getIsAppStore()
		
	case .macAppStore:
		return try certificate.getIsMacAppStore()
		
	case .developerId:
		return try certificate.getIsNonMacAppStore()
		
	default:
		return true
	}
}

private func filter_environment(certificate: KeychainCertificate, environmentFilter: EnvironmentFilter) throws -> Bool
{
	switch environmentFilter {
	case .development:
		return try certificate.getIsDevelopment()
	case .production:
		return try certificate.getIsProduction()
	case .all:
		return true
	}
}

private func filter_organization(certificate: KeychainCertificate, orgName: String) throws -> Bool
{
	if orgName.isEmpty { return true }
	
	if let subjectName = try certificate.getSubjectName()
	{
		if let organization = subjectName.OrganizationName
		{
			return (organization == orgName)
		}
	}
	
	return false
}

private func filter_orgunit(certificate: KeychainCertificate, orgUnit: String) throws -> Bool
{
	if orgUnit.isEmpty { return true }
	
	if let subjectName = try certificate.getSubjectName()
	{
		if let organizationalUnit = subjectName.OrganizationalUnitName
		{
			return (organizationalUnit == orgUnit)
		}
	}
	
	return false
}

private func copy_identity(source: KeychainIdentity, from: Keychain, to: Keychain) throws -> KeychainIdentity
{
	let certificate = try source.getCertificate()
	let summary = certificate.SubjectSummary
	
	print("Exporting : \(summary)")
	
	let password = "bachibouzouk"
	let data = try from.Export(identity: source, password: password)
	
	let exported = try to.Import(data: data, password: password)
	
	switch exported[0] {
	case .identity(let newIdentity):
		return newIdentity
	default:
		throw ExportError.unsupportedKeychainItemType
	}
}


func make_sec_error(_ err: OSStatus, _ message: String) -> NSError
{
	var userInfo: [NSObject : AnyObject] = [
		kCFErrorLocalizedDescriptionKey: message as AnyObject,
	]
	
	if let reason = SecCopyErrorMessageString(err, UnsafeMutableRawPointer(bitPattern: 0))
	{
		userInfo[kCFErrorLocalizedFailureReasonKey] = reason
	}
	
	let error = NSError(domain: kCFErrorDomainOSStatus as String, code: Int(err), userInfo: userInfo)
	
	return error
}

func make_error(_ err: CFError) -> NSError
{
	let domain = CFErrorGetDomain(err) as String
	let code = CFErrorGetCode(err)
	let userInfoNS = CFErrorCopyUserInfo(err) as NSDictionary
	let userInfo = userInfoNS as [NSObject : AnyObject]
	
	let error = NSError(domain: domain as String, code: code, userInfo: userInfo)
	
	return error
}

enum ExportError : Error
{
	case unsupportedKeychainItemType
}

private func parse_args()
{
	program_name = CommandLine.arguments[0]
	
	var longopts = [option]()
	
	longopts.append(make_option_with_arg("cert",     letter: "c"))
	longopts.append(make_option_with_arg("env",      letter: "e"))
	longopts.append(make_option_no_arg  ("force",    letter: "f"))
	longopts.append(make_option_with_arg("keychain", letter: "k"))
	longopts.append(make_option_with_arg("output",   letter: "o"))
	longopts.append(make_option_with_arg("password", letter: "p"))
	longopts.append(make_option_with_arg("teamid",   letter: "t"))
	longopts.append(make_option_with_arg("user",     letter: "u"))
	longopts.append(option())

	while true
	{
		let c = getopt_long(CommandLine.argc, CommandLine.unsafeArgv, "c:e:fk:o:p:t:u:", longopts, nil)
		
		if c < 0 { break }
		
		let char = Character(UnicodeScalar(UInt32(c))!)
		
		switch String(char) {
		case "c":
			switch fetch_required_arg() {
			case "all":
				certificateTypeFilter = .all
			case "ios":
				certificateTypeFilter = .iosAppStore
			case "mac":
				certificateTypeFilter = .macAppStore
			case "devid":
				certificateTypeFilter = .developerId
			default:
				usage()
			}
			
		case "e":
			switch fetch_required_arg() {
			case "all":
				environmentFilter = .all
			case "dev":
				environmentFilter = .development
			case "prod":
				environmentFilter = .production
			default:
				usage()
			}
			
		case "f":
			force_destination = true
			
		case "k":
			source_keychain_path = fetch_required_arg()
			
		case "o":
			dest_keychain_path = fetch_required_arg()
			
		case "p":
			dest_keychain_password = fetch_required_arg()
			
		case "t":
			teamid = fetch_required_arg()
			
		case "u":
			username = fetch_required_arg()
			
		default:
			usage()
		}
	}
	
	if source_keychain_path.isEmpty { usage(); }
	if dest_keychain_path.isEmpty { usage(); }
	if dest_keychain_password.isEmpty { usage(); }
	if teamid.isEmpty && username.isEmpty { usage(); }
}

private func make_option_no_arg(_ name: String, letter: String) -> option
{
	let value = Int32(letter.unicodeScalars.first!.value)
	
	return option(name: name, has_arg: no_argument, flag: nil, val: value)
}

private func make_option_with_arg(_ name: String, letter: String) -> option
{
	let value = Int32(letter.unicodeScalars.first!.value)
	
	return option(name: name, has_arg: required_argument, flag: nil, val: value)
}

private func fetch_required_arg() -> String
{
	let arg = String(cString: UnsafePointer<CChar>(optarg))
	
	//if arg == nil { usage(); }
	//
	//// Since usage() doesn't return, then if we got here it means that arg isn't nil.
	
	return arg
}

private func usage()
{
	print("Usage: export-apple-certs <options>")
	print("Options:")
	print(" -c, --cert TYPE        The type of certificate. Allowed values are :")
	print("                          - all      All certificates types (the default).")
	print("                          - ios      Certificates for iOS, tvOS and watchOS applications.")
	print("                          - mac      Certificates for Mac App Store applications.")
	print("                          - devid    Certificates for Developer ID applications.")
	print(" -e, --env ENV          The environment. Allowed values are :")
	print("                          - all      All environments (the default).")
	print("                          - dev      Development environment.")
	print("                          - prod     Production environment.")
	print(" -f                     Remove any existing destination keychain.")
	print(" -k, --keychain PATH    The path to the source keychain.")
	print(" -o, --output PATH      The path to the destination keychain.")
	print(" -p, --password PASSWD  The password with which to protect the destination keychain.")
	print(" -t, --teamid TEAMID    Filters the exported certificates according to the given iTunes Connect Team ID.")
	print(" -u, --user USER        Filters the exported certificates according to the given iTunes Connect user name.")
	
	exit(2)
}

public struct StderrOutputStream: TextOutputStream {
	public static let stream = StderrOutputStream()
	public func write(_ string: String) {fputs(string, stderr)}
}

public var standardError = StderrOutputStream.stream

main()
