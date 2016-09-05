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
		
		let keychain = try Keychain(path: keychain_name);
		let identities = try keychain.SearchIdentities(maxResults: nil)
		let filteredIdentities = try identities.filter { try filter_identity(identity: $0) }
		let exportedData = try export_identities(identities: filteredIdentities)
		
		try write_export_file(path: output_path, data: exportedData)
		
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
			if let subjectName = try certificate.getSubjectName()
			{
				var goodOrganization = true
				var goodOrganizationalUnit = true
				
				if !username.isEmpty
				{
					goodOrganization = false
					
					if let organization = subjectName.OrganizationName
					{
						goodOrganization = (organization == username)
					}
				}
				
				if !teamid.isEmpty
				{
					goodOrganizationalUnit = false
					
					if let organizationalUnit = subjectName.OrganizationalUnitName
					{
						goodOrganizationalUnit = (organizationalUnit == teamid)
					}
				}
				
				return goodOrganization && goodOrganizationalUnit
			}
		}
	}
	
	return false
}


private func export_identities(identities: [KeychainIdentity]) throws -> Data
{
	for identity in identities
	{
		let certificate = try identity.getCertificate()
		let summary = certificate.SubjectSummary
		
		print("Exporting certificate : \(summary)")
	}
	
	return try export_identities(identities: identities.map { $0.Ref })
}

private func export_identities(identities: [SecIdentity]) throws -> Data
{
	let identitiesArray = identities as NSArray
	let exportFlags = SecItemImportExportFlags.pemArmour
	let unmanagedPassword = Unmanaged<AnyObject>.passRetained(password as AnyObject)
	let unmanagedAlertTitle = Unmanaged<CFString>.passRetained("dummy alert title" as CFString)
	let unmanagedAlertPrompt = Unmanaged<CFString>.passRetained("dummy alert prompt" as CFString)
	
	var parameters = SecItemImportExportKeyParameters(version: UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION),
	                                                  flags: .noAccessControl, passphrase: unmanagedPassword,
	                                                  alertTitle: unmanagedAlertTitle, alertPrompt: unmanagedAlertPrompt,
	                                                  accessRef: nil, keyUsage: nil, keyAttributes: nil)
	
	var dataOpt: CFData? = nil
	let err = withUnsafeMutablePointer(to: &dataOpt) { SecItemExport(identitiesArray, .formatPKCS12, exportFlags, &parameters, UnsafeMutablePointer($0)) }
	
	if err != errSecSuccess {
		throw make_sec_error(err, "Cannot export identities")
	}
	
	let data = dataOpt!
	
	return data as Data;
}

func write_export_file(path: String, data: Data) throws
{
	try data.write(to: URL(fileURLWithPath: path), options: .atomic)
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
	
	longopts.append(make_option_with_arg("keychain", letter: "k"))
	longopts.append(make_option_with_arg("output",   letter: "o"))
	longopts.append(make_option_with_arg("password", letter: "p"))
	longopts.append(make_option_with_arg("teamid",   letter: "t"))
	longopts.append(make_option_with_arg("user",     letter: "u"))
	longopts.append(option())

	while true
	{
		let c = getopt_long(CommandLine.argc, CommandLine.unsafeArgv, "k:o:p:t:u:", longopts, nil)
		
		if c < 0 { break }
		
		let char = Character(UnicodeScalar(UInt32(c))!)
		
		switch String(char) {
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
	print(" -k, --keychain PATH    The path to the keychain to export from.")
	print(" -o, --output PATH      The path to the file into which to export the certificates.")
	print(" -p, --password PASSWD  The password with which to protect the exported certificate file.")
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
