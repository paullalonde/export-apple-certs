//
//  KeychainKey.swift
//  export-apple-certs
//
//  Created by Paul Lalonde on 16-09-04.
//  Copyright © 2016 Paul Lalonde enrg. All rights reserved.
//

import Foundation


struct KeychainKey
{
	private let _key: SecKey
	
	init(_ key: SecKey)
	{
		_key = key;
	}
}
