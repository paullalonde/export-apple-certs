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
	fileprivate let _key: SecKey
	
	init(key: SecKey)
	{
		_key = key;
	}
	
	var ItemRef: SecKeychainItem
	{
		get { return unsafeBitCast(_key, to: SecKeychainItem.self) }
	}
	
	//func ReadAttributes()
	//{
	//	let attrs = SecKeyCopyAttributes(_key)
	//
	//}
}
