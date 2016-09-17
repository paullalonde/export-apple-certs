#!/bin/bash
#
# import-apple-certs.sh
#
# Creates a named keychain (deleting any existing keychain with the same name), and populates it with the identities in a given PKCS#12 file.

function bail
{
	echo ">>> $1 ($?)" 1>&2
	exit 1
}

function usage
{
	echo "usage : import-apple-certs.sh [options]"
	echo "Options:"
	echo "--certs-file=[file]               The path to the PKCS#12 file containing the certificates"
	echo "--certs-password=[password]       The password of the certificates file"
	echo "--keychain=[name]                 Name of the destination keychain"
	echo "--keychain-password=[password]    Password of the destination keychain"
	exit 2
}

for i in "$@"; do
		case $i in
		--certs-file=*)
		CERTS_FILE="${i#*=}"
		shift
		;;
		--certs-password=*)
		CERTS_PASSWORD="${i#*=}"
		shift
		;;
		--keychain=*)
		KEYCHAIN_NAME="${i#*=}"
		shift
		;;
		--keychain-password=*)
		KEYCHAIN_PASSWORD="${i#*=}"
		shift
		;;
	esac
done

if [ -z "$CERTS_FILE" ];         then usage; fi
if [ -z "$CERTS_PASSWORD" ];     then usage; fi
if [ -z "$KEYCHAIN_NAME" ];      then usage; fi
if [ -z "$KEYCHAIN_PASSWORD" ];  then usage; fi

KEYCHAIN_PATH=~/Library/Keychains/$KEYCHAIN_NAME.keychain

if [ -f "$KEYCHAIN_PATH" ]; then
	echo "Deleting existing keychain \"$KEYCHAIN_PATH\" ..."
	security delete-keychain "$KEYCHAIN_PATH" || bail "Cannot delete destination keychain"
fi

echo "Creating keychain \"$KEYCHAIN_PATH\" ..."
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" || bail "Cannot create destination keychain"

echo "Importing certificates into keychain \"$KEYCHAIN_PATH\" ..."
security import "$CERTS_FILE" -k "$KEYCHAIN_PATH" -f pkcs12 -P "$CERTS_PASSWORD" || bail "Cannot import certificates into keychain"
