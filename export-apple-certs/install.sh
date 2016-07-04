#!/bin/bash
#
# Builds and install the export-apple-certs tool.

function bail
{
	echo ">>> $1 ($?)" 1>&2
	exit 1
}

DSTROOT="`     xcodebuild -showBuildSettings | perl -n -e'/^    DSTROOT = (.+)/      && print $1'`"
PRODUCT_NAME="`xcodebuild -showBuildSettings | perl -n -e'/^    PRODUCT_NAME = (.+)/ && print $1'`"
INSTALL_DIR="` xcodebuild -showBuildSettings | perl -n -e'/^    INSTALL_DIR = (.+)/  && print $1'`"
INSTALL_PATH="`xcodebuild -showBuildSettings | perl -n -e'/^    INSTALL_PATH = (.+)/ && print $1'`"
SRC_BIN_PATH="$INSTALL_DIR/$PRODUCT_NAME"
DST_BIN_PATH="$INSTALL_PATH/$PRODUCT_NAME"

sudo xcodebuild clean || bail "Could not clean project"
sudo rm -rf "$DSTROOT"
sudo xcodebuild install || bail "Could not install project"

#echo "Copying $PRODUCT_NAME to $INSTALL_PATH ..."
#
#echo DSTROOT = $DSTROOT
#echo PRODUCT_NAME = $PRODUCT_NAME
#echo INSTALL_DIR = $INSTALL_DIR
#echo INSTALL_PATH = $INSTALL_PATH

sudo rm -f "$DST_BIN_PATH"
echo ditto "$SRC_BIN_PATH" "$DST_BIN_PATH"
sudo ditto "$SRC_BIN_PATH" "$DST_BIN_PATH" || bail "Could not copy $SRC_BIN_PATH to $DST_BIN_PATH"

