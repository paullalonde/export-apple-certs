#!/bin/bash
#
# Builds and install the export-apple-certs tool.

function bail
{
	echo ">>> $1 ($?)" 1>&2
	exit 1
}

PROJECT=./export-apple-certs.xcodeproj
CONFIGURATION=Release

XCODE_VERSION=8
XCODE_PATH="/Applications/Developer/Xcode_${XCODE_VERSION}.app/Contents/Developer"
#LOGOPT="--log"
XCODEBUILD_CMD="env DEVELOPER_DIR=${XCODE_PATH} xcrun --sdk macosx $LOGOPT xcodebuild -project $PROJECT -configuration $CONFIGURATION"
SHOW_SETTINGS_CMD="$XCODEBUILD_CMD -showBuildSettings"

#echo XCODE_VERSION = $XCODE_VERSION
#echo XCODEBUILD_CMD = $XCODEBUILD_CMD
#echo SHOW_SETTINGS_CMD = $SHOW_SETTINGS_CMD

DSTROOT="`     $SHOW_SETTINGS_CMD | perl -n -e'/^    DSTROOT = (.+)/      && print $1'`"
PRODUCT_NAME="`$SHOW_SETTINGS_CMD | perl -n -e'/^    PRODUCT_NAME = (.+)/ && print $1'`"
INSTALL_DIR="` $SHOW_SETTINGS_CMD | perl -n -e'/^    INSTALL_DIR = (.+)/  && print $1'`"
INSTALL_PATH="`$SHOW_SETTINGS_CMD | perl -n -e'/^    INSTALL_PATH = (.+)/ && print $1'`"
SRC_BIN_PATH="$INSTALL_DIR/$PRODUCT_NAME"
DST_BIN_PATH="$INSTALL_PATH/$PRODUCT_NAME"

#echo DSTROOT = $DSTROOT
#echo PRODUCT_NAME = $PRODUCT_NAME
#echo INSTALL_DIR = $INSTALL_DIR
#echo INSTALL_PATH = $INSTALL_PATH

sudo $XCODEBUILD_CMD clean || bail "Could not clean project"
sudo rm -rf "$DSTROOT"
sudo $XCODEBUILD_CMD install || bail "Could not install project"

exit

sudo rm -f "$DST_BIN_PATH"
sudo ditto "$SRC_BIN_PATH" "$DST_BIN_PATH" || bail "Could not copy $SRC_BIN_PATH to $DST_BIN_PATH"

echo "Tool successfully installed to $DST_BIN_PATH"
