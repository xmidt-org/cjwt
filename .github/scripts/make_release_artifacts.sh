#!/bin/bash
# SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

function how_to_use {
    echo "Usage: $0 -v version -r repo [-m] [-p provides]"
    echo "	-v version      Example: (v1.2.3)"
    echo "	-r github repo  Example: (octocat/Hello-World)"
    echo "	-m if passed in generates a meson wrap file"
    echo "	-p the meson library provided or the project name by default Example: foo -> libfoo = libfoo_dep"
}

version="none"
repo_slug="none"
provides="none"
meson=0

while getopts ":v:r:p:mh:" opt; do
    case ${opt} in
        v ) version=${OPTARG} ;;
        r ) repo_slug=${OPTARG} ;;
        p ) provides=${OPTARG} ;;
        m ) meson=1 ;;
        h )
            how_to_use
            exit 0
            ;;
        \?) how_to_use
            exit 0
            ;;
        : ) how_to_use
            exit 1
            ;;
    esac
done

if [ "none" == $version -o "none" == $repo_slug ]; then
    how_to_use
    exit 1
fi

raw_version=$version
if [ "v" == ${version:0:1} ]; then
    raw_version=${version:1}
fi

repo_name=$(echo $repo_slug | awk -F '/' '{print $2}')
release_slug=$(echo "$repo_name-$raw_version")

if [ "none" == $provides ]; then
    provides=$repo_name
fi

echo "     version: $version"
echo " raw_version: $raw_version"
echo "   repo_slug: $repo_slug"
echo "   repo_name: $repo_name"
echo "release_slug: $release_slug"
echo "    provides: $provides"

echo ""
echo "Making the .tar.gz archive"
git archive --format=tar.gz -o $release_slug.tar.gz --prefix=$release_slug/ $version

echo "Making the .zip archive"
git archive --format=zip    -o $release_slug.zip --prefix=$release_slug/ $version

if [ 1 == $meson ]; then

    echo "Making the .wrap file for meson"

    tgz_sum=`sha256sum $release_slug.tar.gz`
    tgz_sum=${tgz_sum:0:64} # Keep only the first 64 bytes which are the checksum

    echo "[wrap-file]"                               > $repo_name.wrap
    echo "directory = $release_slug"                >> $repo_name.wrap
    echo ""                                         >> $repo_name.wrap
    echo "source_filename = $release_slug.tar.gz"   >> $repo_name.wrap
    echo "source_url = https://github.com/$repo_slug/releases/download/$version/$release_slug.tar.gz" >> $repo_name.wrap
    echo "source_hash = $tgz_sum"                   >> $repo_name.wrap
    echo ""                                         >> $repo_name.wrap
    echo "[provides]"                               >> $repo_name.wrap
    echo "lib$provides = lib${provides}_dep"        >> $repo_name.wrap

    echo "Making the sha256sums.txt file"
    sha256sum $release_slug.tar.gz $release_slug.zip $repo_name.wrap > $release_slug-sha256sums.txt
else
    echo "Making the sha256sums.txt file"
    sha256sum $release_slug.tar.gz $release_slug.zip > $release_slug-sha256sums.txt
fi

echo "Copying files to the artifacts directory"
mkdir artifacts
cp ${release_slug}* artifacts/.

if [ -f $repo_name.wrap ]; then
    cp $repo_name.wrap artifacts/.
fi

echo "Complete"
