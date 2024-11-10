import json
import hashlib
import os

# Define paths
files = {
    "website.json": "pushPackage/website.json",
    "icon.iconset/icon_16x16.png": "pushPackage/icon.iconset/icon_16x16.png",
    "icon.iconset/icon_16x16@2x.png": "pushPackage/icon.iconset/icon_16x16@2x.png",
    "icon.iconset/icon_32x32.png": "pushPackage/icon.iconset/icon_32x32.png",
    "icon.iconset/icon_32x32@2x.png": "pushPackage/icon.iconset/icon_32x32@2x.png",
    "icon.iconset/icon_128x128.png": "pushPackage/icon.iconset/icon_128x128.png",
    "icon.iconset/icon_128x128@2x.png": "pushPackage/icon.iconset/icon_128x128@2x.png"
}

# Generate SHA-512 hashes
manifest = {}
for name, path in files.items():
    with open(path, "rb") as f:
        file_hash = hashlib.sha512(f.read()).hexdigest()
    manifest[name] = {
        "hashType": "sha512",
        "hashValue": file_hash
    }

# Write manifest.json
with open("pushPackage/manifest.json", "w") as f:
    json.dump(manifest, f, indent=4)
