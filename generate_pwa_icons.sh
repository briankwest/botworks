#!/bin/bash

# Check if ImageMagick is installed
if ! command -v convert &> /dev/null; then
    echo "ImageMagick is not installed. Please install it first."
    echo "On Ubuntu/Debian: sudo apt-get install imagemagick"
    echo "On MacOS: brew install imagemagick"
    exit 1
fi

# Source image path
SOURCE="static/img/icon_1024x1024.png"

# Check if source image exists
if [ ! -f "$SOURCE" ]; then
    echo "Source image not found: $SOURCE"
    exit 1
fi

# Create directories if they don't exist
mkdir -p static/img/icons
mkdir -p static/img/splash

# Generate PWA icons
convert "$SOURCE" -resize 192x192 static/img/icons/icon-192x192.png
convert "$SOURCE" -resize 152x152 static/img/icons/icon-152x152.png
convert "$SOURCE" -resize 180x180 static/img/icons/icon-180x180.png
convert "$SOURCE" -resize 167x167 static/img/icons/icon-167x167.png

# Generate splash screens
# Function to create splash screen with padding
create_splash() {
    width=$1
    height=$2
    icon_size=$3
    output=$4
    
    # Create a white background
    convert -size ${width}x${height} xc:white \
        \( "$SOURCE" -resize ${icon_size}x${icon_size} \) \
        -gravity center -composite \
        "static/img/splash/$output"
}

# Create splash screens for different devices
create_splash 2048 2732 512 "apple-splash-2048-2732.png"  # iPad Pro 12.9"
create_splash 1668 2388 512 "apple-splash-1668-2388.png"  # iPad Pro 11"
create_splash 1536 2048 512 "apple-splash-1536-2048.png"  # iPad Mini/Air
create_splash 1125 2436 256 "apple-splash-1125-2436.png"  # iPhone X/XS
create_splash 1242 2688 256 "apple-splash-1242-2688.png"  # iPhone XS Max

echo "PWA icons and splash screens have been generated successfully!"