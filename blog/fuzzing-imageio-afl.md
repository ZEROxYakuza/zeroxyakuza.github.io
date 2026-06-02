---
title: "Fuzzing ImageIO with AFL++"
date: "2 Jun 2026"
readTime: "30 min"
excerpt: "Learn to write a custom harness for fuzzing ImageIO with AFL++"
tags: ["iOS", "Security Research", "arm64"]
---


# Custom harness for fuzzing ImageIO

> Fuzzing the ImageIO Framework.

---

## 1. Creating the harness
We are going to start by writing the custom harness for fuzzing. The harness leads to seven ImageIO api calls to maximize coverage:

```
// This harness exercises several paths across all image formats ImageIO supports (TIFF, PNG,
// JPEG, GIF, BMP, WebP, HEIF, ICO, etc.).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>

#define MAX_INPUT_SIZE (10 * 1024 * 1024)

static int fuzz_imageio(const uint8_t *data, size_t len) {
    CFDataRef cfdata = CFDataCreate(kCFAllocatorDefault, data, (CFIndex)len);
    if (!cfdata) return 0;

    // Path 1: Format detection and initial header parsing across all supported image formats
    CGImageSourceRef source = CGImageSourceCreateWithData(cfdata, NULL);
    if (!source) {
        CFRelease(cfdata);
        return 0;
    }

    // Path 2: Multi-frame parsing (animated GIF frames, multi-page TIFF, multi-image HEIF).
    size_t count = CGImageSourceGetCount(source);

    // Path 3: Format identification.
    CFStringRef sourceType = CGImageSourceGetType(source);
    (void)sourceType;

    // Path 4: Header validation.
    CGImageSourceStatus status = CGImageSourceGetStatus(source);
    (void)status;

    size_t framesToDecode = count < 4 ? count : 4;

    for (size_t i = 0; i < framesToDecode; i++) {
        // Path 5: Full pixel decode
        CGImageRef image = CGImageSourceCreateImageAtIndex(source, i, NULL);
        if (image) {
            size_t width  = CGImageGetWidth(image);
            size_t height = CGImageGetHeight(image);
            size_t bpp    = CGImageGetBitsPerPixel(image);
            size_t bpr    = CGImageGetBytesPerRow(image);
            CGColorSpaceRef cs = CGImageGetColorSpace(image);
            (void)width; (void)height; (void)bpp; (void)bpr; (void)cs;

            // Path 6: Create thumbnail
            CFMutableDictionaryRef thumbOpts = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 2,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks);
            if (thumbOpts) {
                int maxPx = 64;
                CFNumberRef maxPixels = CFNumberCreate(kCFAllocatorDefault,
                    kCFNumberIntType, &maxPx);
                if (maxPixels) {
                    CFDictionarySetValue(thumbOpts,
                        kCGImageSourceThumbnailMaxPixelSize, maxPixels);
                    CFDictionarySetValue(thumbOpts,
                        kCGImageSourceCreateThumbnailFromImageAlways,
                        kCFBooleanTrue);
                    CGImageRef thumb = CGImageSourceCreateThumbnailAtIndex(
                        source, i, thumbOpts);
                    if (thumb) CGImageRelease(thumb);
                    CFRelease(maxPixels);
                }
                CFRelease(thumbOpts);
            }

            CGImageRelease(image);
        }

        // Path 7: Metadata extraction
        CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(
            source, i, NULL);
        if (props) CFRelease(props);
    }

    CFRelease(source);
    CFRelease(cfdata);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <image_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > MAX_INPUT_SIZE) {
        fclose(f);
        return 0;
    }

    uint8_t *data = (uint8_t *)malloc((size_t)fsize);
    if (!data) { fclose(f); return 1; }

    size_t nread = fread(data, 1, (size_t)fsize, f);
    fclose(f);

    if (nread != (size_t)fsize) {
        free(data);
        return 1;
    }

    fuzz_imageio(data, nread);

    free(data);
    return 0;
}
```

## 2. Compile for fuzzing
We have to compile the harness:

`afl-clang-fast -fsanitize=address -g -framework CoreFoundation -framework CoreGraphics -framework ImageIO -o imageio_fuzzing imageio_harness.c`

## 3. Create the seeds
You can create several files with header bytes for each image format or copy and paste the following python command to automate the process.

```
mkdir -p seeds && python3 -c "
open('seeds/min.tiff','wb').write(b'II\x2a\x00\x08\x00\x00\x00\x00\x00')

open('seeds/min.png','wb').write(bytes.fromhex(
  '89504e470d0a1a0a0000000d49484452'
  '000000010000000108060000001f15c489'
  '0000000a49444154789c6260000000020001e221bc330000000049454e44ae426082'
))

open('seeds/min.bmp','wb').write(b'BM' + b'\x00'*50)

open('seeds/min.gif','wb').write(b'GIF89a\x01\x00\x01\x00\x00\x00\x00;')
"
```

Now we have seeds for bmp, gif, tiff, and png formats.

## 4. Run AFL++ Fuzzer
Finally, we will run the afl++ fuzzer:

`afl-fuzz -i seeds -o findings -t 5000 -m none -- ./imageio_fuzzing @@`

## 5. Conclusion
This exact technique has found real-world vulnerabilities:

- CVE-2024-27879 — TIFF IFD count mismatch causes heap overflow in tile offset processing

- CVE-2023-32384 — HEIF metadata parsing heap overflow

- CVE-2023-4863 — WebP Huffman table overflow

- CVE-2021-30860 — JBIG2 integer overflow in CoreGraphics PDF rendering
