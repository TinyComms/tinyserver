//! Attachment type policy: extension, MIME, and magic must agree.
//! Raster uploads are re-encoded so polyglot trailers never hit disk.

use std::io::Cursor;
use std::num::NonZeroU64;

use image::codecs::gif::{GifDecoder, GifEncoder, Repeat};
use image::codecs::jpeg::JpegDecoder;
use image::codecs::png::PngDecoder;
use image::codecs::webp::WebPDecoder;
use image::{AnimationDecoder, ImageDecoder, ImageFormat};

use crate::messages::MessageError;

const MAX_EDGE: u64 = 16_384;
const MAX_PIXELS: u64 = 40_000_000;
const MAX_GIF_FRAMES: u64 = 500;
const MAX_RGBA: u64 = 256 * 1024 * 1024;
const MAX_ASPECT: u64 = 50;
const MAX_ZIP_ENTRIES: usize = 1024;
const MAX_ZIP_UNCOMPRESSED: u64 = 200 * 1024 * 1024;

/// Whether zip/7z/rar/tar/gz/bz2 may persist as kind `file`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Archives {
    Denied,
    Allowed,
}

/// A name, MIME, and kind that passed type policy.
pub struct Classified {
    pub name: String,
    pub mime: String,
    pub kind: &'static str,
}

/// Bytes and dimensions after a lossless-enough re-encode of png/jpeg/webp/gif.
pub struct Rewritten {
    pub bytes: Vec<u8>,
    pub mime: String,
    pub kind: &'static str,
    pub width: i32,
    pub height: i32,
}

/// Classify an upload. Size caps stay in `prepare`; this is type policy only.
///
/// MIME is trimmed, stripped of parameters, and lowercased here, so a caller that
/// skips `normalize_mime` still cannot sneak `TEXT/HTML` past the refuse list.
pub fn classify(
    name: &str,
    mime: &str,
    bytes: &[u8],
    archives: Archives,
) -> Result<Classified, MessageError> {
    if bytes.is_empty() {
        return Err(MessageError::Invalid);
    }
    let mime = mime
        .split(';')
        .next()
        .unwrap_or(mime)
        .trim()
        .to_ascii_lowercase();
    if mime.is_empty() {
        return Err(MessageError::Invalid);
    }
    let ext = file_extension(name);
    if ext.as_deref().is_some_and(refused_extension) {
        return Err(MessageError::UnsupportedMedia);
    }
    if refused_mime(&mime) {
        return Err(MessageError::UnsupportedMedia);
    }
    if sniff_pe(bytes) || sniff_elf(bytes) {
        return Err(MessageError::UnsupportedMedia);
    }
    if archive_forbidden(ext.as_deref(), &mime, bytes, archives) {
        return Err(MessageError::UnsupportedMedia);
    }
    if ext
        .as_deref()
        .is_some_and(|ext| !extension_fits(ext, &mime))
    {
        return Err(MessageError::UnsupportedMedia);
    }
    let kind = kind_from_mime(ext.as_deref(), &mime, bytes)?;
    if let Some(detected) = infer::get(bytes) {
        if !mimes_compatible(detected.mime_type(), &mime) {
            return Err(MessageError::UnsupportedMedia);
        }
    }
    Ok(Classified {
        name: name.to_string(),
        mime,
        kind,
    })
}

/// Re-encode a classified raster. Header caps run before a full decode.
/// Post-rewrite byte size is checked by `save_attachment` against `image_max_bytes`.
pub fn rewrite_raster(bytes: &[u8], mime: &str) -> Result<Rewritten, MessageError> {
    let format = format_of(mime)?;
    let kind = kind_of_raster(mime)?;
    if format == ImageFormat::Gif {
        let (width, height) = gif_check_caps(bytes)?;
        rewrite_gif(bytes, width, height, kind)
    } else {
        let (width, height) = header_dimensions(bytes, format)?;
        reject_caps(width, height, 1)?;
        rewrite_still(bytes, format, mime, kind)
    }
}

fn format_of(mime: &str) -> Result<ImageFormat, MessageError> {
    match mime {
        "image/png" => Ok(ImageFormat::Png),
        "image/jpeg" => Ok(ImageFormat::Jpeg),
        "image/webp" => Ok(ImageFormat::WebP),
        "image/gif" => Ok(ImageFormat::Gif),
        _ => Err(MessageError::UnsupportedMedia),
    }
}

fn kind_of_raster(mime: &str) -> Result<&'static str, MessageError> {
    match mime {
        "image/gif" => Ok("gif"),
        "image/png" | "image/jpeg" | "image/webp" => Ok("image"),
        _ => Err(MessageError::UnsupportedMedia),
    }
}

fn header_dimensions(bytes: &[u8], format: ImageFormat) -> Result<(u32, u32), MessageError> {
    let cursor = Cursor::new(bytes);
    let dims = match format {
        ImageFormat::Png => PngDecoder::new(cursor)
            .map_err(|_| MessageError::UnsupportedMedia)?
            .dimensions(),
        ImageFormat::Jpeg => JpegDecoder::new(cursor)
            .map_err(|_| MessageError::UnsupportedMedia)?
            .dimensions(),
        ImageFormat::WebP => WebPDecoder::new(cursor)
            .map_err(|_| MessageError::UnsupportedMedia)?
            .dimensions(),
        _ => return Err(MessageError::UnsupportedMedia),
    };
    Ok(dims)
}

fn reject_caps(width: u32, height: u32, frames: u32) -> Result<(), MessageError> {
    let width = u64::from(width);
    let height = u64::from(height);
    let frames = u64::from(frames);
    if width == 0 || height == 0 || frames == 0 {
        return Err(MessageError::UnsupportedMedia);
    }
    if width > MAX_EDGE || height > MAX_EDGE {
        return Err(MessageError::UnsupportedMedia);
    }
    if frames > MAX_GIF_FRAMES {
        return Err(MessageError::UnsupportedMedia);
    }
    let pixels = width.saturating_mul(height).saturating_mul(frames);
    if pixels > MAX_PIXELS {
        return Err(MessageError::UnsupportedMedia);
    }
    if pixels.saturating_mul(4) > MAX_RGBA {
        return Err(MessageError::UnsupportedMedia);
    }
    let long = width.max(height);
    let short = width.min(height);
    if long > short.saturating_mul(MAX_ASPECT) {
        return Err(MessageError::UnsupportedMedia);
    }
    Ok(())
}

/// Header/metadata only: `skip_frame_decoding` so a 1×1 screen with huge frames
/// cannot spend the bomb budget on `collect_frames`.
fn gif_check_caps(bytes: &[u8]) -> Result<(u32, u32), MessageError> {
    let mut options = gif::DecodeOptions::new();
    options.skip_frame_decoding(true);
    options.set_memory_limit(match NonZeroU64::new(MAX_RGBA) {
        Some(limit) => gif::MemoryLimit::Bytes(limit),
        None => gif::MemoryLimit::Unlimited,
    });
    let mut decoder = options
        .read_info(Cursor::new(bytes))
        .map_err(|_| MessageError::UnsupportedMedia)?;
    let screen_w = u32::from(decoder.width());
    let screen_h = u32::from(decoder.height());
    let mut max_w = screen_w;
    let mut max_h = screen_h;
    let mut frames = 0u32;
    loop {
        match decoder.next_frame_info() {
            Ok(Some(frame)) => {
                max_w = max_w.max(u32::from(frame.width));
                max_h = max_h.max(u32::from(frame.height));
                frames = frames.saturating_add(1);
                reject_caps(max_w, max_h, frames)?;
            }
            Ok(None) => break,
            Err(_) => return Err(MessageError::UnsupportedMedia),
        }
    }
    if frames == 0 {
        return Err(MessageError::UnsupportedMedia);
    }
    Ok((screen_w, screen_h))
}

fn rewrite_still(
    bytes: &[u8],
    format: ImageFormat,
    mime: &str,
    kind: &'static str,
) -> Result<Rewritten, MessageError> {
    let img = image::load_from_memory_with_format(bytes, format)
        .map_err(|_| MessageError::UnsupportedMedia)?;
    reject_caps(img.width(), img.height(), 1)?;
    let width = i32::try_from(img.width()).map_err(|_| MessageError::UnsupportedMedia)?;
    let height = i32::try_from(img.height()).map_err(|_| MessageError::UnsupportedMedia)?;
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, format)
        .map_err(|_| MessageError::UnsupportedMedia)?;
    Ok(Rewritten {
        bytes: out.into_inner(),
        mime: mime.to_string(),
        kind,
        width,
        height,
    })
}

fn rewrite_gif(
    bytes: &[u8],
    width: u32,
    height: u32,
    kind: &'static str,
) -> Result<Rewritten, MessageError> {
    let decoder =
        GifDecoder::new(Cursor::new(bytes)).map_err(|_| MessageError::UnsupportedMedia)?;
    let frames = decoder
        .into_frames()
        .collect_frames()
        .map_err(|_| MessageError::UnsupportedMedia)?;
    let frame_count = u64::try_from(frames.len()).unwrap_or(u64::MAX);
    if frames.is_empty() || frame_count > MAX_GIF_FRAMES {
        return Err(MessageError::UnsupportedMedia);
    }
    let width = i32::try_from(width).map_err(|_| MessageError::UnsupportedMedia)?;
    let height = i32::try_from(height).map_err(|_| MessageError::UnsupportedMedia)?;
    let mut out = Vec::new();
    {
        let mut encoder = GifEncoder::new(&mut out);
        encoder
            .set_repeat(Repeat::Infinite)
            .map_err(|_| MessageError::UnsupportedMedia)?;
        encoder
            .encode_frames(frames)
            .map_err(|_| MessageError::UnsupportedMedia)?;
    }
    Ok(Rewritten {
        bytes: out,
        mime: "image/gif".to_string(),
        kind,
        width,
        height,
    })
}

fn file_extension(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let base = base.trim_end_matches('.');
    let ext = base.rsplit_once('.')?.1;
    if ext.is_empty() {
        None
    } else {
        Some(ext.to_ascii_lowercase())
    }
}

fn refused_extension(ext: &str) -> bool {
    matches!(
        ext,
        "lnk"
            | "iso"
            | "img"
            | "vhd"
            | "vhdx"
            | "html"
            | "htm"
            | "hta"
            | "svg"
            | "js"
            | "vbs"
            | "cmd"
            | "bat"
            | "ps1"
            | "msi"
            | "scr"
            | "jar"
            | "exe"
            | "dll"
            | "com"
            | "pif"
            | "wsf"
            | "one"
            | "docm"
            | "xlsm"
            | "pptm"
            | "dotm"
            | "xltm"
            | "ppsm"
    )
}

fn refused_mime(mime: &str) -> bool {
    mime == "image/svg+xml" || mime == "text/html"
}

fn archive_forbidden(ext: Option<&str>, mime: &str, bytes: &[u8], archives: Archives) -> bool {
    // OOXML is a zip container and stays a document. It is not on the archive opt-in path.
    if is_plain_office(ext, mime) {
        return false;
    }
    let marked = ext.is_some_and(archive_extension)
        || archive_mime(mime)
        || sniff_archive(bytes)
        || infer_container(bytes);
    if !marked {
        return false;
    }
    if archives == Archives::Denied {
        return true;
    }
    if zip_container(ext, mime, bytes) {
        if ext == Some("zip") && zip_mime(mime) {
            return zip_exceeds_caps(bytes);
        }
        return true;
    }
    // 7z/rar/tar/gz/tgz/bz2 have no table of contents. MIME and extension must name the same
    // kind; `classify` still requires `infer` to agree when it recognizes the bytes.
    !ext.is_some_and(|ext| archive_mime_fits(ext, mime))
}

fn zip_container(ext: Option<&str>, mime: &str, bytes: &[u8]) -> bool {
    ext == Some("zip") || zip_mime(mime) || sniff_zip(bytes)
}

fn zip_mime(mime: &str) -> bool {
    matches!(mime, "application/zip" | "application/x-zip-compressed")
}

fn archive_mime_fits(ext: &str, mime: &str) -> bool {
    match ext {
        "zip" => zip_mime(mime),
        "7z" => mime == "application/x-7z-compressed",
        "rar" => matches!(mime, "application/vnd.rar" | "application/x-rar-compressed"),
        "tar" => matches!(mime, "application/x-tar" | "application/x-gtar"),
        "gz" | "tgz" => matches!(mime, "application/gzip" | "application/x-gzip"),
        "bz2" => matches!(mime, "application/x-bzip2" | "application/x-bzip"),
        _ => false,
    }
}

/// Central directory only. The outer zip is depth 1. An entry named as another archive is depth 2
/// and is not opened. A central directory that fails to parse is refused.
fn zip_exceeds_caps(bytes: &[u8]) -> bool {
    let Ok(archive) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        return true;
    };
    if archive.len() > MAX_ZIP_ENTRIES {
        return true;
    }
    let mut total = 0u64;
    for index in 0..archive.len() {
        let Ok(entry) = archive.by_index_data(index) else {
            return true;
        };
        if entry.encrypted() || entry.is_symlink() {
            return true;
        }
        let Ok(name) = entry.name() else {
            return true;
        };
        if unsafe_zip_name(&name) {
            return true;
        }
        let compressed = entry.compressed_size();
        let plain = entry.size();
        if (compressed == 0 && plain > 0) || plain > compressed.saturating_mul(4) {
            return true;
        }
        total = total.saturating_add(plain);
        if total > MAX_ZIP_UNCOMPRESSED {
            return true;
        }
    }
    false
}

fn unsafe_zip_name(name: &str) -> bool {
    if name.contains("..") || name.contains('\0') {
        return true;
    }
    let bytes = name.as_bytes();
    if bytes
        .first()
        .is_some_and(|byte| *byte == b'/' || *byte == b'\\')
    {
        return true;
    }
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

/// `infer` files PDF under `MatcherType::Archive`; that is a document, not a zip.
fn infer_container(bytes: &[u8]) -> bool {
    infer::get(bytes).is_some_and(|detected| {
        detected.matcher_type() == infer::MatcherType::Archive
            && detected.mime_type() != "application/pdf"
    })
}

fn archive_extension(ext: &str) -> bool {
    matches!(ext, "zip" | "7z" | "rar" | "tar" | "gz" | "tgz" | "bz2")
}

fn archive_mime(mime: &str) -> bool {
    matches!(
        mime,
        "application/zip"
            | "application/x-zip-compressed"
            | "application/x-7z-compressed"
            | "application/vnd.rar"
            | "application/x-rar-compressed"
            | "application/x-tar"
            | "application/gzip"
            | "application/x-gzip"
            | "application/x-gtar"
            | "application/x-bzip2"
            | "application/x-bzip"
    )
}

fn is_plain_office(ext: Option<&str>, mime: &str) -> bool {
    match ext {
        Some("doc") => mime == "application/msword",
        Some("docx") => {
            mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        }
        Some("xls") => mime == "application/vnd.ms-excel",
        Some("xlsx") => mime == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("ppt") => mime == "application/vnd.ms-powerpoint",
        Some("pptx") => {
            mime == "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        }
        _ => false,
    }
}

fn extension_fits(ext: &str, mime: &str) -> bool {
    match ext {
        "png" => mime == "image/png",
        "jpg" | "jpeg" => mime == "image/jpeg",
        "webp" => mime == "image/webp",
        "gif" => mime == "image/gif",
        "mp4" => mime == "video/mp4",
        "webm" => mime == "video/webm" || mime == "audio/webm",
        "pdf" => mime == "application/pdf",
        "mp3" | "mpeg" | "mpga" => mime == "audio/mpeg",
        "ogg" | "oga" => mime == "audio/ogg",
        "wav" => mime == "audio/wav" || mime == "audio/x-wav",
        "doc" => mime == "application/msword",
        "docx" => mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => mime == "application/vnd.ms-excel",
        "xlsx" => mime == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => mime == "application/vnd.ms-powerpoint",
        "pptx" => {
            mime == "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        }
        _ => true,
    }
}

fn kind_from_mime(
    ext: Option<&str>,
    mime: &str,
    bytes: &[u8],
) -> Result<&'static str, MessageError> {
    let kind = match mime {
        "image/png" if sniff_png(bytes) => "image",
        "image/jpeg" if sniff_jpeg(bytes) => "image",
        "image/webp" if sniff_webp(bytes) => "image",
        "image/gif" if sniff_gif(bytes) => "gif",
        "video/mp4" if sniff_mp4(bytes) => "video",
        "video/webm" if sniff_webm(bytes) => "video",
        "application/pdf" if sniff_pdf(bytes) => "file",
        "application/pdf" => return Err(MessageError::UnsupportedMedia),
        "audio/mpeg" | "audio/ogg" | "audio/wav" | "audio/x-wav" | "audio/webm"
            if audio_agrees(mime, bytes) =>
        {
            "file"
        }
        other
            if other.starts_with("image/")
                || other.starts_with("video/")
                || other.starts_with("audio/") =>
        {
            return Err(MessageError::UnsupportedMedia);
        }
        other if is_office_mime(other) => {
            if is_plain_office(ext, mime) && office_magic(ext, bytes) {
                "file"
            } else {
                return Err(MessageError::UnsupportedMedia);
            }
        }
        _ => "file",
    };
    Ok(kind)
}

fn is_office_mime(mime: &str) -> bool {
    matches!(
        mime,
        "application/msword"
            | "application/vnd.ms-excel"
            | "application/vnd.ms-powerpoint"
            | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    )
}

fn office_magic(ext: Option<&str>, bytes: &[u8]) -> bool {
    match ext {
        Some("doc" | "xls" | "ppt") => sniff_ole(bytes),
        Some("docx" | "xlsx" | "pptx") => sniff_zip(bytes),
        _ => false,
    }
}

fn audio_agrees(mime: &str, bytes: &[u8]) -> bool {
    if mime == "audio/webm" && sniff_webm(bytes) {
        return true;
    }
    infer::get(bytes).is_some_and(|detected| mimes_compatible(detected.mime_type(), mime))
}

fn mimes_compatible(inferred: &str, declared: &str) -> bool {
    inferred == declared
        || (inferred == "image/jpeg" && declared == "image/jpg")
        || (inferred == "audio/x-wav" && declared == "audio/wav")
        || (inferred == "audio/wav" && declared == "audio/x-wav")
}

fn sniff_png(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x89PNG\r\n\x1a\n")
}

fn sniff_jpeg(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF
}

fn sniff_webp(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP"
}

fn sniff_gif(bytes: &[u8]) -> bool {
    bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")
}

fn sniff_mp4(bytes: &[u8]) -> bool {
    let window = &bytes[..bytes.len().min(32)];
    window.windows(4).any(|chunk| chunk == b"ftyp")
}

fn sniff_webm(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x1A, 0x45, 0xDF, 0xA3])
}

fn sniff_pdf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"%PDF")
}

fn sniff_pe(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
}

fn sniff_elf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
}

fn sniff_ole(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
}

fn sniff_zip(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes[0] == b'P'
        && bytes[1] == b'K'
        && matches!(bytes[2], 3 | 5 | 7)
        && matches!(bytes[3], 4 | 6 | 8)
}

fn sniff_archive(bytes: &[u8]) -> bool {
    sniff_zip(bytes)
        || bytes.starts_with(&[0x1F, 0x8B])
        || bytes.starts_with(b"7z\xBC\xAF'\x1C")
        || bytes.starts_with(b"Rar!\x1A\x07")
        || bytes.starts_with(b"BZh")
        || (bytes.len() >= 262 && &bytes[257..262] == b"ustar")
}

#[cfg(test)]
mod tests {
    use super::{classify as classify_with, rewrite_raster, Archives, Classified};
    use crate::messages::MessageError;

    /// 1×1 RGB PNG (red). Hand-built so the polyglot test does not depend on `image`.
    const TINY_PNG: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90,
        0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0xF8,
        0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0xC9, 0xFE, 0x92, 0xEF, 0x00, 0x00, 0x00,
        0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    fn png_crc(bytes: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in bytes {
            crc ^= u32::from(b);
            for _ in 0..8 {
                if crc & 1 == 0 {
                    crc >>= 1;
                } else {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                }
            }
        }
        !crc
    }

    fn png_ihdr(width: u32, height: u32) -> Vec<u8> {
        let mut ihdr = Vec::from(*b"IHDR");
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        let crc = png_crc(&ihdr);
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        out.extend_from_slice(&13u32.to_be_bytes());
        out.extend_from_slice(&ihdr);
        out.extend_from_slice(&crc.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(b"IEND");
        out.extend_from_slice(&png_crc(b"IEND").to_be_bytes());
        out
    }

    #[test]
    fn rewrite_png_drops_polyglot_trailer() {
        let mut bytes = TINY_PNG.to_vec();
        bytes.extend_from_slice(b"%PDF-1.4");
        let got = rewrite_raster(&bytes, "image/png").expect("rewrite");
        assert!(
            !got.bytes.windows(4).any(|chunk| chunk == b"%PDF"),
            "rewritten PNG still contains a %PDF trailer"
        );
        assert_eq!(got.mime, "image/png");
        assert_eq!(got.kind, "image");
        assert_eq!(got.width, 1);
        assert_eq!(got.height, 1);
    }

    #[test]
    fn rewrite_rejects_pixel_bomb_from_header() {
        let bytes = png_ihdr(100_000, 100_000);
        assert!(
            matches!(
                rewrite_raster(&bytes, "image/png"),
                Err(MessageError::UnsupportedMedia | MessageError::TooLarge)
            ),
            "pixel bomb from IHDR must fail before a full decode"
        );
    }

    /// 1×1 logical screen, four 3200×3200 frames. Screen budget is 1×1×4; spec budget is
    /// 3200×3200×4 = 40.96e6 > 40e6. Each frame is under the gif crate's 50 MiB RGBA limit,
    /// so a screen-only cap would decode instead of refusing from the image descriptor.
    fn gif_1x1_screen_with_large_frames() -> Vec<u8> {
        let mut out = Vec::new();
        let palette = [0, 0, 0, 0xFF, 0xFF, 0xFF];
        {
            let mut encoder = gif::Encoder::new(&mut out, 1, 1, &palette).expect("1×1 GIF screen");
            let pixels = vec![0_u8; 3200 * 3200];
            for _ in 0..4 {
                let frame = gif::Frame::from_indexed_pixels(3200, 3200, pixels.clone(), None);
                encoder.write_frame(&frame).expect("oversized frame");
            }
        }
        out
    }

    #[test]
    fn rewrite_rejects_gif_frame_larger_than_logical_screen() {
        let bytes = gif_1x1_screen_with_large_frames();
        let started = std::time::Instant::now();
        let result = rewrite_raster(&bytes, "image/gif");
        assert!(
            started.elapsed().as_millis() < 200,
            "must refuse from GIF image-descriptor metadata, took {:?}",
            started.elapsed()
        );
        assert!(
            matches!(
                result,
                Err(MessageError::UnsupportedMedia | MessageError::TooLarge)
            ),
            "GIF frame pixels must count toward the bomb budget, not only the 1×1 screen"
        );
    }

    fn classify(name: &str, mime: &str, bytes: &[u8]) -> Result<Classified, MessageError> {
        classify_with(name, mime, bytes, Archives::Denied)
    }

    #[test]
    fn refuses_pe_named_as_png() {
        let mut bytes = b"MZ".to_vec();
        bytes.extend_from_slice(&[0; 64]);
        assert!(matches!(
            classify("photo.png", "image/png", &bytes),
            Err(MessageError::UnsupportedMedia)
        ));
    }

    #[test]
    fn refuses_html_and_svg_and_lnk() {
        assert!(matches!(
            classify("page.html", "text/html", b"<html>hi</html>"),
            Err(MessageError::UnsupportedMedia)
        ));
        assert!(matches!(
            classify("page.HTML", "text/plain", b"hello"),
            Err(MessageError::UnsupportedMedia)
        ));
        assert!(matches!(
            classify(
                "icon.svg",
                "image/svg+xml",
                b"<svg xmlns='http://www.w3.org/2000/svg'></svg>"
            ),
            Err(MessageError::UnsupportedMedia)
        ));
        assert!(matches!(
            classify(
                "shortcut.lnk",
                "application/octet-stream",
                &[0x4C, 0x00, 0x00, 0x00]
            ),
            Err(MessageError::UnsupportedMedia)
        ));
    }

    #[test]
    fn allows_pdf_when_sniff_agrees() {
        let bytes = b"%PDF-1.4\n";
        let got = classify("doc.pdf", "application/pdf", bytes).expect("pdf");
        assert_eq!(got.kind, "file");
        assert_eq!(got.mime, "application/pdf");
    }

    #[test]
    fn refuses_zip_by_default() {
        assert!(matches!(
            classify("mods.zip", "application/zip", b"PK\x03\x04"),
            Err(MessageError::UnsupportedMedia)
        ));
    }

    #[test]
    fn refuses_trailing_dot_weaponized_extensions() {
        assert!(matches!(
            classify_with("payload.js.", "text/plain", b"alert(1)", Archives::Denied),
            Err(MessageError::UnsupportedMedia)
        ));
        assert!(matches!(
            classify_with(
                "page.html.",
                "text/plain",
                b"<html>hi</html>",
                Archives::Denied
            ),
            Err(MessageError::UnsupportedMedia)
        ));
    }

    #[test]
    fn refuses_elf_regardless_of_name() {
        assert!(matches!(
            classify("note.txt", "text/plain", b"\x7fELF"),
            Err(MessageError::UnsupportedMedia)
        ));
    }

    #[test]
    fn refuses_html_mime_even_when_uppercase() {
        assert!(matches!(
            classify("notes.txt", "TEXT/HTML", b"<html>hi</html>"),
            Err(MessageError::UnsupportedMedia)
        ));
    }

    #[test]
    fn uploads_match_their_declared_type() {
        assert_eq!(
            classify("wave.gif", "image/gif", b"GIF89a")
                .expect("gif")
                .kind,
            "gif"
        );
        assert_eq!(
            classify("photo.png", "image/png", b"\x89PNG\r\n\x1a\n")
                .expect("png")
                .kind,
            "image"
        );
        assert_eq!(
            classify("photo.jpg", "image/jpeg", b"\xFF\xD8\xFF")
                .expect("jpeg")
                .kind,
            "image"
        );
        let mut webp = vec![0_u8; 12];
        webp[0..4].copy_from_slice(b"RIFF");
        webp[8..12].copy_from_slice(b"WEBP");
        assert_eq!(
            classify("photo.webp", "image/webp", &webp)
                .expect("webp")
                .kind,
            "image"
        );
        let mut mp4 = vec![0_u8; 16];
        mp4[4..8].copy_from_slice(b"ftyp");
        assert_eq!(
            classify("clip.mp4", "video/mp4", &mp4).expect("mp4").kind,
            "video"
        );
        assert_eq!(
            classify("clip.webm", "video/webm", &[0x1A, 0x45, 0xDF, 0xA3])
                .expect("webm")
                .kind,
            "video"
        );
        assert!(matches!(
            classify("doc.pdf", "application/pdf", b"not-a-pdf"),
            Err(MessageError::UnsupportedMedia)
        ));
        assert!(matches!(
            classify("photo.png", "image/png", b"GIF89a"),
            Err(MessageError::UnsupportedMedia)
        ));
        assert!(matches!(
            classify("photo.bmp", "image/bmp", b"BM"),
            Err(MessageError::UnsupportedMedia)
        ));
        assert!(matches!(
            classify("wave.gif", "image/gif", b""),
            Err(MessageError::Invalid)
        ));
    }

    fn allow(name: &str, mime: &str, bytes: &[u8]) -> Result<Classified, MessageError> {
        classify_with(name, mime, bytes, Archives::Allowed)
    }

    fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;

        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, data) in files {
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            writer.start_file(*name, options).expect("zip entry");
            writer.write_all(data).expect("zip bytes");
        }
        writer.finish().expect("zip finish").into_inner()
    }

    /// Central-directory sizes, as the bomb cap reads them. Proves the fixture
    /// before `classify` is asked to refuse it.
    fn central_entry(bytes: &[u8], index: usize) -> (u64, u64, bool, bool) {
        let archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("read zip");
        let entry = archive.by_index_data(index).expect("entry");
        (
            entry.compressed_size(),
            entry.size(),
            entry.encrypted(),
            entry.is_symlink(),
        )
    }

    fn patch_central(
        bytes: &mut [u8],
        name: &str,
        compressed: u32,
        uncompressed: u32,
        encrypt: bool,
    ) {
        let signature = [0x50, 0x4b, 0x01, 0x02];
        let wanted = name.as_bytes();
        let mut index = 0;
        while index + 46 <= bytes.len() {
            if bytes[index..index + 4] == signature {
                let name_len = u16::from_le_bytes([bytes[index + 28], bytes[index + 29]]) as usize;
                let extra_len = u16::from_le_bytes([bytes[index + 30], bytes[index + 31]]) as usize;
                let comment_len =
                    u16::from_le_bytes([bytes[index + 32], bytes[index + 33]]) as usize;
                let name_at = index + 46;
                if name_at + name_len <= bytes.len()
                    && &bytes[name_at..name_at + name_len] == wanted
                {
                    bytes[index + 20..index + 24].copy_from_slice(&compressed.to_le_bytes());
                    bytes[index + 24..index + 28].copy_from_slice(&uncompressed.to_le_bytes());
                    if encrypt {
                        bytes[index + 8] |= 1;
                    }
                    return;
                }
                index += (46 + name_len + extra_len + comment_len).max(1);
                continue;
            }
            index += 1;
        }
        panic!("central directory entry {name} not found");
    }

    #[test]
    fn an_allowed_zip_of_one_text_file_is_a_file() {
        let bytes = stored_zip(&[("hello.txt", b"hello")]);
        let got = allow("notes.zip", "application/zip", &bytes).expect("small zip");
        assert_eq!(got.kind, "file");
        assert_eq!(got.mime, "application/zip");
    }

    #[test]
    fn allowed_zip_rejects_more_than_1024_entries() {
        let ok = many_zip(1024);
        allow("ok.zip", "application/zip", &ok).expect("1024 entries is the limit");

        let over = many_zip(1025);
        assert!(matches!(
            allow("over.zip", "application/zip", &over),
            Err(MessageError::UnsupportedMedia)
        ));
    }

    fn many_zip(count: usize) -> Vec<u8> {
        use std::io::Write;

        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for i in 0..count {
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            writer
                .start_file(format!("f{i}.txt"), options)
                .expect("zip entry");
            writer.write_all(b"x").expect("zip bytes");
        }
        writer.finish().expect("zip finish").into_inner()
    }

    #[test]
    fn allowed_zip_rejects_a_ratio_above_four_to_one() {
        let mut exact = stored_zip(&[("a.txt", b"hello")]);
        patch_central(&mut exact, "a.txt", 10, 40, false);
        assert_eq!(central_entry(&exact, 0).0, 10, "fixture compressed size");
        assert_eq!(central_entry(&exact, 0).1, 40, "fixture uncompressed size");
        allow("a.zip", "application/zip", &exact).expect("4× compressed is the limit");

        let mut over = stored_zip(&[("a.txt", b"hello")]);
        patch_central(&mut over, "a.txt", 10, 41, false);
        assert_eq!(
            (central_entry(&over, 0).0, central_entry(&over, 0).1),
            (10, 41)
        );
        assert!(matches!(
            allow("a.zip", "application/zip", &over),
            Err(MessageError::UnsupportedMedia)
        ));
    }

    #[test]
    fn allowed_zip_rejects_zero_compressed_with_uncompressed_bytes() {
        let mut bytes = stored_zip(&[("a.txt", b"hello")]);
        patch_central(&mut bytes, "a.txt", 0, 5, false);
        let (compressed, plain, encrypted, _) = central_entry(&bytes, 0);
        assert_eq!((compressed, plain, encrypted), (0, 5, false));
        assert!(matches!(
            allow("a.zip", "application/zip", &bytes),
            Err(MessageError::UnsupportedMedia)
        ));
    }

    #[test]
    fn allowed_zip_rejects_total_uncompressed_over_200_mib() {
        const MIB: u32 = 1024 * 1024;
        let mut at_cap = stored_zip(&[("a.txt", b"hello")]);
        let plain_ok = 200 * MIB;
        patch_central(&mut at_cap, "a.txt", plain_ok / 4, plain_ok, false);
        assert_eq!(central_entry(&at_cap, 0).1, u64::from(plain_ok));
        allow("cap.zip", "application/zip", &at_cap).expect("200 MiB is the limit");

        let mut over = stored_zip(&[("a.txt", b"hello")]);
        let plain = 200 * MIB + 1;
        let compressed = plain / 4 + 1;
        patch_central(&mut over, "a.txt", compressed, plain, false);
        assert_eq!(central_entry(&over, 0).1, u64::from(plain));
        assert!(
            central_entry(&over, 0).1 <= central_entry(&over, 0).0.saturating_mul(4),
            "fixture must trip the total cap without also tripping the ratio cap"
        );
        assert!(matches!(
            allow("over.zip", "application/zip", &over),
            Err(MessageError::UnsupportedMedia)
        ));
    }

    #[test]
    fn allowed_zip_rejects_dotdot_absolute_symlink_and_encryption() {
        for name in [
            "../secret.txt",
            "foo/../../etc/passwd",
            "/etc/passwd",
            r"C:\Windows\note.txt",
        ] {
            let bytes = stored_zip(&[(name, b"x")]);
            assert!(
                matches!(
                    allow("mods.zip", "application/zip", &bytes),
                    Err(MessageError::UnsupportedMedia)
                ),
                "{name}"
            );
        }

        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .add_symlink(
                "link",
                "target.txt",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .expect("symlink entry");
        let symlink = writer.finish().expect("zip finish").into_inner();
        assert!(
            central_entry(&symlink, 0).3,
            "fixture must be a unix symlink"
        );
        assert!(matches!(
            allow("mods.zip", "application/zip", &symlink),
            Err(MessageError::UnsupportedMedia)
        ));

        let mut encrypted = stored_zip(&[("a.txt", b"hello")]);
        patch_central(&mut encrypted, "a.txt", 5, 5, true);
        assert!(
            central_entry(&encrypted, 0).2,
            "fixture must set the encryption flag"
        );
        assert!(matches!(
            allow("secret.zip", "application/zip", &encrypted),
            Err(MessageError::UnsupportedMedia)
        ));
    }

    #[test]
    fn allowed_zip_accepts_nested_archive_names_without_inflating() {
        let bytes = stored_zip(&[
            ("readme.txt", b"hi"),
            ("nested.zip", b"PK\x03\x04not-opened"),
            ("nested.7z", b"nope"),
            ("nested.rar", b"nope"),
            ("nested.tar", b"nope"),
            ("nested.gz", b"nope"),
            ("nested.tgz", b"nope"),
            ("nested.bz2", b"nope"),
        ]);
        let got = allow("mods.zip", "application/zip", &bytes).expect("depth 2 by name");
        assert_eq!(got.kind, "file");
    }

    #[test]
    fn allowed_non_zip_needs_mime_and_extension_agreement() {
        assert!(matches!(
            allow("mods.7z", "text/plain", b"not-an-archive"),
            Err(MessageError::UnsupportedMedia)
        ));
        assert_eq!(
            allow("mods.7z", "application/x-7z-compressed", b"not-an-archive")
                .expect("7z mime agrees with extension")
                .kind,
            "file"
        );

        let gz = [0x1f, 0x8b, 0x08];
        assert!(matches!(
            classify("logs.gz", "application/gzip", &gz),
            Err(MessageError::UnsupportedMedia)
        ));
        assert_eq!(
            allow("logs.gz", "application/gzip", &gz)
                .expect("gzip when archives are allowed")
                .kind,
            "file"
        );
        assert!(matches!(
            allow("logs.gz", "text/plain", &gz),
            Err(MessageError::UnsupportedMedia)
        ));
    }

    #[test]
    fn a_docx_is_not_bomb_capped() {
        let bytes = stored_zip(&[
            ("word/document.xml", b"<w:document/>"),
            ("../secret.txt", b"nope"),
        ]);
        let mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
        let got = allow("doc.docx", mime, &bytes).expect("docx stays a document");
        assert_eq!(got.kind, "file");
        assert_eq!(got.mime, mime);
    }
}
