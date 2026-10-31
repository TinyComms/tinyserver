//! Attachment type policy: extension, MIME, and magic must agree.
//! Raster uploads are re-encoded so polyglot trailers never hit disk.

use std::io::Cursor;

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
    let (width, height) = header_dimensions(bytes, format)?;
    let frames = if format == ImageFormat::Gif {
        gif_frame_count(bytes)?
    } else {
        1
    };
    reject_caps(width, height, frames)?;
    let kind = kind_of_raster(mime)?;
    if format == ImageFormat::Gif {
        rewrite_gif(bytes, width, height, kind)
    } else {
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
        ImageFormat::Gif => GifDecoder::new(cursor)
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

fn gif_frame_count(bytes: &[u8]) -> Result<u32, MessageError> {
    if bytes.len() < 13 || !(bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        return Err(MessageError::UnsupportedMedia);
    }
    let packed = bytes[10];
    let mut i = 13usize;
    if packed & 0x80 != 0 {
        let table = 3usize.saturating_mul(1usize << ((packed & 0x07) + 1));
        i = i.checked_add(table).ok_or(MessageError::UnsupportedMedia)?;
        if i > bytes.len() {
            return Err(MessageError::UnsupportedMedia);
        }
    }
    let mut frames = 0u32;
    while let Some(&marker) = bytes.get(i) {
        i += 1;
        match marker {
            0x3B => break,
            0x21 => {
                i = i.checked_add(1).ok_or(MessageError::UnsupportedMedia)?;
                i = skip_gif_subblocks(bytes, i)?;
            }
            0x2C => {
                i = i.checked_add(9).ok_or(MessageError::UnsupportedMedia)?;
                if i > bytes.len() {
                    return Err(MessageError::UnsupportedMedia);
                }
                let packed = bytes[i - 1];
                if packed & 0x80 != 0 {
                    let table = 3usize.saturating_mul(1usize << ((packed & 0x07) + 1));
                    i = i.checked_add(table).ok_or(MessageError::UnsupportedMedia)?;
                    if i > bytes.len() {
                        return Err(MessageError::UnsupportedMedia);
                    }
                }
                i = i.checked_add(1).ok_or(MessageError::UnsupportedMedia)?;
                i = skip_gif_subblocks(bytes, i)?;
                frames = frames.saturating_add(1);
                if u64::from(frames) > MAX_GIF_FRAMES {
                    return Err(MessageError::UnsupportedMedia);
                }
            }
            _ => return Err(MessageError::UnsupportedMedia),
        }
    }
    if frames == 0 {
        return Err(MessageError::UnsupportedMedia);
    }
    Ok(frames)
}

fn skip_gif_subblocks(bytes: &[u8], mut i: usize) -> Result<usize, MessageError> {
    loop {
        let Some(&len) = bytes.get(i) else {
            return Err(MessageError::UnsupportedMedia);
        };
        i += 1;
        if len == 0 {
            return Ok(i);
        }
        i = i
            .checked_add(usize::from(len))
            .ok_or(MessageError::UnsupportedMedia)?;
        if i > bytes.len() {
            return Err(MessageError::UnsupportedMedia);
        }
    }
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
    if archives == Archives::Allowed || is_plain_office(ext, mime) {
        return false;
    }
    ext.is_some_and(archive_extension)
        || archive_mime(mime)
        || sniff_archive(bytes)
        || infer_container(bytes)
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
}
