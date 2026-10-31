//! Attachment type policy: extension, MIME, and magic must agree.

use crate::messages::MessageError;

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
    use super::{classify as classify_with, Archives, Classified};
    use crate::messages::MessageError;

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
