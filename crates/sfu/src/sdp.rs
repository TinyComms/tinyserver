//! Caps on an offer, checked before it reaches the media thread or str0m's parser.

use crate::{Config, Refused};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Caps {
    bytes: usize,
    audio: usize,
    video: usize,
}

impl From<&Config> for Caps {
    fn from(config: &Config) -> Self {
        Self {
            bytes: config.offer_bytes,
            audio: config.offer_audio,
            video: config.offer_video,
        }
    }
}

impl Caps {
    /// `BadSdp` for an offer over the byte cap, with too many audio or video m-lines, or with
    /// any other kind.
    pub fn check(&self, offer: &str) -> Result<(), Refused> {
        if offer.len() > self.bytes {
            return Err(Refused::BadSdp);
        }
        let (mut audio, mut video) = (0, 0);
        for line in offer.split(['\r', '\n']) {
            let Some(media) = line.strip_prefix("m=") else {
                continue;
            };
            match media.split(' ').next() {
                Some("audio") => audio += 1,
                Some("video") => video += 1,
                _ => return Err(Refused::BadSdp),
            }
            if audio > self.audio || video > self.video {
                return Err(Refused::BadSdp);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Caps;
    use crate::Refused;

    const CAPS: Caps = Caps {
        bytes: 200,
        audio: 2,
        video: 1,
    };

    #[test]
    fn an_offer_within_the_caps_passes() {
        let offer = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nm=audio 9 x\r\nm=video 9 x\r\n";
        assert_eq!(CAPS.check(offer), Ok(()));
        assert_eq!(CAPS.check("v=0"), Ok(()));
    }

    #[test]
    fn too_many_m_lines_or_bytes_or_another_kind_is_bad_sdp() {
        let audio = "v=0\r\nm=audio 9 x\r\nm=audio 9 x\r\nm=audio 9 x\r\n";
        assert_eq!(CAPS.check(audio), Err(Refused::BadSdp));
        let video = "v=0\r\nm=video 9 x\r\nm=video 9 x\r\n";
        assert_eq!(CAPS.check(video), Err(Refused::BadSdp));
        let data = "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
        assert_eq!(CAPS.check(data), Err(Refused::BadSdp));
        assert_eq!(CAPS.check(&"a".repeat(201)), Err(Refused::BadSdp));
    }
}
