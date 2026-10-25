//! Caps on an offer, checked before it reaches the media thread or str0m's parser, and
//! whether it starts a share.

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

/// Whether the offer's share m-line sends: the second video m-line that is not `recvonly`,
/// with `sendonly` or `sendrecv`, which is the default. Read before str0m takes the offer, so
/// a share that is taken can be refused without changing anything.
pub(crate) fn share_sending(offer: &str) -> bool {
    let mut sections: Vec<&str> = Vec::new();
    let mut video = false;
    for line in offer.split(['\r', '\n']) {
        if let Some(media) = line.strip_prefix("m=") {
            video = media.starts_with("video ");
            if video {
                sections.push("sendrecv");
            }
            continue;
        }
        let direction = line.strip_prefix("a=").filter(|attribute| {
            matches!(
                *attribute,
                "sendonly" | "recvonly" | "sendrecv" | "inactive"
            )
        });
        if let (true, Some(direction), Some(last)) = (video, direction, sections.last_mut()) {
            *last = direction;
        }
    }
    sections
        .iter()
        .filter(|direction| **direction != "recvonly")
        .nth(1)
        .is_some_and(|direction| matches!(*direction, "sendonly" | "sendrecv"))
}

#[cfg(test)]
mod tests {
    use super::{share_sending, Caps};
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

    #[test]
    fn the_share_is_the_second_video_m_line_that_may_send() {
        let camera = "m=video 9 x\r\na=mid:1\r\na=sendonly\r\n";
        let slot = "m=video 9 x\r\na=recvonly\r\n";
        let share = |direction: &str| format!("m=video 9 x\r\na={direction}\r\n");
        let audio = "m=audio 9 x\r\na=sendonly\r\n";
        let offer = format!("v=0\r\n{audio}{camera}{}{slot}", share("sendonly"));
        assert!(share_sending(&offer));
        let offer = format!("v=0\r\n{audio}{camera}{slot}{}", share("sendrecv"));
        assert!(share_sending(&offer));
        let offer = format!("v=0\r\n{audio}{camera}{}{slot}", share("inactive"));
        assert!(!share_sending(&offer));
        // Without a direction an m-line is sendrecv.
        let offer = format!("v=0\r\n{camera}m=video 9 x\r\na=mid:2\r\n");
        assert!(share_sending(&offer));
        assert!(!share_sending(&format!("v=0\r\n{audio}{camera}{slot}")));
        assert!(!share_sending(&format!("v=0\r\n{slot}{slot}{slot}")));
        // A direction on an audio m-line says nothing about video.
        let offer = format!("v=0\r\n{camera}m=video 9 x\r\na=inactive\r\n{audio}");
        assert!(!share_sending(&offer));
    }
}
