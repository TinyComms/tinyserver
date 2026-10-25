# Fixtures

## `camera-h.h264`, `camera-l.h264`

The headless client's two camera layers. Each is a raw H.264 Annex B stream: 300 frames at 30 fps, constrained baseline, level 3.1, one IDR frame (with its SPS and PPS) and then 299 P frames, one slice each, no B frames. `h` is 320×180 and `l` is 160×90. The picture is SMPTE colour bars, which do not move, so the P frames are a few bytes each.

The headless client's share sends `camera-h.h264` too, at 15 fps, tagged layer `s` and padded to 2.5 Mb/s. A share of colour bars is not a screen, but the SFU never looks inside a frame, so it routes the same.

`client.rs` cuts each stream into frames, puts an SEI message in front of each one that names the sender and the layer, and pads it to the layer's nominal bitrate. A keyframe request from the SFU starts the layer over at its IDR frame; otherwise it loops every 10 s.

They were made with FFmpeg 9.0.2 and libx264 0.165 on 2026-10-24, from FFmpeg's built-in `smptebars` source. libx264's SEI with its version and settings is stripped:

```sh
ffmpeg -f lavfi -i smptebars=size=320x180:rate=30 -frames:v 300 \
  -c:v libx264 -profile:v baseline -level 3.1 -pix_fmt yuv420p -threads 1 \
  -g 300 -keyint_min 300 -sc_threshold 0 -bf 0 -refs 1 -b:v 300k \
  -bsf:v filter_units=remove_types=6 -f h264 camera-h.h264
ffmpeg -f lavfi -i smptebars=size=160x90:rate=30 -frames:v 300 \
  -c:v libx264 -profile:v baseline -level 3.1 -pix_fmt yuv420p -threads 1 \
  -g 300 -keyint_min 300 -sc_threshold 0 -bf 0 -refs 1 -b:v 100k \
  -bsf:v filter_units=remove_types=6 -f h264 camera-l.h264
```

`ffprobe` reports `Constrained Baseline`, and `ffmpeg -i camera-h.h264 -f null -` decodes both without an error.

Licence: the input is a synthetic test pattern and the output is an encoder's output, which libx264's GPL does not cover. The files are part of this repository under its MIT licence. `mediad` may copy them on the same terms.
