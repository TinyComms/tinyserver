# Link previews

tinyserver never fetches a link posted in a message.

- **No server-side fetching.** The server makes no outbound HTTP or DNS request when a message is posted, edited, or read. It stores only what the sender's app submits.
- **Sender-side unfurling.** When a sender pastes a link, the sender's app may fetch the page once before sending, upload any thumbnail image through the standard scanned and re-encoded upload path (`POST /v1/media`, or as a sealed attachment in an encrypted conversation), and attach the resulting preview metadata to the message.
- **Treated as the sender's claim.** Because the sender wrote the preview fields (`site`, `title`, `description`, `image_attachment_id`), a sender can write a misleading preview for a URL that appears in the message body. Readers' apps should display the real destination host beside the preview and treat the preview text as untrusted sender-supplied content.
- **No reader tracking.** Readers' apps render the stored preview and download any preview image only from the community server (`/v1/media/{id}`). Readers never contact the linked site until they explicitly choose to open the link.
- **Encrypted conversations.** In end-to-end encrypted conversations, previews travel inside the sealed MLS payload with the same shape, preview images are sealed attachments, and the server refuses any plaintext `previews` field on a ciphertext post (`400 e2ee_required`).
