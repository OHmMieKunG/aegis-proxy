use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../ui/dist"]
struct Assets;

pub(super) fn get(path: &str) -> Option<aegisproxy_admin::WebAsset> {
    let content_type = match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        _ => "application/octet-stream",
    };
    Assets::get(path).map(|asset| aegisproxy_admin::WebAsset {
        bytes: asset.data.into_owned(),
        content_type,
    })
}
