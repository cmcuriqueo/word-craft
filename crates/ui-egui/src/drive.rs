//! Open from Google Drive: another place a file can come from, not a second editor.
//!
//! File › Open › Open from Google Drive asks the host ([`Services::open_drive`]) to sign in and
//! list files. The dialog here is the picker. Choosing one asks the host
//! ([`Services::fetch_drive`]) to export a Google Doc as .docx or download an Office, text or
//! OpenDocument file. Those bytes arrive on the inbox and open through `file.open`, the same
//! command a local pick uses ([`crate::WordApp::drain_inbox`]). Saving the document is unchanged.
//!
//! The web app does the OAuth and the downloads. Desktop builds show why the button is quiet
//! there: this phase has no desktop sign-in.

use std::sync::mpsc::{Receiver, TryRecvError, channel};

use serde_json::Value;

use crate::WordApp;

/// Read-only Drive scope. Listing and downloading need nothing broader.
pub const DRIVE_READONLY: &str = "https://www.googleapis.com/auth/drive.readonly";

/// A Google Doc is not a .docx until Drive exports it as one.
pub const GOOGLE_DOC: &str = "application/vnd.google-apps.document";

/// Export target for a Google Doc: a Word document.
pub const EXPORT_DOCX: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

/// Largest file read from Drive into the editor (80 MiB). Bigger replies are refused.
pub const MAX_FILE_BYTES: usize = 80 << 20;

const SIGNING_IN: &str = "Signing in to Google Drive…";
const LOADING: &str = "Loading files from Google Drive…";
const OPENING: &str = "Opening the file from Google Drive…";

/// Office, text and OpenDocument types downloaded as themselves: (MIME type, extension).
const DOWNLOAD: &[(&str, &str)] = &[
    (EXPORT_DOCX, "docx"),
    ("application/vnd.openxmlformats-officedocument.wordprocessingml.template", "dotx"),
    ("application/msword", "doc"),
    ("application/vnd.ms-word.document.macroEnabled.12", "docm"),
    ("application/vnd.ms-word.template.macroEnabled.12", "dotm"),
    ("application/vnd.oasis.opendocument.text", "odt"),
    ("application/rtf", "rtf"),
    ("text/rtf", "rtf"),
    ("text/plain", "txt"),
    ("text/markdown", "md"),
    ("text/html", "html"),
    ("application/x-tex", "tex"),
    ("text/x-tex", "tex"),
    ("application/json", "json"),
    ("application/xml", "xml"),
    ("text/xml", "xml"),
];

/// Extensions left on a downloaded name. An export to .docx does not keep a different one.
const KEEP_EXT: &[&str] =
    &["docx", "docm", "dotx", "dotm", "doc", "dot", "odt", "rtf", "txt", "text", "md", "markdown", "html", "htm", "tex", "json", "xml"];

/// One file in a Drive listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveFile {
    pub id: String,
    pub name: String,
    pub mime: String,
}

/// What the host should fetch for a file the user chose. `name` is the `file.open` path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveRequest {
    pub id: String,
    pub name: String,
    pub export_docx: bool,
}

/// How the chosen file becomes bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenPlan {
    pub name: String,
    pub export_docx: bool,
}

/// News from the host while the picker is open.
#[derive(Clone, Debug)]
pub enum DriveEvent {
    /// No client id is configured. The dialog asks for one.
    NeedClientId,
    /// Signed in; the file list is on its way.
    Listing,
    Files(Vec<DriveFile>),
    Error(String),
}

/// A page of [`parse_file_list`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilePage {
    pub files: Vec<DriveFile>,
    pub next_page_token: Option<String>,
}

/// The Open from Google Drive dialog.
pub(crate) struct Picker {
    rx: Receiver<DriveEvent>,
    phase: Phase,
    files: Vec<DriveFile>,
    selected: Option<usize>,
    client_id: String,
    client_error: Option<&'static str>,
}

#[derive(Debug)]
enum Phase {
    Working(&'static str),
    NeedClientId,
    Choose,
    Error(String),
}

/// File › Open › Open from Google Drive, and `ui.openFromDrive` ([`crate::file_dialogs`]).
///
/// Returns whether the host started sign-in. With no host (the desktop app) the dialog explains
/// that this runs in the web app.
pub(crate) fn start(app: &mut WordApp) -> bool {
    if app.file_dialog_open() {
        app.status(tl!("A file dialog is already open."));
        return false;
    }
    let Some(start) = &app.services.open_drive else {
        app.drive_picker = Some(Picker::explain("Open from Google Drive is available in the web app."));
        return false;
    };
    app.drive_picker = Some(Picker::working(start("")));
    true
}

impl Picker {
    fn working(rx: Receiver<DriveEvent>) -> Self {
        Self { rx, phase: Phase::Working(SIGNING_IN), files: Vec::new(), selected: None, client_id: String::new(), client_error: None }
    }

    fn explain(message: &str) -> Self {
        let (tx, rx) = channel();
        drop(tx);
        Self { rx, phase: Phase::Error(message.to_string()), files: Vec::new(), selected: None, client_id: String::new(), client_error: None }
    }
}

/// A Google OAuth client id (`123-abc.apps.googleusercontent.com`). Anything else is refused
/// before it is stored or sent.
pub fn valid_client_id(id: &str) -> bool {
    let id = id.trim();
    let Some(rest) = id.strip_suffix(".apps.googleusercontent.com") else { return false };
    if rest.len() < 3 || rest.len() > 120 {
        return false;
    }
    let Some((nums, tail)) = rest.split_once('-') else { return false };
    !nums.is_empty() && nums.bytes().all(|b| b.is_ascii_digit()) && !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// How to turn this Drive file into something `file.open` already accepts.
pub fn plan(id: &str, name: &str, mime: &str) -> Result<OpenPlan, &'static str> {
    if !safe_id(id) {
        return Err("That Google Drive file id isn't usable.");
    }
    if mime.eq_ignore_ascii_case("application/vnd.google-apps.spreadsheet") || mime.eq_ignore_ascii_case("application/vnd.google-apps.presentation") {
        return Err("Google Sheets and Google Slides aren't opened in WordCraft.");
    }
    if mime.eq_ignore_ascii_case(GOOGLE_DOC) {
        return Ok(OpenPlan { name: export_name(name), export_docx: true });
    }
    if let Some((_, ext)) = DOWNLOAD.iter().find(|(m, _)| mime.eq_ignore_ascii_case(m)) {
        return Ok(OpenPlan { name: download_name(name, ext), export_docx: false });
    }
    Err("That Google Drive file can't be opened here.")
}

/// Whether a host may fetch `req`. The id goes into a Drive URL; the name is only a file name.
pub fn accept_fetch(req: &DriveRequest) -> bool {
    if !safe_id(&req.id) {
        return false;
    }
    let name = req.name.trim();
    if name.is_empty() || name.len() > 240 {
        return false;
    }
    if name.chars().any(|c| c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    if req.export_docx {
        return lower.ends_with(".docx");
    }
    KEEP_EXT.iter().any(|ext| lower.ends_with(&format!(".{ext}")))
}

/// `files.list` for the types [`plan`] can open, newest first. `page_token` is the previous
/// page's token; a token with unexpected characters is refused.
pub fn list_url(page_token: Option<&str>) -> Option<String> {
    if let Some(token) = page_token
        && !safe_page_token(token)
    {
        return None;
    }
    let mut url = format!(
        "https://www.googleapis.com/drive/v3/files?pageSize=50&orderBy=modifiedTime%20desc&fields={fields}&q={q}&supportsAllDrives=true&includeItemsFromAllDrives=true",
        fields = encode_query("files(id,name,mimeType),nextPageToken"),
        q = encode_query(&list_query()),
    );
    if let Some(token) = page_token {
        url.push_str("&pageToken=");
        url.push_str(&encode_query(token));
    }
    Some(url)
}

/// Download URL for an Office, text or OpenDocument file. The id is not escaped into the path
/// unless it is a Drive id.
pub fn media_url(id: &str) -> Option<String> {
    if !safe_id(id) {
        return None;
    }
    Some(format!("https://www.googleapis.com/drive/v3/files/{id}?alt=media&supportsAllDrives=true"))
}

/// Export URL: a Google Doc as .docx.
pub fn export_url(id: &str) -> Option<String> {
    if !safe_id(id) {
        return None;
    }
    Some(format!("https://www.googleapis.com/drive/v3/files/{id}/export?mimeType={}&supportsAllDrives=true", encode_query(EXPORT_DOCX)))
}

/// Percent-encode one query component (RFC 3986 unreserved characters stay as they are).
pub fn encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decode a query component. Bad `%` sequences are left as written.
pub fn decode_query_component(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(b) = hex_byte(bytes[i + 1], bytes[i + 2])
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse a `files.list` body. Entries without a usable id or type are skipped. A body that is
/// not a list, or is enormous, is an error.
pub fn parse_file_list(text: &str) -> Result<FilePage, &'static str> {
    if text.len() > 1_000_000 {
        return Err("Google Drive's file list was too large to read.");
    }
    let v: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Err("Google Drive sent a file list WordCraft couldn't read."),
    };
    let Some(files) = v.get("files").and_then(Value::as_array) else {
        if v.as_object().is_some() && v.get("error").is_none() {
            return Ok(FilePage { files: Vec::new(), next_page_token: None });
        }
        return Err("Google Drive sent a file list WordCraft couldn't read.");
    };
    let mut out = Vec::new();
    for item in files.iter().take(200) {
        let Some(obj) = item.as_object() else { continue };
        let Some(id) = obj.get("id").and_then(Value::as_str).filter(|id| safe_id(id)) else { continue };
        let name = obj.get("name").and_then(Value::as_str).unwrap_or("");
        let name: String = name.chars().take(500).collect();
        let Some(mime) = obj.get("mimeType").and_then(Value::as_str) else { continue };
        if mime.len() > 200 || mime.chars().any(|c| c.is_control()) {
            continue;
        }
        out.push(DriveFile { id: id.to_string(), name, mime: mime.to_string() });
    }
    let next = v.get("nextPageToken").and_then(Value::as_str).filter(|t| safe_page_token(t)).map(str::to_string);
    Ok(FilePage { files: out, next_page_token: next })
}

/// `error.message` from a Drive error body, with controls removed and the length capped.
/// `None` when the body is not that shape.
pub fn api_error_message(text: &str) -> Option<String> {
    let end = text.char_indices().nth(8_000).map(|(i, _)| i).unwrap_or(text.len());
    let v: Value = serde_json::from_str(&text[..end]).ok()?;
    let msg = v.get("error")?.get("message")?.as_str()?;
    let msg: String = msg.chars().filter(|c| !c.is_control()).take(180).collect();
    if msg.is_empty() { None } else { Some(msg) }
}

/// A short label for the picker's type column.
pub fn kind_label(mime: &str) -> &'static str {
    if mime.eq_ignore_ascii_case(GOOGLE_DOC) {
        "Google Doc"
    } else if mime.eq_ignore_ascii_case("application/msword") {
        "Word 97-2003 document"
    } else if mime.eq_ignore_ascii_case("application/vnd.oasis.opendocument.text") {
        "OpenDocument text"
    } else if mime.eq_ignore_ascii_case("application/rtf") || mime.eq_ignore_ascii_case("text/rtf") {
        "Rich Text"
    } else if mime.eq_ignore_ascii_case("text/plain")
        || mime.eq_ignore_ascii_case("text/markdown")
        || mime.eq_ignore_ascii_case("text/html")
        || mime.eq_ignore_ascii_case("application/json")
        || mime.eq_ignore_ascii_case("application/xml")
        || mime.eq_ignore_ascii_case("text/xml")
        || mime.eq_ignore_ascii_case("application/x-tex")
        || mime.eq_ignore_ascii_case("text/x-tex")
    {
        "Text"
    } else {
        "Word document"
    }
}

fn list_query() -> String {
    let mut parts = Vec::with_capacity(DOWNLOAD.len() + 1);
    parts.push(format!("mimeType='{GOOGLE_DOC}'"));
    for (mime, _) in DOWNLOAD {
        parts.push(format!("mimeType='{mime}'"));
    }
    format!("({}) and trashed=false", parts.join(" or "))
}

fn safe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 256 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn safe_page_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 512
        && token.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'=' | b'+' | b'/'))
}

fn hex_byte(hi: u8, lo: u8) -> Option<u8> {
    Some((hex_val(hi)? << 4) | hex_val(lo)?)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn sanitize_base(name: &str) -> String {
    let out: String =
        name.chars().filter(|c| !c.is_control() && !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')).take(180).collect();
    let out = out.trim().trim_matches('.').trim();
    if out.is_empty() { "Document".to_string() } else { out.to_string() }
}

fn download_name(name: &str, ext: &str) -> String {
    let base = sanitize_base(name);
    let lower = base.to_ascii_lowercase();
    if KEEP_EXT.iter().any(|e| lower.ends_with(&format!(".{e}"))) { base } else { format!("{base}.{ext}") }
}

fn export_name(name: &str) -> String {
    let mut base = sanitize_base(name);
    let lower = base.to_ascii_lowercase();
    for ext in KEEP_EXT {
        let suffix = format!(".{ext}");
        if lower.ends_with(&suffix) {
            base.truncate(base.len() - suffix.len());
            break;
        }
    }
    let base = base.trim().trim_matches('.').trim();
    let base = if base.is_empty() { "Document" } else { base };
    if base.to_ascii_lowercase().ends_with(".docx") { base.to_string() } else { format!("{base}.docx") }
}

fn display_name(name: &str) -> String {
    let clean = sanitize_base(name);
    let mut chars = clean.chars();
    let short: String = chars.by_ref().take(80).collect();
    if chars.next().is_some() { format!("{short}…") } else { short }
}

fn clean_message(s: &str) -> String {
    let out: String = s.chars().filter(|c| !c.is_control()).take(300).collect();
    if out.trim().is_empty() { "Couldn't open the file from Google Drive.".to_string() } else { out }
}

fn sanitize_files(files: Vec<DriveFile>) -> Vec<DriveFile> {
    files
        .into_iter()
        .filter(|f| safe_id(&f.id) && f.mime.len() <= 200 && f.name.len() <= 500 && !f.mime.chars().any(|c| c.is_control()))
        .take(150)
        .collect()
}

/// Apply host events. A dropped host fails only while sign-in or a download is still running;
/// once the list is on screen the user can still choose.
pub(crate) fn poll(app: &mut WordApp) {
    for _ in 0..8 {
        let event = {
            let Some(picker) = &app.drive_picker else { return };
            match picker.rx.try_recv() {
                Ok(event) => event,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    if !matches!(picker.phase, Phase::Working(_)) {
                        return;
                    }
                    DriveEvent::Error("Google Drive closed before it finished.".into())
                }
            }
        };
        apply(app, event);
    }
}

fn apply(app: &mut WordApp, event: DriveEvent) {
    let Some(picker) = &mut app.drive_picker else { return };
    match event {
        DriveEvent::NeedClientId => picker.phase = Phase::NeedClientId,
        DriveEvent::Listing => picker.phase = Phase::Working(LOADING),
        DriveEvent::Files(files) => {
            picker.files = sanitize_files(files);
            picker.selected = None;
            picker.phase = Phase::Choose;
        }
        DriveEvent::Error(msg) => picker.phase = Phase::Error(clean_message(&msg)),
    }
}

/// `file.open` from the inbox finished a Drive choice: close the picker, or show why it failed.
pub(crate) fn note_opened(app: &mut WordApp, result: &Result<Value, String>) {
    let opening = app.drive_picker.as_ref().is_some_and(|p| matches!(p.phase, Phase::Working(OPENING)));
    if !opening {
        return;
    }
    match result {
        Ok(_) => app.drive_picker = None,
        Err(e) => {
            if let Some(picker) = &mut app.drive_picker {
                picker.phase = Phase::Error(clean_message(e));
            }
        }
    }
}

/// Choose the file at `index`. Sheets and Slides stay listed only if a host sent them; choosing
/// one does not fetch.
#[cfg(test)]
pub(crate) fn open_index(app: &mut WordApp, index: usize) {
    let Some(mut picker) = app.drive_picker.take() else { return };
    open_file(app, &mut picker, index);
    app.drive_picker = Some(picker);
}

fn open_file(app: &mut WordApp, picker: &mut Picker, index: usize) {
    if matches!(picker.phase, Phase::Working(_)) {
        return;
    }
    let Some(file) = picker.files.get(index).cloned() else { return };
    let plan = match plan(&file.id, &file.name, &file.mime) {
        Ok(plan) => plan,
        Err(msg) => {
            app.status(tl!(msg));
            return;
        }
    };
    let req = DriveRequest { id: file.id, name: plan.name, export_docx: plan.export_docx };
    let Some(fetch) = &app.services.fetch_drive else {
        app.status(tl!("Open from Google Drive is available in the web app."));
        return;
    };
    fetch(req);
    picker.selected = Some(index);
    picker.phase = Phase::Working(OPENING);
}

fn submit_client_id(app: &mut WordApp, picker: &mut Picker) {
    let id = picker.client_id.trim().to_string();
    if !valid_client_id(&id) {
        picker.client_error = Some("That doesn't look like a Google OAuth client ID.");
        return;
    }
    picker.client_error = None;
    picker.client_id = id.clone();
    let Some(start) = &app.services.open_drive else {
        picker.phase = Phase::Error("Open from Google Drive is available in the web app.".into());
        return;
    };
    picker.rx = start(&id);
    picker.phase = Phase::Working(SIGNING_IN);
}

pub(crate) fn show(app: &mut WordApp, ctx: &egui::Context) {
    let Some(mut picker) = app.drive_picker.take() else { return };
    let mut open = true;
    let mut close = false;
    let shown = egui::Window::new(tl!("Open from Google Drive"))
        .id(egui::Id::new("open_from_drive"))
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, -40.0))
        .open(&mut open)
        .show(ctx, |ui| {
            ui.set_min_width(420.0);
            ui.set_max_width(520.0);
            close = picker_body(app, ui, &mut picker);
        });
    if shown.is_some() && (!open || close) {
        app.canvas.want_focus = true;
    } else {
        app.drive_picker = Some(picker);
    }
}

fn picker_body(app: &mut WordApp, ui: &mut egui::Ui, picker: &mut Picker) -> bool {
    match &picker.phase {
        Phase::Working(msg) => {
            let msg = *msg;
            ui.label(tl!(msg));
            ui.add_space(8.0);
            cancel_row(ui)
        }
        Phase::NeedClientId => client_form(app, ui, picker),
        Phase::Choose => file_list(app, ui, picker),
        Phase::Error(_) => error_view(ui, picker),
    }
}

fn client_form(app: &mut WordApp, ui: &mut egui::Ui, picker: &mut Picker) -> bool {
    ui.label(tl!(
        "This site has no Google client ID yet. Paste an OAuth client ID whose authorized origin is this page. It is saved in this browser only."
    ));
    ui.add_space(8.0);
    ui.label(tl!("Google OAuth client ID"));
    ui.add(
        egui::TextEdit::singleline(&mut picker.client_id).desired_width(ui.available_width()).hint_text("1234567890-abc.apps.googleusercontent.com"),
    );
    if let Some(err) = picker.client_error {
        ui.label(tl!(err));
    }
    let (ok, cancel) = action_row(ui, tl!("Continue"), true);
    if cancel || escape(ui) {
        return true;
    }
    if ok || enter(ui) {
        submit_client_id(app, picker);
    }
    false
}

fn file_list(app: &mut WordApp, ui: &mut egui::Ui, picker: &mut Picker) -> bool {
    let rows: Vec<(String, String)> = picker.files.iter().map(|f| (f.name.clone(), f.mime.clone())).collect();
    if rows.is_empty() {
        ui.label(tl!("No documents in Google Drive match the files WordCraft can open."));
        ui.add_space(8.0);
        return cancel_row(ui);
    }
    let mut pick = picker.selected;
    let mut open_now = None;
    egui::ScrollArea::vertical().id_salt("drive_file_list").max_height(280.0).show(ui, |ui| {
        for (i, (name, mime)) in rows.iter().enumerate() {
            let label = format!("{}  ·  {}", display_name(name), tl!(kind_label(mime)));
            let resp = ui.selectable_label(pick == Some(i), label);
            if resp.double_clicked() {
                open_now = Some(i);
            } else if resp.clicked() {
                pick = Some(i);
            }
        }
    });
    picker.selected = pick;
    let (ok, cancel) = action_row(ui, tl!("Open"), pick.is_some());
    if cancel || escape(ui) {
        return true;
    }
    if let Some(index) = open_now.or(if ok || enter(ui) { pick } else { None }) {
        open_file(app, picker, index);
    }
    false
}

fn error_view(ui: &mut egui::Ui, picker: &mut Picker) -> bool {
    let msg = match &picker.phase {
        Phase::Error(msg) => msg.clone(),
        _ => return false,
    };
    ui.label(crate::i18n::t(&msg).to_string());
    ui.add_space(8.0);
    let mut close = false;
    let mut back = false;
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(crate::widgets::primary_button(ui, tl!("Close"))).clicked() {
                close = true;
            }
            if !picker.files.is_empty() && ui.button(tl!("Back")).clicked() {
                back = true;
            }
        });
    });
    if back {
        picker.phase = Phase::Choose;
    }
    close || escape(ui)
}

fn action_row(ui: &mut egui::Ui, ok: &str, ok_enabled: bool) -> (bool, bool) {
    let mut clicked = (false, false);
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button(tl!("Cancel")).clicked() {
                clicked.1 = true;
            }
            if ui.add_enabled(ok_enabled, crate::widgets::primary_button(ui, ok)).clicked() {
                clicked.0 = true;
            }
        });
    });
    clicked
}

fn cancel_row(ui: &mut egui::Ui) -> bool {
    ui.add_space(8.0);
    let mut cancel = false;
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button(tl!("Cancel")).clicked() {
                cancel = true;
            }
        });
    });
    cancel || escape(ui)
}

fn escape(ui: &egui::Ui) -> bool {
    !crate::colors::is_open(ui.ctx()) && ui.input(|i| i.key_pressed(egui::Key::Escape))
}

fn enter(ui: &egui::Ui) -> bool {
    !crate::colors::is_open(ui.ctx()) && ui.input(|i| i.key_pressed(egui::Key::Enter))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::mpsc::Sender;

    use super::*;
    use crate::Services;
    use serde_json::json;

    fn app() -> WordApp {
        WordApp::new(wordcraft_engine::Session::new(wordcraft_doc::Document::new()), Services::default())
    }

    struct Host {
        app: WordApp,
        tx: Rc<RefCell<Option<Sender<DriveEvent>>>>,
        fetched: Rc<RefCell<Vec<DriveRequest>>>,
        inbox: crate::Inbox,
    }

    fn host() -> Host {
        let tx = Rc::new(RefCell::new(None));
        let fetched = Rc::new(RefCell::new(Vec::new()));
        let inbox: crate::Inbox = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let services = Services {
            open_drive: Some(Box::new({
                let tx = tx.clone();
                move |_| {
                    let (send, recv) = channel();
                    *tx.borrow_mut() = Some(send);
                    recv
                }
            })),
            fetch_drive: Some(Box::new({
                let fetched = fetched.clone();
                let inbox = inbox.clone();
                move |req| {
                    if req.name.ends_with(".txt") {
                        inbox.lock().unwrap_or_else(|e| e.into_inner()).push((req.name.clone(), b"Hello from Drive\n".to_vec()));
                    }
                    fetched.borrow_mut().push(req);
                }
            })),
            inbox: Some(inbox.clone()),
            ..Default::default()
        };
        Host { app: WordApp::new(wordcraft_engine::Session::new(wordcraft_doc::Document::new()), services), tx, fetched, inbox }
    }

    fn send(host: &Host, event: DriveEvent) {
        host.tx.borrow().as_ref().unwrap().send(event).unwrap();
    }

    #[test]
    fn plans_export_and_download_and_refuses_sheets() {
        let doc = plan("abc_DEF-1", "Notes", GOOGLE_DOC).unwrap();
        assert!(doc.export_docx);
        assert_eq!(doc.name, "Notes.docx");
        let kept = plan("abc", "Notes.DOCX", EXPORT_DOCX).unwrap();
        assert!(!kept.export_docx && kept.name == "Notes.DOCX");
        assert_eq!(plan("abc", "Letter", "application/msword").unwrap().name, "Letter.doc");
        assert_eq!(plan("abc", "Page", "application/vnd.oasis.opendocument.text").unwrap().name, "Page.odt");
        assert_eq!(plan("abc", "Plain.md", "text/plain").unwrap().name, "Plain.md");
        assert_eq!(plan("abc", "  ", "text/plain").unwrap().name, "Document.txt");
        let sneaky = plan("abc", "../../etc/passwd", "text/plain").unwrap();
        assert!(!sneaky.name.contains('/') && !sneaky.name.contains('\\'));
        assert_eq!(sneaky.name, "etcpasswd.txt");
        assert!(plan("abc", "Deck", "application/vnd.google-apps.presentation").unwrap_err().contains("Slides"));
        assert!(plan("abc", "Grid", "application/vnd.google-apps.spreadsheet").is_err());
        assert!(plan("../x", "Notes", "text/plain").is_err());
        assert!(plan("", "Notes", GOOGLE_DOC).is_err());
        let odd = plan("abc", "Report.txt", GOOGLE_DOC).unwrap();
        assert!(odd.export_docx && odd.name.ends_with(".docx") && !odd.name.to_ascii_lowercase().ends_with(".txt"));
    }

    #[test]
    fn client_ids_urls_and_list_parsing_are_strict() {
        assert!(valid_client_id("1234567890-abc.apps.googleusercontent.com"));
        assert!(!valid_client_id(""));
        assert!(!valid_client_id("javascript:alert(1)"));
        assert!(!valid_client_id("123-abc.apps.googleusercontent.com.evil.com"));
        assert!(!valid_client_id(&format!("{}-abc.apps.googleusercontent.com", "1".repeat(200))));
        let url = list_url(None).unwrap();
        assert!(url.starts_with("https://www.googleapis.com/drive/v3/files?"));
        assert!(url.contains("trashed%3Dfalse") || url.contains("trashed=false"));
        assert!(url.contains(&encode_query(GOOGLE_DOC)));
        assert!(url.contains(&encode_query(EXPORT_DOCX)));
        assert!(!url.contains("spreadsheet") && !url.contains("presentation"));
        assert!(list_url(Some("abc/def+=")).unwrap().contains("pageToken=abc%2Fdef%2B%3D"));
        assert!(list_url(Some("a&b")).is_none());
        assert!(media_url("abc_DEF-1").unwrap().contains("alt=media"));
        assert!(!media_url("abc_DEF-1").unwrap().contains("/export"));
        assert!(media_url("../x").is_none());
        assert!(export_url("abc").unwrap().contains("/export?mimeType="));
        assert!(export_url("abc").unwrap().contains(&encode_query(EXPORT_DOCX)));
        assert_eq!(decode_query_component("a%2Fb+c"), "a/b c");
        assert_eq!(DRIVE_READONLY, "https://www.googleapis.com/auth/drive.readonly");
        assert_eq!(MAX_FILE_BYTES, 80 << 20);

        let page = parse_file_list(
            r#"{"nextPageToken":"tok/1","files":[null,{"id":"../x","name":"no","mimeType":"text/plain"},{"id":"good_1","name":"Notes","mimeType":"text/plain"},{"mimeType":"text/plain"}]}"#,
        )
        .unwrap();
        assert_eq!(page.files, vec![DriveFile { id: "good_1".into(), name: "Notes".into(), mime: "text/plain".into() }]);
        assert_eq!(page.next_page_token.as_deref(), Some("tok/1"));
        assert!(parse_file_list("[").is_err());
        assert!(parse_file_list(&"a".repeat(1_000_001)).is_err());
        assert!(parse_file_list("{}").unwrap().files.is_empty());
        let huge = "m".repeat(400);
        let body = format!(r#"{{"error":{{"message":"{huge}\nmore"}}}}"#);
        let msg = api_error_message(&body).unwrap();
        assert!(msg.chars().count() <= 180 && !msg.contains('\n'));
        assert!(api_error_message("nope").is_none());
        assert!(accept_fetch(&DriveRequest { id: "abc".into(), name: "Notes.docx".into(), export_docx: true }));
        assert!(!accept_fetch(&DriveRequest { id: "a/b".into(), name: "Notes.docx".into(), export_docx: true }));
        assert!(!accept_fetch(&DriveRequest { id: "abc".into(), name: "Notes.txt".into(), export_docx: true }));
    }

    #[test]
    fn desktop_explains_and_does_not_start() {
        let mut app = app();
        let started = app.run("ui.openFromDrive", json!({"path": 1, "data": null})).unwrap();
        assert_eq!(started["started"], false);
        assert!(matches!(&app.drive_picker.as_ref().unwrap().phase, Phase::Error(m) if m.contains("web app")));
    }

    #[test]
    fn picker_lists_exports_and_opens_through_file_open() {
        let mut host = host();
        assert_eq!(host.app.run("ui.openFromDrive", json!({})).unwrap()["started"], true);
        assert!(matches!(host.app.drive_picker.as_ref().unwrap().phase, Phase::Working(_)));
        send(
            &host,
            DriveEvent::Files(vec![
                DriveFile { id: "doc1".into(), name: "Essay".into(), mime: GOOGLE_DOC.into() },
                DriveFile { id: "bad".into(), name: "Deck".into(), mime: "application/vnd.google-apps.presentation".into() },
                DriveFile { id: "txt1".into(), name: "Hello".into(), mime: "text/plain".into() },
            ]),
        );
        poll(&mut host.app);
        assert!(matches!(host.app.drive_picker.as_ref().unwrap().phase, Phase::Choose));
        open_index(&mut host.app, 1);
        assert!(host.fetched.borrow().is_empty(), "slides are not fetched");
        assert!(host.app.status_msg.as_ref().unwrap().0.contains("Slides"));
        open_index(&mut host.app, 0);
        assert_eq!(host.fetched.borrow()[0].name, "Essay.docx");
        assert!(host.fetched.borrow()[0].export_docx);
        assert!(matches!(host.app.drive_picker.as_ref().unwrap().phase, Phase::Working(OPENING)));
        // A second choice while the download is in flight does nothing.
        open_index(&mut host.app, 2);
        assert_eq!(host.fetched.borrow().len(), 1);

        // The text file: fetch pushes bytes, and the inbox opens them with file.open.
        host.app.drive_picker.as_mut().unwrap().phase = Phase::Choose;
        open_index(&mut host.app, 2);
        assert_eq!(host.fetched.borrow()[1].name, "Hello.txt");
        assert!(!host.fetched.borrow()[1].export_docx);
        host.app.drain_inbox();
        assert!(host.app.drive_picker.is_none());
        assert!(!host.app.ui.backstage);
        assert_eq!(host.app.session.doc.plain_text(wordcraft_doc::StoryRef::Body), "Hello from Drive\n");
        assert_eq!(host.inbox.lock().unwrap().len(), 0);
    }

    #[test]
    fn need_client_id_rejects_junk_and_a_dropped_host_fails_only_while_working() {
        let mut host = host();
        host.app.run("ui.openFromDrive", json!({})).unwrap();
        send(&host, DriveEvent::NeedClientId);
        poll(&mut host.app);
        assert!(matches!(host.app.drive_picker.as_ref().unwrap().phase, Phase::NeedClientId));
        {
            let mut picker = host.app.drive_picker.take().unwrap();
            picker.client_id = "not a client".into();
            submit_client_id(&mut host.app, &mut picker);
            assert!(picker.client_error.is_some());
            assert!(matches!(picker.phase, Phase::NeedClientId));
            host.app.drive_picker = Some(picker);
        }
        send(&host, DriveEvent::Error(format!("nope\0{}", "x".repeat(500))));
        poll(&mut host.app);
        match &host.app.drive_picker.as_ref().unwrap().phase {
            Phase::Error(msg) => {
                assert!(msg.chars().count() <= 300 && !msg.contains('\0'));
            }
            other => panic!("expected error, got {other:?}"),
        }
        // Back to the list, then a dropped sender leaves the list up.
        send(&host, DriveEvent::Files(vec![DriveFile { id: "a".into(), name: "N".into(), mime: "text/plain".into() }]));
        poll(&mut host.app);
        *host.tx.borrow_mut() = None;
        poll(&mut host.app);
        assert!(matches!(host.app.drive_picker.as_ref().unwrap().phase, Phase::Choose));
        // While signing in, a dropped host is an error.
        host.app.drive_picker.as_mut().unwrap().phase = Phase::Working(SIGNING_IN);
        poll(&mut host.app);
        assert!(matches!(host.app.drive_picker.as_ref().unwrap().phase, Phase::Error(_)));
    }

    #[test]
    fn an_open_file_dialog_blocks_drive() {
        let shown = Rc::new(RefCell::new(0u32));
        // Keep the sender: dropping it answers the dialog at once, which is not "still open".
        let hold = Rc::new(RefCell::new(None));
        let mut app = WordApp::new(
            wordcraft_engine::Session::new(wordcraft_doc::Document::new()),
            Services {
                file_dialog: Some(Box::new({
                    let shown = shown.clone();
                    let hold = hold.clone();
                    move |_| {
                        *shown.borrow_mut() += 1;
                        let (tx, rx) = channel();
                        *hold.borrow_mut() = Some(tx);
                        rx
                    }
                })),
                open_drive: Some(Box::new(|_| channel().1)),
                ..Default::default()
            },
        );
        app.open_dialog();
        assert_eq!(*shown.borrow(), 1);
        assert_eq!(app.run("ui.openFromDrive", json!({})).unwrap()["started"], false);
        assert!(app.drive_picker.is_none());
    }
}
