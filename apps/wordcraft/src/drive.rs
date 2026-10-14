//! Open from Google Drive in the desktop app.
//!
//! Sign-in opens the system browser. Google redirects to a page on `127.0.0.1` that only this
//! process is listening on, with PKCE so the authorization code is tied to this request. A Google
//! Doc is exported as .docx; an Office, text or OpenDocument file is downloaded. The bytes go to
//! the inbox and open with `file.open`.
//!
//! The Desktop OAuth client id and secret are `WORDCRAFT_GOOGLE_CLIENT_ID` and
//! `WORDCRAFT_GOOGLE_CLIENT_SECRET`, or the values pasted in the dialog. Those are saved in
//! WordCraft's settings folder. The access token stays in memory for this run and is never logged.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use wordcraft_ui_egui::Inbox;
use wordcraft_ui_egui::drive::{self, DriveEvent, DriveLogin, DriveRequest};

const CLIENT_FILE: &str = "google-drive-client.json";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const AUTH_EXPIRED: &str = "Google Drive sign-in expired. Try again.";
const SIGN_IN_WAIT: Duration = Duration::from_secs(180);

struct Token {
    access: String,
    expires_at: Instant,
}

struct Inner {
    tx: Option<Sender<DriveEvent>>,
    token: Option<Token>,
}

struct Host {
    inner: Arc<Mutex<Inner>>,
    ctx: egui::Context,
    inbox: Inbox,
    /// Settings folder. `None` when preferences are off: the dialog still works, nothing is saved.
    settings: Option<PathBuf>,
}

pub struct Hooks {
    pub open_drive: Box<dyn Fn(DriveLogin) -> Receiver<DriveEvent>>,
    pub fetch_drive: Box<dyn Fn(DriveRequest)>,
}

pub fn hooks(ctx: egui::Context, inbox: Inbox, settings: Option<PathBuf>) -> Hooks {
    let host = Arc::new(Host { inner: Arc::new(Mutex::new(Inner { tx: None, token: None })), ctx, inbox, settings });
    let open_host = host.clone();
    let fetch_host = host;
    Hooks { open_drive: Box::new(move |login| begin(&open_host, login)), fetch_drive: Box::new(move |req| fetch(fetch_host.clone(), req)) }
}

fn begin(host: &Arc<Host>, login: DriveLogin) -> Receiver<DriveEvent> {
    let env_id = std::env::var("WORDCRAFT_GOOGLE_CLIENT_ID").ok();
    let env_secret = std::env::var("WORDCRAFT_GOOGLE_CLIENT_SECRET").ok();
    begin_from(host, login, env_id, env_secret)
}

fn begin_from(host: &Arc<Host>, login: DriveLogin, env_id: Option<String>, env_secret: Option<String>) -> Receiver<DriveEvent> {
    let (tx, rx) = std::sync::mpsc::channel();
    host.inner.lock().unwrap_or_else(|e| e.into_inner()).tx = Some(tx);
    let saved = host.settings.as_deref().and_then(read_saved);
    match resolve(&login, env_id.as_deref(), env_secret.as_deref(), saved.as_ref()) {
        Resolve::Missing => {
            send(host, DriveEvent::NeedClientId);
        }
        Resolve::Invalid(msg) => {
            send(host, DriveEvent::Error(msg.into()));
        }
        Resolve::Ready(creds) => {
            if let Some(dir) = &host.settings {
                save_client(dir, &creds);
            }
            if let Some(token) = fresh_token(host) {
                spawn_list(host.clone(), token);
            } else {
                spawn_sign_in(host.clone(), creds);
            }
        }
    }
    rx
}

struct Creds {
    id: String,
    secret: String,
}

enum Resolve {
    Missing,
    Invalid(&'static str),
    Ready(Creds),
}

/// Where the client id and secret come from. A typed id wins, then the environment, then the
/// settings file. A typed id without a usable secret is an error, not a silent fallback.
fn resolve(login: &DriveLogin, env_id: Option<&str>, env_secret: Option<&str>, saved: Option<&Creds>) -> Resolve {
    let typed = login.client_id.trim();
    if !typed.is_empty() {
        if !drive::valid_client_id(typed) {
            return Resolve::Invalid("That doesn't look like a Google OAuth client ID.");
        }
        if !drive::valid_client_secret(&login.client_secret) {
            return Resolve::Invalid("Paste the desktop client's secret too.");
        }
        return Resolve::Ready(Creds { id: typed.to_string(), secret: login.client_secret.trim().to_string() });
    }
    if let Some(id) = env_id.map(str::trim).filter(|s| !s.is_empty()) {
        if !drive::valid_client_id(id) {
            return Resolve::Invalid("WORDCRAFT_GOOGLE_CLIENT_ID is not a Google OAuth client ID.");
        }
        let secret = env_secret.unwrap_or("").trim();
        if !drive::valid_client_secret(secret) {
            return Resolve::Invalid("Set WORDCRAFT_GOOGLE_CLIENT_SECRET to the desktop client's secret.");
        }
        return Resolve::Ready(Creds { id: id.to_string(), secret: secret.to_string() });
    }
    if let Some(saved) = saved
        && drive::valid_client_id(&saved.id)
        && drive::valid_client_secret(&saved.secret)
    {
        return Resolve::Ready(Creds { id: saved.id.clone(), secret: saved.secret.clone() });
    }
    Resolve::Missing
}

fn spawn_sign_in(host: Arc<Host>, creds: Creds) {
    if std::thread::Builder::new().name("wordcraft-drive".into()).spawn(move || sign_in(host, creds)).is_err() {
        log::warn!("could not start Google Drive sign-in");
    }
}

fn sign_in(host: Arc<Host>, creds: Creds) {
    let result = (|| {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| "Couldn't wait for Google to return.".to_string())?;
        let port = listener.local_addr().map_err(|_| "Couldn't wait for Google to return.".to_string())?.port();
        let verifier = random_token(32).ok_or_else(|| "Couldn't start Google sign-in.".to_string())?;
        let state = random_token(16).ok_or_else(|| "Couldn't start Google sign-in.".to_string())?;
        let challenge = code_challenge(&verifier);
        let redirect = format!("http://127.0.0.1:{port}");
        let url = authorize_url(&creds.id, &redirect, &challenge, &state);
        log::info!("google drive sign-in waiting on 127.0.0.1:{port}");
        open::that_detached(&url).map_err(|_| "Couldn't open the browser for Google sign-in.".to_string())?;
        let code = wait_for_code(listener, &state)?;
        let token = exchange(&creds, &redirect, &verifier, &code)?;
        store_token(&host, &token);
        Ok::<_, String>(token.access)
    })();
    match result {
        Ok(access) => list_files(&host, &access),
        Err(e) => {
            log::warn!("google drive sign-in failed");
            send(&host, DriveEvent::Error(e));
        }
    }
}

fn spawn_list(host: Arc<Host>, token: String) {
    if std::thread::Builder::new().name("wordcraft-drive".into()).spawn(move || list_files(&host, &token)).is_err() {
        log::warn!("could not list Google Drive");
    }
}

fn list_files(host: &Host, token: &str) {
    if !send(host, DriveEvent::Listing) {
        return;
    }
    let mut page_token = None;
    let mut all = Vec::new();
    for _ in 0..3 {
        let Some(url) = drive::list_url(page_token.as_deref()) else { break };
        let (status, body) = match get_text(token, &url) {
            Ok(v) => v,
            Err(e) => {
                send(host, DriveEvent::Error(e));
                return;
            }
        };
        if status == 401 {
            clear_token(host);
            send(host, DriveEvent::Error(AUTH_EXPIRED.into()));
            return;
        }
        if status != 200 {
            let msg = drive::api_error_message(&body).unwrap_or_else(|| format!("Google Drive returned {status}."));
            send(host, DriveEvent::Error(msg));
            return;
        }
        match drive::parse_file_list(&body) {
            Ok(page) => {
                let next = page.next_page_token;
                all.extend(page.files);
                if next.is_none() || all.len() >= 150 {
                    break;
                }
                page_token = next;
            }
            Err(e) => {
                send(host, DriveEvent::Error(e.into()));
                return;
            }
        }
    }
    all.truncate(150);
    log::info!("google drive listed {} files", all.len());
    send(host, DriveEvent::Files(all));
}

fn fetch(host: Arc<Host>, req: DriveRequest) {
    if !drive::accept_fetch(&req) {
        send(&host, DriveEvent::Error("That Google Drive file can't be opened here.".into()));
        return;
    }
    let Some(token) = fresh_token(&host) else {
        send(&host, DriveEvent::Error(AUTH_EXPIRED.into()));
        return;
    };
    let Some(url) = (if req.export_docx { drive::export_url(&req.id) } else { drive::media_url(&req.id) }) else {
        send(&host, DriveEvent::Error("That Google Drive file can't be opened here.".into()));
        return;
    };
    if std::thread::Builder::new().name("wordcraft-drive".into()).spawn(move || download_into(host, token, url, req.name)).is_err() {
        log::warn!("could not download from Google Drive");
    }
}

fn download_into(host: Arc<Host>, token: String, url: String, name: String) {
    match download(&token, &url) {
        Ok(bytes) => {
            log::info!("opening {name} from Google Drive ({} bytes)", bytes.len());
            host.inbox.lock().unwrap_or_else(|e| e.into_inner()).push((name, bytes));
            host.ctx.request_repaint();
        }
        Err(e) => {
            if e == AUTH_EXPIRED {
                clear_token(&host);
            }
            log::warn!("google drive download failed");
            send(&host, DriveEvent::Error(e));
        }
    }
}

fn authorize_url(client_id: &str, redirect: &str, challenge: &str, state: &str) -> String {
    format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&code_challenge={}&code_challenge_method=S256&state={}&access_type=online",
        drive::encode_query(client_id),
        drive::encode_query(redirect),
        drive::encode_query(drive::DRIVE_READONLY),
        drive::encode_query(challenge),
        drive::encode_query(state),
    )
}

fn exchange(creds: &Creds, redirect: &str, verifier: &str, code: &str) -> Result<Token, String> {
    let body = form_pairs(&[
        ("code", code),
        ("client_id", &creds.id),
        ("client_secret", &creds.secret),
        ("redirect_uri", redirect),
        ("grant_type", "authorization_code"),
        ("code_verifier", verifier),
    ]);
    let (status, text) = post_form(TOKEN_URL, &body)?;
    if status != 200 {
        let msg = token_error(&text).unwrap_or_else(|| "Google sign-in failed.".to_string());
        return Err(msg);
    }
    parse_token(&text).ok_or_else(|| "Google didn't return a sign-in token.".to_string())
}

fn token_error(text: &str) -> Option<String> {
    let end = text.char_indices().nth(4_000).map(|(i, _)| i).unwrap_or(text.len());
    let v: serde_json::Value = serde_json::from_str(&text[..end]).ok()?;
    let code = v.get("error").and_then(|e| e.as_str()).unwrap_or("");
    match code {
        "invalid_client" => Some("Google refused that client. Use a Desktop OAuth client and its secret.".into()),
        "invalid_grant" => Some("Google sign-in expired before it finished. Try again.".into()),
        "access_denied" => Some("Google Drive access was cancelled.".into()),
        "" => None,
        _ => {
            let detail = v.get("error_description").and_then(|e| e.as_str()).unwrap_or("");
            let detail: String = detail.chars().filter(|c| !c.is_control()).take(180).collect();
            if detail.is_empty() { Some("Google sign-in failed.".into()) } else { Some(detail) }
        }
    }
}

fn parse_token(text: &str) -> Option<Token> {
    if text.len() > 16_000 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let access = v.get("access_token")?.as_str()?.to_string();
    if !safe_bearer(&access) {
        return None;
    }
    let expires_in = v.get("expires_in").and_then(serde_json::Value::as_f64).unwrap_or(3600.0);
    let expires_in = expires_in.clamp(0.0, 86_400.0);
    let skew = Duration::from_secs(60);
    let life = Duration::from_secs(expires_in as u64);
    let expires_at = Instant::now() + life.saturating_sub(skew);
    Some(Token { access, expires_at })
}

fn wait_for_code(listener: TcpListener, state: &str) -> Result<String, String> {
    listener.set_nonblocking(true).map_err(|_| "Couldn't wait for Google to return.".to_string())?;
    let deadline = Instant::now() + SIGN_IN_WAIT;
    let mut accepts = 0u32;
    while Instant::now() < deadline && accepts < 16 {
        match listener.accept() {
            Ok((mut stream, addr)) => {
                accepts += 1;
                if !addr.ip().is_loopback() {
                    continue;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let Ok(head) = read_head(&mut stream) else { continue };
                match classify_callback(&head, state) {
                    Callback::Code(code) => {
                        let _ = stream.write_all(&html_page(true));
                        return Ok(code);
                    }
                    Callback::Ignore => {}
                    Callback::Fail(msg) => {
                        let _ = stream.write_all(&html_page(false));
                        return Err(msg);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(40)),
            Err(_) => return Err("Couldn't wait for Google to return.".into()),
        }
    }
    Err("Google sign-in timed out. Try again.".into())
}

#[derive(Debug)]
enum Callback {
    Code(String),
    Ignore,
    Fail(String),
}

fn classify_callback(head: &str, expected_state: &str) -> Callback {
    let Some(line) = head.lines().next() else { return Callback::Ignore };
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "GET" {
        return Callback::Ignore;
    }
    let path = target.split('?').next().unwrap_or("");
    if path.contains("favicon") {
        return Callback::Ignore;
    }
    if path != "/" {
        return Callback::Fail("Google returned somewhere WordCraft was not listening.".into());
    }
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for part in query.split('&').take(16) {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        let v = drive::decode_query_component(v);
        match k {
            "code" => code = Some(v),
            "state" => state = Some(v),
            "error" => error = Some(v),
            _ => {}
        }
    }
    if let Some(error) = error.as_deref() {
        return Callback::Fail(if error == "access_denied" { "Google Drive access was cancelled.".into() } else { "Google sign-in failed.".into() });
    }
    if !state.as_deref().is_some_and(|s| same_ascii(s, expected_state)) {
        return Callback::Fail("Google sign-in didn't match this request. Try again.".into());
    }
    match code.filter(|c| safe_code(c)) {
        Some(code) => Callback::Code(code),
        None => Callback::Fail("Google didn't return a sign-in code.".into()),
    }
}

fn html_page(ok: bool) -> Vec<u8> {
    let body = if ok {
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>WordCraft</title></head><body><p>Signed in. You can close this tab and return to WordCraft.</p></body></html>"
    } else {
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>WordCraft</title></head><body><p>WordCraft could not finish signing in. Close this tab and try again from WordCraft.</p></body></html>"
    };
    let header = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let mut out = header.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn read_head(stream: &mut TcpStream) -> Result<String, ()> {
    let mut buf = [0u8; 8192];
    let mut n = 0;
    while n < buf.len() {
        match stream.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => {
                n += k;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(()),
        }
    }
    if n == 0 {
        return Err(());
    }
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

fn get_text(token: &str, url: &str) -> Result<(u16, String), String> {
    let bytes = request("GET", url, token, None)?;
    let status = bytes.0;
    if bytes.1.len() > 1_000_000 {
        return Err("Google Drive's file list was too large to read.".into());
    }
    Ok((status, String::from_utf8_lossy(&bytes.1).into_owned()))
}

fn download(token: &str, url: &str) -> Result<Vec<u8>, String> {
    let (status, bytes) = request("GET", url, token, None)?;
    if status == 401 {
        return Err(AUTH_EXPIRED.into());
    }
    if status != 200 {
        let text = String::from_utf8_lossy(&bytes);
        return Err(drive::api_error_message(&text).unwrap_or_else(|| format!("Google Drive returned {status}.")));
    }
    if bytes.is_empty() {
        return Err("The file from Google Drive was empty.".into());
    }
    Ok(bytes)
}

fn post_form(url: &str, body: &str) -> Result<(u16, String), String> {
    let (status, bytes) = request("POST", url, "", Some(body.as_bytes()))?;
    Ok((status, String::from_utf8_lossy(&bytes).chars().take(4_000).collect()))
}

/// `bearer` empty means a POST of `body` (the token exchange). Otherwise a GET with that bearer.
fn request(method: &str, url: &str, bearer: &str, body: Option<&[u8]>) -> Result<(u16, Vec<u8>), String> {
    if !url.starts_with("https://accounts.google.com/")
        && !url.starts_with("https://oauth2.googleapis.com/")
        && !url.starts_with("https://www.googleapis.com/")
    {
        return Err("Refused a Google Drive address that was not Google's.".into());
    }
    if method == "GET" && !safe_bearer(bearer) {
        return Err(AUTH_EXPIRED.into());
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(20))
        .timeout_read(Duration::from_secs(120))
        .timeout_write(Duration::from_secs(30))
        .build();
    let result = if method == "POST" {
        agent.post(url).set("Content-Type", "application/x-www-form-urlencoded").send_bytes(body.unwrap_or(b""))
    } else {
        agent.get(url).set("Authorization", &format!("Bearer {bearer}")).call()
    };
    let response = match result {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(_) => return Err("Couldn't reach Google Drive.".into()),
    };
    let status = response.status();
    response_bytes(status, response)
}

fn response_bytes(status: u16, response: ureq::Response) -> Result<(u16, Vec<u8>), String> {
    let mut reader = response.into_reader().take(drive::MAX_FILE_BYTES as u64 + 1);
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).map_err(|_| "Couldn't read Google Drive's reply.".to_string())?;
    if buf.len() > drive::MAX_FILE_BYTES {
        return Err("The file from Google Drive is larger than 80 MB.".into());
    }
    Ok((status, buf))
}

fn form_pairs(pairs: &[(&str, &str)]) -> String {
    pairs.iter().map(|(k, v)| format!("{}={}", drive::encode_query(k), drive::encode_query(v))).collect::<Vec<_>>().join("&")
}

fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random_token(bytes: usize) -> Option<String> {
    let mut buf = vec![0u8; bytes.min(64)];
    getrandom::fill(&mut buf).ok()?;
    Some(URL_SAFE_NO_PAD.encode(buf))
}

fn safe_bearer(token: &str) -> bool {
    !token.is_empty() && token.len() <= 8_192 && token.bytes().all(|b| b.is_ascii_graphic())
}

fn safe_code(code: &str) -> bool {
    (8..=512).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b'~'))
}

fn same_ascii(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn fresh_token(host: &Host) -> Option<String> {
    let guard = host.inner.lock().unwrap_or_else(|e| e.into_inner());
    guard.token.as_ref().filter(|t| t.expires_at > Instant::now() && safe_bearer(&t.access)).map(|t| t.access.clone())
}

fn store_token(host: &Host, token: &Token) {
    host.inner.lock().unwrap_or_else(|e| e.into_inner()).token = Some(Token { access: token.access.clone(), expires_at: token.expires_at });
}

fn clear_token(host: &Host) {
    host.inner.lock().unwrap_or_else(|e| e.into_inner()).token = None;
}

fn send(host: &Host, event: DriveEvent) -> bool {
    let ok = host.inner.lock().unwrap_or_else(|e| e.into_inner()).tx.as_ref().is_some_and(|tx| tx.send(event).is_ok());
    host.ctx.request_repaint();
    ok
}

fn save_client(dir: &Path, creds: &Creds) {
    if !drive::valid_client_id(&creds.id) || !drive::valid_client_secret(&creds.secret) {
        return;
    }
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join(CLIENT_FILE);
    let raw = serde_json::json!({"client_id": creds.id, "client_secret": creds.secret}).to_string();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(mut file) = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path) {
            let _ = file.write_all(raw.as_bytes());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(&path, raw.as_bytes());
    }
}

fn read_saved(dir: &Path) -> Option<Creds> {
    let raw = std::fs::read(dir.join(CLIENT_FILE)).ok()?;
    if raw.len() > 4_096 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let id = v.get("client_id")?.as_str()?.to_string();
    let secret = v.get("client_secret")?.as_str()?.to_string();
    (drive::valid_client_id(&id) && drive::valid_client_secret(&secret)).then_some(Creds { id, secret })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(id: &str, secret: &str) -> Creds {
        Creds { id: id.into(), secret: secret.into() }
    }

    #[test]
    fn pkce_matches_the_published_vector() {
        // RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(code_challenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn authorize_url_is_google_and_carries_no_secret() {
        let url = authorize_url("123-abc.apps.googleusercontent.com", "http://127.0.0.1:9", "challenge", "state");
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A9"));
        assert!(url.contains("code_challenge=challenge"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains(&drive::encode_query(drive::DRIVE_READONLY)));
        assert!(!url.contains("secret") && !url.contains("GOCSPX"));
    }

    #[test]
    fn callback_checks_state_and_ignores_favicon() {
        let ok = "GET /?code=4/0Aabc_def-123.xyz&state=STATE HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        match classify_callback(ok, "STATE") {
            Callback::Code(code) => assert_eq!(code, "4/0Aabc_def-123.xyz"),
            other => panic!("expected code, got {other:?}"),
        }
        assert!(matches!(classify_callback("GET /favicon.ico HTTP/1.1\r\n\r\n", "STATE"), Callback::Ignore));
        assert!(matches!(
            classify_callback("GET /?error=access_denied&state=STATE HTTP/1.1\r\n\r\n", "STATE"),
            Callback::Fail(msg) if msg.contains("cancelled")
        ));
        assert!(matches!(classify_callback("GET /?code=4/0Aabc_def&state=OTHER HTTP/1.1\r\n\r\n", "STATE"), Callback::Fail(_)));
        assert!(matches!(classify_callback("GET /evil?code=4/0Aabc_def&state=STATE HTTP/1.1\r\n\r\n", "STATE"), Callback::Fail(_)));
        let page = html_page(true);
        let text = String::from_utf8(page).unwrap();
        assert!(text.contains("Content-Length:") && text.contains("return to WordCraft") && !text.contains("code="));
    }

    #[test]
    fn token_parse_refuses_a_token_that_is_not_a_bearer() {
        let token = parse_token(r#"{"access_token":"ya29.abc-DEF_123","expires_in":100}"#).unwrap();
        assert_eq!(token.access, "ya29.abc-DEF_123");
        assert!(token.expires_at > Instant::now());
        assert!(parse_token(r#"{"access_token":"has a space","expires_in":100}"#).is_none());
        assert!(parse_token(&format!(r#"{{"access_token":"{}"}}"#, "a".repeat(9000))).is_none());
        assert_eq!(
            token_error(r#"{"error":"invalid_client"}"#).as_deref(),
            Some("Google refused that client. Use a Desktop OAuth client and its secret.")
        );
    }

    #[test]
    fn resolve_prefers_what_was_typed_then_env_then_the_file() {
        let secret = "GOCSPX-abcdefghijklmnopqrstuv";
        let id = "123-abc.apps.googleusercontent.com";
        let saved = creds(id, secret);
        assert!(matches!(resolve(&DriveLogin::default(), None, None, None), Resolve::Missing));
        assert!(matches!(resolve(&DriveLogin { client_id: "nope".into(), client_secret: secret.into() }, None, None, None), Resolve::Invalid(_)));
        assert!(matches!(resolve(&DriveLogin { client_id: id.into(), client_secret: String::new() }, None, None, Some(&saved)), Resolve::Invalid(_)));
        match resolve(&DriveLogin { client_id: id.into(), client_secret: secret.into() }, None, None, None) {
            Resolve::Ready(c) => assert_eq!(c.id, id),
            _ => panic!("typed id"),
        }
        match resolve(&DriveLogin::default(), Some(id), Some(secret), None) {
            Resolve::Ready(c) => assert_eq!((c.id.as_str(), c.secret.as_str()), (id, secret)),
            _ => panic!("env"),
        }
        assert!(matches!(resolve(&DriveLogin::default(), Some(id), None, None), Resolve::Invalid(_)));
        match resolve(&DriveLogin::default(), None, None, Some(&saved)) {
            Resolve::Ready(c) => assert_eq!(c.secret, secret),
            _ => panic!("saved"),
        }
    }

    #[test]
    fn saved_client_is_private_and_a_missing_one_asks_without_a_browser() {
        let dir = std::env::temp_dir().join(format!("wordcraft-drive-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let secret = "GOCSPX-abcdefghijklmnopqrstuv";
        let id = "123-abc.apps.googleusercontent.com";
        save_client(&dir, &creds(id, secret));
        let loaded = read_saved(&dir).unwrap();
        assert_eq!(loaded.id, id);
        assert_eq!(loaded.secret, secret);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(CLIENT_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "the client file is not private: {mode:o}");
        }
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let host = Arc::new(Host {
            inner: Arc::new(Mutex::new(Inner { tx: None, token: None })),
            ctx: egui::Context::default(),
            inbox: Arc::new(Mutex::new(Vec::new())),
            settings: Some(dir.clone()),
        });
        // No environment and no saved client: ask. This must not open a browser.
        let rx = begin_from(&host, DriveLogin::default(), None, None);
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, DriveEvent::NeedClientId));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
