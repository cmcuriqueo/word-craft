//! Open from Google Drive in the browser.
//!
//! Google Identity Services (`https://accounts.google.com/gsi/client`) asks for
//! `https://www.googleapis.com/auth/drive.readonly`. The script is added when the page starts so
//! the consent popup can open in the click that asked for it. A Google Doc is exported as .docx;
//! an Office, text or OpenDocument file is downloaded. The bytes go to the inbox and open with
//! `file.open`, the same path as a file from the browser's picker.
//!
//! The OAuth client id is `WORDCRAFT_GOOGLE_CLIENT_ID` at build time, otherwise one saved in this
//! browser (`wordcraft.google.clientId`, also accepted once as `?google_client_id=`). The access
//! token stays in the tab (`sessionStorage`). It is never written to the document or to a log.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::Receiver;

use wasm_bindgen::JsCast as _;
use wasm_bindgen::closure::Closure;
use wordcraft_ui_egui::Inbox;
use wordcraft_ui_egui::drive::{self, DriveEvent, DriveRequest};

const CLIENT_KEY: &str = "wordcraft.google.clientId";
const TOKEN_KEY: &str = "wordcraft.google.driveToken";
const SCRIPT_ID: &str = "wordcraft-gis";
const SCRIPT_SRC: &str = "https://accounts.google.com/gsi/client";
const AUTH_EXPIRED: &str = "Google Drive sign-in expired. Try again.";
const NOT_READY: &str = "Google sign-in isn't ready yet. Try again in a moment.";

struct Token {
    access: String,
    expires_at_ms: f64,
}

struct Inner {
    tx: Option<std::sync::mpsc::Sender<DriveEvent>>,
    token: Option<Token>,
    force_consent: bool,
    ctx: egui::Context,
    inbox: Inbox,
}

struct DriveHost {
    inner: Rc<RefCell<Inner>>,
    token_cb: RefCell<Option<Closure<dyn FnMut(wasm_bindgen::JsValue)>>>,
    token_err: RefCell<Option<Closure<dyn FnMut(wasm_bindgen::JsValue)>>>,
}

pub struct Hooks {
    pub open_drive: Box<dyn Fn(&str) -> Receiver<DriveEvent>>,
    pub fetch_drive: Box<dyn Fn(DriveRequest)>,
}

/// Load the sign-in script once, and keep a client id passed in the page address.
pub fn preload() {
    absorb_query_client_id();
    let Some(document) = web_sys::window().and_then(|w| w.document()) else { return };
    if document.get_element_by_id(SCRIPT_ID).is_some() {
        return;
    }
    let Ok(el) = document.create_element("script") else {
        log::warn!("couldn't create the Google sign-in script");
        return;
    };
    let Ok(script) = el.dyn_into::<web_sys::HtmlScriptElement>() else { return };
    script.set_id(SCRIPT_ID);
    script.set_async(true);
    script.set_src(SCRIPT_SRC);
    if let Some(head) = document.head()
        && head.append_child(&script).is_err()
    {
        log::warn!("couldn't add the Google sign-in script");
    }
}

pub fn hooks(ctx: egui::Context, inbox: Inbox) -> Hooks {
    preload();
    let host = Rc::new(DriveHost {
        inner: Rc::new(RefCell::new(Inner { tx: None, token: None, force_consent: false, ctx, inbox })),
        token_cb: RefCell::new(None),
        token_err: RefCell::new(None),
    });
    let open_host = host.clone();
    let fetch_inner = host.inner.clone();
    Hooks { open_drive: Box::new(move |id| open(&open_host, id)), fetch_drive: Box::new(move |req| fetch(fetch_inner.clone(), req)) }
}

fn open(host: &Rc<DriveHost>, client_id: &str) -> Receiver<DriveEvent> {
    let (tx, rx) = std::sync::mpsc::channel();
    host.inner.borrow_mut().tx = Some(tx.clone());
    match resolve_client_id(client_id) {
        ClientId::Missing => send(&host.inner, DriveEvent::NeedClientId),
        ClientId::Invalid => send(&host.inner, DriveEvent::Error("That doesn't look like a Google OAuth client ID.".into())),
        ClientId::Id(id) => {
            if let Some(token) = fresh_token(host) {
                spawn_list(host.inner.clone(), token);
            } else if let Err(e) = request_token(host, &id) {
                send(&host.inner, DriveEvent::Error(e));
            }
        }
    }
    rx
}

enum ClientId {
    Missing,
    Invalid,
    Id(String),
}

fn resolve_client_id(passed: &str) -> ClientId {
    let passed = passed.trim();
    if !passed.is_empty() {
        return if drive::valid_client_id(passed) {
            save_client_id(passed);
            ClientId::Id(passed.to_string())
        } else {
            ClientId::Invalid
        };
    }
    if let Some(built) = option_env!("WORDCRAFT_GOOGLE_CLIENT_ID") {
        let built = built.trim();
        if drive::valid_client_id(built) {
            return ClientId::Id(built.to_string());
        }
    }
    if let Some(stored) = read_client_id() {
        return ClientId::Id(stored);
    }
    ClientId::Missing
}

fn request_token(host: &Rc<DriveHost>, client_id: &str) -> Result<(), String> {
    let window = web_sys::window().ok_or_else(|| "no window".to_string())?;
    let oauth2 = google_oauth2(&window)?;
    let init: js_sys::Function = prop(&oauth2, "initTokenClient").and_then(|v| v.dyn_into().ok()).ok_or_else(|| NOT_READY.to_string())?;
    let inner = host.inner.clone();
    let callback = Closure::wrap(Box::new(move |resp: wasm_bindgen::JsValue| on_token(&inner, resp)) as Box<dyn FnMut(wasm_bindgen::JsValue)>);
    let inner = host.inner.clone();
    let error_callback =
        Closure::wrap(Box::new(move |err: wasm_bindgen::JsValue| on_token_error(&inner, err)) as Box<dyn FnMut(wasm_bindgen::JsValue)>);
    let opts = js_sys::Object::new();
    set_str(&opts, "client_id", client_id);
    set_str(&opts, "scope", drive::DRIVE_READONLY);
    let _ = js_sys::Reflect::set(&opts, &wasm_bindgen::JsValue::from_str("callback"), callback.as_ref());
    let _ = js_sys::Reflect::set(&opts, &wasm_bindgen::JsValue::from_str("error_callback"), error_callback.as_ref());
    let client = init.call1(&oauth2, &opts).map_err(js_msg)?;
    let request: js_sys::Function =
        prop(&client, "requestAccessToken").and_then(|v| v.dyn_into().ok()).ok_or_else(|| "Google sign-in isn't available.".to_string())?;
    let prompt = if host.inner.borrow().force_consent { "consent" } else { "" };
    let over = js_sys::Object::new();
    set_str(&over, "prompt", prompt);
    *host.token_cb.borrow_mut() = Some(callback);
    *host.token_err.borrow_mut() = Some(error_callback);
    request.call1(&client, &over).map_err(js_msg)?;
    Ok(())
}

fn on_token(inner: &Rc<RefCell<Inner>>, resp: wasm_bindgen::JsValue) {
    let err = field_str(&resp, "error").unwrap_or_default();
    if !err.is_empty() {
        if err == "interaction_required" {
            inner.borrow_mut().force_consent = true;
            send(inner, DriveEvent::Error("Google Drive needs you to sign in again.".into()));
        } else if err == "access_denied" {
            send(inner, DriveEvent::Error("Google Drive access was cancelled.".into()));
        } else {
            send(inner, DriveEvent::Error("Google sign-in failed.".into()));
        }
        return;
    }
    let Some(access) = field_str(&resp, "access_token").filter(|t| safe_bearer(t)) else {
        send(inner, DriveEvent::Error("Google didn't return a sign-in token.".into()));
        return;
    };
    let expires_in = field_f64(&resp, "expires_in").unwrap_or(3600.0).clamp(0.0, 86_400.0);
    let token = Token { access: access.clone(), expires_at_ms: js_sys::Date::now() + expires_in * 1000.0 - 60_000.0 };
    save_token(&token);
    {
        let mut inner = inner.borrow_mut();
        inner.token = Some(token);
        inner.force_consent = false;
    }
    spawn_list(inner.clone(), access);
}

fn on_token_error(inner: &Rc<RefCell<Inner>>, err: wasm_bindgen::JsValue) {
    let kind = field_str(&err, "type").unwrap_or_default();
    let message = match kind.as_str() {
        "popup_closed" => "Google sign-in was closed before it finished.".to_string(),
        "popup_failed_to_open" => "The browser blocked the Google sign-in window. Allow pop-ups for this site and try again.".to_string(),
        _ => {
            if kind == "interaction_required" {
                inner.borrow_mut().force_consent = true;
                "Google Drive needs you to sign in again.".to_string()
            } else {
                let detail = field_str(&err, "message").unwrap_or_default();
                let detail: String = detail.chars().filter(|c| !c.is_control()).take(180).collect();
                if detail.is_empty() { "Google sign-in failed.".to_string() } else { detail }
            }
        }
    };
    send(inner, DriveEvent::Error(message));
}

fn spawn_list(inner: Rc<RefCell<Inner>>, token: String) {
    send(&inner, DriveEvent::Listing);
    wasm_bindgen_futures::spawn_local(async move {
        list_files(token, inner).await;
    });
}

async fn list_files(token: String, inner: Rc<RefCell<Inner>>) {
    let mut page_token = None;
    let mut all = Vec::new();
    for _ in 0..3 {
        let Some(url) = drive::list_url(page_token.as_deref()) else { break };
        let (status, body) = match get_text(&token, &url).await {
            Ok(v) => v,
            Err(e) => {
                send(&inner, DriveEvent::Error(e));
                return;
            }
        };
        if status == 401 {
            clear_token(&inner);
            send(&inner, DriveEvent::Error(AUTH_EXPIRED.into()));
            return;
        }
        if status != 200 {
            let msg = drive::api_error_message(&body).unwrap_or_else(|| format!("Google Drive returned {status}."));
            send(&inner, DriveEvent::Error(msg));
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
                send(&inner, DriveEvent::Error(e.into()));
                return;
            }
        }
    }
    all.truncate(150);
    log::info!("google drive listed {} files", all.len());
    send(&inner, DriveEvent::Files(all));
}

fn fetch(inner: Rc<RefCell<Inner>>, req: DriveRequest) {
    if !drive::accept_fetch(&req) {
        send(&inner, DriveEvent::Error("That Google Drive file can't be opened here.".into()));
        return;
    }
    let Some(token) = current_token(&inner) else {
        send(&inner, DriveEvent::Error(AUTH_EXPIRED.into()));
        return;
    };
    let Some(url) = (if req.export_docx { drive::export_url(&req.id) } else { drive::media_url(&req.id) }) else {
        send(&inner, DriveEvent::Error("That Google Drive file can't be opened here.".into()));
        return;
    };
    let name = req.name;
    wasm_bindgen_futures::spawn_local(async move {
        match download(&token, &url).await {
            Ok(bytes) => {
                log::info!("opening {name} from Google Drive ({} bytes)", bytes.len());
                let (inbox, ctx) = {
                    let guard = inner.borrow();
                    (guard.inbox.clone(), guard.ctx.clone())
                };
                inbox.lock().unwrap_or_else(|e| e.into_inner()).push((name, bytes));
                ctx.request_repaint();
            }
            Err(e) => {
                if e == AUTH_EXPIRED {
                    clear_token(&inner);
                }
                log::warn!("google drive download failed: {e}");
                send(&inner, DriveEvent::Error(e));
            }
        }
    });
}

async fn get_text(token: &str, url: &str) -> Result<(u16, String), String> {
    let resp = response(token, url).await?;
    let status = resp.status();
    let blob = blob_of(&resp).await?;
    if blob.size() > 1_000_000.0 {
        return Err("Google Drive's file list was too large to read.".into());
    }
    let text = text_from_blob(&blob, 1_000_000).await?;
    Ok((status, text))
}

async fn download(token: &str, url: &str) -> Result<Vec<u8>, String> {
    let resp = response(token, url).await?;
    let status = resp.status();
    if status == 401 {
        return Err(AUTH_EXPIRED.to_string());
    }
    let blob = blob_of(&resp).await?;
    if status != 200 {
        let text = text_from_blob(&blob, 4_000).await.unwrap_or_default();
        return Err(drive::api_error_message(&text).unwrap_or_else(|| format!("Google Drive returned {status}.")));
    }
    let size = blob.size();
    if !size.is_finite() || size <= 0.0 {
        return Err("The file from Google Drive was empty.".into());
    }
    if size > drive::MAX_FILE_BYTES as f64 {
        return Err("The file from Google Drive is larger than 80 MB.".into());
    }
    let bytes = bytes_of_blob(&blob).await?;
    if bytes.is_empty() {
        return Err("The file from Google Drive was empty.".into());
    }
    if bytes.len() > drive::MAX_FILE_BYTES {
        return Err("The file from Google Drive is larger than 80 MB.".into());
    }
    Ok(bytes)
}

async fn response(token: &str, url: &str) -> Result<web_sys::Response, String> {
    if !safe_bearer(token) {
        return Err(AUTH_EXPIRED.to_string());
    }
    let window = web_sys::window().ok_or_else(|| "no window".to_string())?;
    let headers = web_sys::Headers::new().map_err(js_msg)?;
    headers.set("Authorization", &format!("Bearer {token}")).map_err(js_msg)?;
    let init = web_sys::RequestInit::new();
    init.set_method("GET");
    init.set_headers(headers.as_ref());
    let promise = window.fetch_with_str_and_init(url, &init);
    let val = wasm_bindgen_futures::JsFuture::from(promise).await.map_err(|_| "Couldn't reach Google Drive.".to_string())?;
    val.dyn_into::<web_sys::Response>().map_err(|_| "Couldn't reach Google Drive.".to_string())
}

async fn blob_of(resp: &web_sys::Response) -> Result<web_sys::Blob, String> {
    let promise = resp.blob().map_err(js_msg)?;
    let val = wasm_bindgen_futures::JsFuture::from(promise).await.map_err(|_| "Couldn't read Google Drive's reply.".to_string())?;
    val.dyn_into().map_err(|_| "Couldn't read Google Drive's reply.".to_string())
}

async fn bytes_of_blob(blob: &web_sys::Blob) -> Result<Vec<u8>, String> {
    let val = wasm_bindgen_futures::JsFuture::from(blob.array_buffer()).await.map_err(|_| "Couldn't read Google Drive's reply.".to_string())?;
    Ok(js_sys::Uint8Array::new(&val).to_vec())
}

async fn text_from_blob(blob: &web_sys::Blob, max_chars: usize) -> Result<String, String> {
    let bytes = bytes_of_blob(blob).await?;
    Ok(String::from_utf8_lossy(&bytes).chars().take(max_chars).collect())
}

fn fresh_token(host: &DriveHost) -> Option<String> {
    remembered(&host.inner)
}

fn current_token(inner: &RefCell<Inner>) -> Option<String> {
    remembered(inner)
}

fn remembered(inner: &RefCell<Inner>) -> Option<String> {
    let existing = {
        let guard = inner.borrow();
        guard.token.as_ref().map(|t| (t.access.clone(), t.expires_at_ms))
    };
    if let Some((access, exp)) = existing
        && exp > js_sys::Date::now()
        && safe_bearer(&access)
    {
        return Some(access);
    }
    let loaded = load_token()?;
    if loaded.expires_at_ms <= js_sys::Date::now() || !safe_bearer(&loaded.access) {
        return None;
    }
    let access = loaded.access.clone();
    inner.borrow_mut().token = Some(loaded);
    Some(access)
}

fn safe_bearer(token: &str) -> bool {
    !token.is_empty() && token.len() <= 8_192 && token.bytes().all(|b| b.is_ascii_graphic())
}

fn send(inner: &RefCell<Inner>, event: DriveEvent) {
    let guard = inner.borrow();
    if let Some(tx) = &guard.tx {
        let _ = tx.send(event);
    }
    guard.ctx.request_repaint();
}

fn clear_token(inner: &RefCell<Inner>) {
    inner.borrow_mut().token = None;
    if let Some(storage) = session_storage() {
        let _ = storage.remove_item(TOKEN_KEY);
    }
}

fn save_token(token: &Token) {
    let Some(storage) = session_storage() else { return };
    let raw = serde_json::json!({"access_token": token.access, "expires_at_ms": token.expires_at_ms}).to_string();
    let _ = storage.set_item(TOKEN_KEY, &raw);
}

fn load_token() -> Option<Token> {
    let storage = session_storage()?;
    let raw = storage.get_item(TOKEN_KEY).ok()??;
    if raw.len() > 16_000 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let access = v.get("access_token")?.as_str()?.to_string();
    let expires_at_ms = v.get("expires_at_ms")?.as_f64()?;
    if !safe_bearer(&access) || !expires_at_ms.is_finite() {
        return None;
    }
    Some(Token { access, expires_at_ms })
}

fn read_client_id() -> Option<String> {
    let id = local_storage()?.get_item(CLIENT_KEY).ok()??;
    drive::valid_client_id(&id).then_some(id)
}

fn save_client_id(id: &str) {
    if !drive::valid_client_id(id) {
        return;
    }
    if let Some(storage) = local_storage() {
        let _ = storage.set_item(CLIENT_KEY, id.trim());
    }
}

fn absorb_query_client_id() {
    let search = web_sys::window().and_then(|w| w.location().search().ok()).unwrap_or_default();
    let Some(raw) = query_param(&search, "google_client_id") else { return };
    let id = drive::decode_query_component(&raw);
    if drive::valid_client_id(&id) {
        save_client_id(&id);
    }
}

fn query_param(search: &str, key: &str) -> Option<String> {
    let search = search.strip_prefix('?').unwrap_or(search);
    if search.is_empty() {
        return None;
    }
    for part in search.split('&').take(32) {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn session_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.session_storage().ok()?
}

fn google_oauth2(window: &web_sys::Window) -> Result<wasm_bindgen::JsValue, String> {
    let google = prop(window.as_ref(), "google").ok_or_else(|| NOT_READY.to_string())?;
    let accounts = prop(&google, "accounts").ok_or_else(|| NOT_READY.to_string())?;
    prop(&accounts, "oauth2").ok_or_else(|| NOT_READY.to_string())
}

fn prop(obj: &wasm_bindgen::JsValue, key: &str) -> Option<wasm_bindgen::JsValue> {
    let v = js_sys::Reflect::get(obj, &wasm_bindgen::JsValue::from_str(key)).ok()?;
    if v.is_null() || v.is_undefined() { None } else { Some(v) }
}

fn field_str(obj: &wasm_bindgen::JsValue, key: &str) -> Option<String> {
    prop(obj, key).and_then(|v| v.as_string()).filter(|s| !s.is_empty())
}

fn field_f64(obj: &wasm_bindgen::JsValue, key: &str) -> Option<f64> {
    prop(obj, key).and_then(|v| v.as_f64()).filter(|n| n.is_finite())
}

fn set_str(obj: &js_sys::Object, key: &str, value: &str) {
    let _ = js_sys::Reflect::set(obj, &wasm_bindgen::JsValue::from_str(key), &wasm_bindgen::JsValue::from_str(value));
}

fn js_msg(e: wasm_bindgen::JsValue) -> String {
    let raw = e.as_string().or_else(|| field_str(&e, "message")).unwrap_or_else(|| "Google Drive request failed".to_string());
    let out: String = raw.chars().filter(|c| !c.is_control()).take(180).collect();
    if out.is_empty() { "Google Drive request failed".to_string() } else { out }
}
