use gloo::events::EventListener;
use wasm_bindgen::JsCast;
use web_sys::{EventSource, MessageEvent};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use serde::de::DeserializeOwned;

/// RAII guard for Server-Sent Events with proper cleanup
pub struct SseGuard {
    es: EventSource,
    _msg: EventListener,
    _err: EventListener,
    _open: EventListener,
    canceled: Arc<AtomicBool>,
}

impl SseGuard {
    pub fn new<T: DeserializeOwned + 'static>(
        url: &str,
        on_msg: impl Fn(T) + 'static,
        on_error: impl Fn(String) + 'static,
        on_connected: impl Fn(bool) + 'static,
    ) -> Result<Self, String> {
        let es = EventSource::new(url)
            .map_err(|e| format!("EventSource failed: {:?}", e))?;

        let canceled = Arc::new(AtomicBool::new(false));

        // Wrap callbacks in Arc to share between listeners
        let on_msg = Arc::new(on_msg);
        let on_error = Arc::new(on_error);
        let on_connected = Arc::new(on_connected);

        let msg_flag = canceled.clone();
        let msg_on_msg = on_msg.clone();
        let msg_on_error = on_error.clone();
        let msg_listener = EventListener::new(&es, "message", move |evt| {
            if msg_flag.load(Ordering::Relaxed) { return; }

            if let Some(text) = evt.dyn_ref::<MessageEvent>()
                .and_then(|e| e.data().as_string())
            {
                match serde_json::from_str::<T>(&text) {
                    Ok(payload) => msg_on_msg(payload),
                    Err(de) => msg_on_error(format!("SSE decode error: {}", de)),
                }
            }
        });

        let err_flag = canceled.clone();
        let err_on_connected = on_connected.clone();
        let err_on_error = on_error.clone();
        let err_listener = EventListener::new(&es, "error", move |_| {
            if err_flag.load(Ordering::Relaxed) { return; }
            err_on_connected(false);
            err_on_error("SSE connection error".into());
        });

        let open_flag = canceled.clone();
        let open_on_connected = on_connected.clone();
        let open_listener = EventListener::new(&es, "open", move |_| {
            if open_flag.load(Ordering::Relaxed) { return; }
            open_on_connected(true);
        });

        Ok(Self {
            es,
            _msg: msg_listener,
            _err: err_listener,
            _open: open_listener,
            canceled,
        })
    }
}

impl Drop for SseGuard {
    fn drop(&mut self) {
        self.canceled.store(true, Ordering::Relaxed);
        self.es.close(); // Stop the stream
    }
}