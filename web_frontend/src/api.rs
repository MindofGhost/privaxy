use serde::{de::DeserializeOwned, Deserialize, Serialize};
use yew::Callback;

#[cfg(feature = "tauri-backend")]
use futures::future::{AbortHandle, Abortable};
#[cfg(feature = "tauri-backend")]
use futures::StreamExt;
#[cfg(feature = "web-backend")]
use gloo_net::http::Request;
#[cfg(feature = "tauri-backend")]
use tauri_sys::{event, tauri};
#[cfg(feature = "web-backend")]
use wasm_bindgen::{prelude::Closure, JsCast};
#[cfg(feature = "tauri-backend")]
use wasm_bindgen_futures::spawn_local;

#[derive(Serialize)]
struct BlockingEnabledArg {
    enabled: bool,
}

#[derive(Serialize)]
struct SettingPayload {
    input: String,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct FilterStatusChangeRequestPayload<T> {
    filterStatusChangeRequest: T,
}

pub async fn get_statistics<T: DeserializeOwned>() -> Result<T, String> {
    #[cfg(feature = "tauri-backend")]
    {
        tauri::invoke("get_statistics", &())
            .await
            .map_err(|err| format!("{:?}", err))
    }

    #[cfg(feature = "web-backend")]
    {
        get_json("/api/statistics").await
    }
}

pub async fn get_blocking_enabled() -> Result<bool, String> {
    #[cfg(feature = "tauri-backend")]
    {
        tauri::invoke("get_blocking_enabled", &())
            .await
            .map_err(|err| format!("{:?}", err))
    }

    #[cfg(feature = "web-backend")]
    {
        #[derive(Deserialize)]
        struct Response {
            enabled: bool,
        }

        let response: Response = get_json("/api/blocking-enabled").await?;
        Ok(response.enabled)
    }
}

pub async fn set_blocking_enabled(enabled: bool) -> Result<(), String> {
    #[cfg(feature = "tauri-backend")]
    {
        tauri::invoke::<_, ()>("set_blocking_enabled", &BlockingEnabledArg { enabled })
            .await
            .map_err(|err| format!("{:?}", err))
    }

    #[cfg(feature = "web-backend")]
    {
        let body =
            serde_json::to_string(&BlockingEnabledArg { enabled }).map_err(|err| err.to_string())?;
        Request::post("/api/blocking-enabled")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        Ok(())
    }
}

pub async fn get_text_resource(resource_name: &str) -> Result<String, String> {
    #[cfg(feature = "tauri-backend")]
    {
        tauri::invoke(resource_name, &())
            .await
            .map_err(|err| format!("{:?}", err))
    }

    #[cfg(feature = "web-backend")]
    {
        Request::get(&format!("/api/{}", api_resource_name(resource_name)))
            .send()
            .await
            .map_err(|err| err.to_string())?
            .text()
            .await
            .map_err(|err| err.to_string())
    }
}

pub async fn set_text_resource(resource_name: &str, input: String) -> Result<(), String> {
    #[cfg(feature = "tauri-backend")]
    {
        tauri::invoke::<_, ()>(resource_name, &SettingPayload { input })
            .await
            .map_err(|err| format!("{:?}", err))
    }

    #[cfg(feature = "web-backend")]
    {
        Request::put(&format!("/api/{}", api_resource_name(resource_name)))
            .body(input)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        Ok(())
    }
}

pub async fn get_filters_configuration<T: DeserializeOwned>() -> Result<T, String> {
    #[cfg(feature = "tauri-backend")]
    {
        tauri::invoke("get_filters_configuration", &())
            .await
            .map_err(|err| format!("{:?}", err))
    }

    #[cfg(feature = "web-backend")]
    {
        get_json("/api/filters").await
    }
}

pub async fn change_filter_status<T, P>(payload: P) -> Result<T, String>
where
    T: DeserializeOwned,
    P: Serialize,
{
    #[cfg(feature = "tauri-backend")]
    {
        tauri::invoke(
            "change_filter_status",
            &FilterStatusChangeRequestPayload {
                filterStatusChangeRequest: payload,
            },
        )
        .await
        .map_err(|err| format!("{:?}", err))
    }

    #[cfg(feature = "web-backend")]
    {
        post_json("/api/filters", &payload).await
    }
}

#[cfg(feature = "web-backend")]
async fn get_json<T: DeserializeOwned>(url: &str) -> Result<T, String> {
    let response = Request::get(url)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    json_response(response).await
}

#[cfg(feature = "web-backend")]
async fn post_json<T, P>(url: &str, payload: &P) -> Result<T, String>
where
    T: DeserializeOwned,
    P: Serialize,
{
    let response = Request::post(url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(payload).map_err(|err| err.to_string())?)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    json_response(response).await
}

#[cfg(feature = "web-backend")]
async fn json_response<T: DeserializeOwned>(
    response: gloo_net::http::Response,
) -> Result<T, String> {
    let status = response.status();
    let body = response.text().await.map_err(|err| err.to_string())?;

    if !(200..300).contains(&status) {
        return Err(format!("HTTP {}: {}", status, body));
    }

    serde_json::from_str(&body).map_err(|err| {
        format!(
            "JSON parse error: {}; body starts with {:?}",
            err,
            body.chars().take(200).collect::<String>()
        )
    })
}

pub struct RequestEvents {
    #[cfg(feature = "tauri-backend")]
    abort_handle: AbortHandle,
    #[cfg(feature = "web-backend")]
    event_source: web_sys::EventSource,
    #[cfg(feature = "web-backend")]
    _onmessage: Closure<dyn FnMut(web_sys::MessageEvent)>,
}

impl RequestEvents {
    pub fn close(&self) {
        #[cfg(feature = "tauri-backend")]
        self.abort_handle.abort();

        #[cfg(feature = "web-backend")]
        self.event_source.close();
    }
}

pub fn listen_requests<T>(message_callback: Callback<T>) -> RequestEvents
where
    T: DeserializeOwned + 'static,
{
    #[cfg(feature = "tauri-backend")]
    {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let future = Abortable::new(
            async move {
                let mut events = event::listen::<T>("logged_request").await.unwrap();
                while let Some(event) = events.next().await {
                    message_callback.emit(event.payload);
                }
            },
            abort_registration,
        );

        spawn_local(async {
            let _result = future.await;
        });

        RequestEvents { abort_handle }
    }

    #[cfg(feature = "web-backend")]
    {
        let event_source = web_sys::EventSource::new("/api/events").unwrap();
        let onmessage = Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
            if let Some(data) = event.data().as_string() {
                match serde_json::from_str::<T>(&data) {
                    Ok(message) => message_callback.emit(message),
                    Err(err) => log::error!("{:?}", err),
                }
            }
        }) as Box<dyn FnMut(_)>);

        event_source.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        RequestEvents {
            event_source,
            _onmessage: onmessage,
        }
    }
}

#[cfg(feature = "web-backend")]
fn api_resource_name(resource_name: &str) -> String {
    match resource_name {
        "get_custom_filters" | "set_custom_filters" => "custom-filters".to_string(),
        "get_exclusions" | "set_exclusions" => "exclusions".to_string(),
        _ => resource_name.to_string(),
    }
}
