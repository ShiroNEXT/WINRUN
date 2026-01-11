mod metrics;
mod apps;
mod cache;

use actix_cors::Cors;
use actix_web::{get, post, middleware::Logger, web, App, HttpResponse, HttpServer, Responder};
use serde_json::json;
use std::sync::{Arc, Mutex};

const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[get("/health")]
async fn health_handler() -> impl Responder {
    HttpResponse::Ok().json(json!({ "status": "ok" }))
}

#[get("/version")]
async fn version_handler() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "version": SERVER_VERSION,
        "commit_hash": option_env!("GIT_COMMIT_HASH").unwrap_or("n/a"),
        "build_time": option_env!("BUILD_TIMESTAMP").unwrap_or("n/a"),
    }))
}

async fn metrics_handler() -> impl Responder {
    match metrics::collect_metrics() {
        Ok(metrics) => HttpResponse::Ok().json(metrics),
        Err(err) => HttpResponse::InternalServerError().json(json!({
            "error": err.to_string()
        })),
    }
}

#[get("/apps")]
async fn apps_handler(cache: web::Data<Arc<Mutex<cache::AppsCache>>>) -> impl Responder {
    let cache = cache.lock().unwrap();
    match cache.get_apps() {
        Ok(apps_response) => {
            HttpResponse::Ok()
                .content_type("application/json; charset=utf-8")
                .json(apps_response)
        }
        Err(err) => {
            log::error!("Failed to get cached apps: {}", err);
            HttpResponse::InternalServerError().json(json!({
                "error": err.to_string()
            }))
        }
    }
}

#[post("/get-icon")]
async fn get_icon_handler(form: web::Form<IconRequest>) -> impl Responder {
    let path = form.path.as_str();
    
    if path.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "error": "path is required"
        }));
    }

    match apps::extract_icon_base64(path) {
        Ok(base64_icon) => {
            HttpResponse::Ok()
                .content_type("text/plain; charset=utf-8")
                .body(base64_icon)
        }
        Err(err) => {
            log::error!("Failed to extract icon from {}: {}", path, err);
            HttpResponse::InternalServerError().json(json!({
                "error": err.to_string()
            }))
        }
    }
}

#[derive(serde::Deserialize)]
struct IconRequest {
    path: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Initialize cache and perform initial scan
    let cache = Arc::new(Mutex::new(cache::AppsCache::new()));
    
    // Perform initial scan on startup
    {
        let cache_clone = cache.clone();
        std::thread::spawn(move || {
            log::info!("Starting initial app scan on service startup...");
            match apps::scan_installed_programs() {
                Ok(apps_response) => {
                    let mut cache = cache_clone.lock().unwrap();
                    if let Err(e) = cache.save_apps(&apps_response) {
                        log::error!("Failed to save apps cache: {}", e);
                    } else {
                        log::info!("App cache saved successfully with {} apps", apps_response.apps.len());
                    }
                }
                Err(e) => {
                    log::error!("Failed to scan apps on startup: {}", e);
                }
            }
        });
    }

    let cache_data = web::Data::new(cache);

    HttpServer::new(move || {
        App::new()
            .app_data(cache_data.clone())
            .wrap(Logger::default())
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header(),
            )
            .service(health_handler)
            .service(version_handler)
            .service(apps_handler)
            .service(get_icon_handler)
            .route("/metrics", web::get().to(metrics_handler))
    })
    .bind(("0.0.0.0", 7148))?
    .run()
    .await
}
