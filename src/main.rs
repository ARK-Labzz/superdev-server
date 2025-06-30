use actix_web::{
    post, web, HttpResponse, Result as ActixResult, 
    middleware::Logger
};
use shuttle_actix_web::ShuttleActixWeb;

mod types;
mod solana_service;

use crate::types::*;
use crate::solana_service::SolanaService;


#[post("/keypair")]
async fn generate_keypair() -> ActixResult<HttpResponse> {
    match SolanaService::generate_keypair() {
        Ok(keypair_data) => {
            let response = ApiResponse {
                success: true,
                data: Some(keypair_data),
                error: None,
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e),
            };
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

#[post("/token/create")]
async fn create_token(body: web::Json<CreateTokenRequest>) -> ActixResult<HttpResponse> {
    match SolanaService::create_token_instruction(&body) {
        Ok(instruction_data) => {
            let response = ApiResponse {
                success: true,
                data: Some(instruction_data),
                error: None,
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e),
            };
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}


#[post("/token/mint")]
async fn mint_token(body: web::Json<MintTokenRequest>) -> ActixResult<HttpResponse> {
    match SolanaService::create_mint_instruction(&body) {
        Ok(instruction_data) => {
            let response = ApiResponse {
                success: true,
                data: Some(instruction_data),
                error: None,
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e),
            };
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}


#[post("/message/sign")]
async fn sign_message(body: web::Json<SignMessageRequest>) -> ActixResult<HttpResponse> {
    
    if body.message.is_empty() || body.secret.is_empty() {
        let response = ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        };
        return Ok(HttpResponse::BadRequest().json(response));
    }

    match SolanaService::sign_message(&body.message, &body.secret) {
        Ok((signature, pubkey)) => {
            let response = ApiResponse {
                success: true,
                data: Some(SignMessageData {
                    signature,
                    public_key: pubkey,
                    message: body.message.clone(),
                }),
                error: None,
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e),
            };
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}


#[post("/message/verify")]
async fn verify_message(body: web::Json<VerifyMessageRequest>) -> ActixResult<HttpResponse> {
    match SolanaService::verify_message(&body.message, &body.signature, &body.pubkey) {
        Ok(is_valid) => {
            let response = ApiResponse {
                success: true,
                data: Some(VerifyMessageData {
                    valid: is_valid,
                    message: body.message.clone(),
                    pubkey: body.pubkey.clone(),
                }),
                error: None,
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e),
            };
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}


#[post("/send/sol")]
async fn send_sol(body: web::Json<SendSolRequest>) -> ActixResult<HttpResponse> {
    match SolanaService::create_sol_transfer_instruction(&body) {
        Ok(instruction_data) => {
            let response = ApiResponse {
                success: true,
                data: Some(instruction_data),
                error: None,
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e),
            };
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}


#[post("/send/token")]
async fn send_token(body: web::Json<SendTokenRequest>) -> ActixResult<HttpResponse> {
    match SolanaService::create_token_transfer_instruction(&body) {
        Ok(instruction_data) => {
            let response = ApiResponse {
                success: true,
                data: Some(instruction_data),
                error: None,
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e),
            };
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

#[shuttle_runtime::main]
async fn main() -> ShuttleActixWeb<impl FnOnce(&mut web::ServiceConfig) + Send + Clone + 'static> {
    
    env_logger::init();

    let config = move |cfg: &mut web::ServiceConfig| {
        cfg.service(
            web::scope("")
                .wrap(Logger::default())
                .service(generate_keypair)
                .service(create_token)
                .service(mint_token)
                .service(sign_message)
                .service(verify_message)
                .service(send_sol)
                .service(send_token)
        );
    };

    Ok(config.into())
}