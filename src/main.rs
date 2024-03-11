// use std::fs;
mod helpers;
use std::path::PathBuf;

use helpers::cal_roothash::restore_roothash;

use actix_web::cookie::Key;
use actix_web::middleware::Logger;
use actix_web::web::{get, post, JsonConfig};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use env_logger::Env;
use helpers::startup::startup;
use miden_vm::VMResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Req {
    // used to verify the ZKP result
    pub program_hash: String,
    pub stack_inputs: String,
    pub zkp_result: VMResult,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Resp {
    pub roothash: String,
    pub is_valid: bool,
}

type WebResult<T> = Result<T, Error>;

// ============================= Implement webauthn-rs ===========================

use actix_session::{Session, SessionMiddleware};
use actix_web::web::{Data, Json, Path};
use log::{error, info};
use tokio::sync::Mutex;

use crate::helpers::error::Error;
use crate::helpers::session::MemorySession;
use helpers::startup::UserData;

/*
 * Webauthn RS auth handlers.
 * These files use webauthn to process the data received from each route, and are closely tied to actix_web
 */

// 1. Import the prelude - this contains everything needed for the server to function.
use webauthn_rs::prelude::*;

// 2. The first step a client (user) will carry out is requesting a credential to be
// registered. We need to provide a challenge for this. The work flow will be:
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Reg     │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │  4. Yield PubKey    │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │                      │
//                  │                     │  5. Send Reg Opts    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │         PubKey
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │─ ─ ─
//                  │                     │                      │     │ 6. Persist
//                  │                     │                      │       Credential
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// In this step, we are responding to the start reg(istration) request, and providing
// the challenge to the browser.
pub(crate) async fn start_register(
    username: Path<String>,
    session: Session,
    webauthn_users: Data<Mutex<UserData>>,
    webauthn: Data<Webauthn>,
    // ) -> impl Responder {
) -> WebResult<Json<CreationChallengeResponse>> {
    info!("Start register");

    // We get the username from the URL, but you could get this via form submission or
    // some other process. In some parts of Webauthn, you could also use this as a "display name"
    // instead of a username. Generally you should consider that the user *can* and *will* change
    // their username at any time.

    // Since a user's username could change at anytime, we need to bind to a unique id.
    // We use uuid's for this purpose, and you should generate these randomly. If the
    // username does exist and is found, we can match back to our unique id. This is
    // important in authentication, where presented credentials may *only* provide
    // the unique id, and not the username!

    let user_unique_id = {
        let users_guard = webauthn_users.lock().await;
        users_guard
            .name_to_id
            .get(username.as_str())
            .copied()
            .unwrap_or_else(Uuid::new_v4)
    };

    // Remove any previous registrations that may have occurred from the session.
    session.remove("reg_state");

    // If the user has any other credentials, we exclude these here so they can't be duplicate registered.
    // It also hints to the browser that only new credentials should be "blinked" for interaction.
    let exclude_credentials = {
        let users_guard = webauthn_users.lock().await;
        users_guard
            .keys
            .get(&user_unique_id)
            .map(|keys| keys.iter().map(|sk| sk.cred_id().clone()).collect())
    };

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user_unique_id, &username, &username, exclude_credentials)
        .map_err(|e| {
            info!("challenge_register -> {:?}", e);
            Error::Unknown(e)
        })?;

    // Note that due to the session store in use being a server side memory store, this is
    // safe to store the reg_state into the session since it is not client controlled and
    // not open to replay attacks. If this was a cookie store, this would be UNSAFE.
    if let Err(err) = session.insert("reg_state", (username.as_str(), user_unique_id, reg_state)) {
        error!("Failed to save reg_state to session storage!");
        return Err(Error::SessionInsert(err));
    };

    info!("Registration Successful!");

    // HttpResponse::Ok().json(Json(ccr))
    Ok(Json(ccr))
}

// 3. The browser has completed it's steps and the user has created a public key
// on their device. Now we have the registration options sent to us, and we need
// to verify these and persist them.
pub(crate) async fn finish_register(
    req: Json<RegisterPublicKeyCredential>,
    session: Session,
    webauthn_users: Data<Mutex<UserData>>,
    webauthn: Data<Webauthn>,
    // ) -> impl Responder {
) -> WebResult<HttpResponse> {
    let (username, user_unique_id, reg_state) = match session.get("reg_state")? {
        Some((username, user_unique_id, reg_state)) => (username, user_unique_id, reg_state),
        None => return Err(Error::CorruptSession),
    };

    session.remove("reg_state");

    let sk = webauthn
        .finish_passkey_registration(&req, &reg_state)
        .map_err(|e| {
            info!("challenge_register -> {:?}", e);
            Error::BadRequest(e)
        })?;

    let mut users_guard = webauthn_users.lock().await;

    //TODO: This is where we would store the credential in a db, or persist them in some other way.

    users_guard
        .keys
        .entry(user_unique_id)
        .and_modify(|keys| keys.push(sk.clone()))
        .or_insert_with(|| vec![sk.clone()]);

    users_guard.name_to_id.insert(username, user_unique_id);

    Ok(HttpResponse::Ok().finish())
}

// 4. Now that our public key has been registered, we can authenticate a user and verify
// that they are the holder of that security token. The work flow is similar to registration.
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Auth    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │    4. Yield Sig     │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │    5. Send Auth      │
//                  │                     │        Opts          │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │          Sig
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// The user indicates the wish to start authentication and we need to provide a challenge.

pub(crate) async fn start_authentication(
    username: Path<String>,
    session: Session,
    webauthn_users: Data<Mutex<UserData>>,
    webauthn: Data<Webauthn>,
    // ) -> impl Responder {
) -> WebResult<Json<RequestChallengeResponse>> {
    info!("Start Authentication");
    // We get the username from the URL, but you could get this via form submission or
    // some other process.

    // Remove any previous authentication that may have occurred from the session.
    session.remove("auth_state");

    // Get the set of keys that the user possesses
    let users_guard = webauthn_users.lock().await;

    // Look up their unique id from the username
    let user_unique_id = users_guard
        .name_to_id
        .get(username.as_str())
        .copied()
        .ok_or(Error::UserNotFound)
        .unwrap();

    let allow_credentials = users_guard
        .keys
        .get(&user_unique_id)
        .ok_or(Error::UserHasNoCredentials)
        .unwrap();

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(allow_credentials)
        .map_err(|e| {
            info!("challenge_authenticate -> {:?}", e);
            Error::Unknown(e)
        })
        .unwrap();

    // Drop the mutex to allow the mut borrows below to proceed
    drop(users_guard);

    // Note that due to the session store in use being a server side memory store, this is
    // safe to store the auth_state into the session since it is not client controlled and
    // not open to replay attacks. If this was a cookie store, this would be UNSAFE.
    session
        .insert("auth_state", (user_unique_id, auth_state))
        .unwrap();

    Ok(Json(rcr))
}

// 5. The browser and user have completed their part of the processing. Only in the
// case that the webauthn authenticate call returns Ok, is authentication considered
// a success. If the browser does not complete this call, or *any* error occurs,
// this is an authentication failure.
pub(crate) async fn finish_authentication(
    auth: Json<PublicKeyCredential>,
    session: Session,
    webauthn_users: Data<Mutex<UserData>>,
    webauthn: Data<Webauthn>,
    // ) -> impl Responder {
) -> WebResult<HttpResponse> {
    let (user_unique_id, auth_state) = session
        .get("auth_state")
        .unwrap()
        .ok_or(Error::CorruptSession)
        .unwrap();

    session.remove("auth_state");

    let auth_result = webauthn
        .finish_passkey_authentication(&auth, &auth_state)
        .map_err(|e| {
            info!("challenge_register -> {:?}", e);
            Error::BadRequest(e)
        })
        .unwrap();

    let mut users_guard = webauthn_users.lock().await;

    // Update the credential counter, if possible.
    users_guard
        .keys
        .get_mut(&user_unique_id)
        .map(|keys| {
            keys.iter_mut().for_each(|sk| {
                // This will update the credential if it's the matching
                // one. Otherwise it's ignored. That is why it is safe to
                // iterate this over the full list.
                sk.update_credential(&auth_result);
            })
        })
        .ok_or(Error::UserHasNoCredentials)
        .unwrap();

    info!("Authentication Successful!");
    Ok(HttpResponse::Ok().finish())
}

// ============================= Finish Implement webauthn-rs ===========================

#[post("verify")]
async fn verify(req: web::Json<Req>) -> impl Responder {
    log::info!("{:?}", &req.0.program_hash);

    // let zkp_result: String =
    //     fs::read_to_string("src/zkp_result.json").expect("LogRocket: error reading file");
    // let program_hash: String =
    //     String::from("01d680e6c4f82c8274c43626c67a0f494e65f147245330a3bd6a9c69271223c1");
    // let stack_inputs: String = String::from("12");

    // // A request data demo
    // let req_data = Req {
    //     program_hash,
    //     stack_inputs,
    //     zkp_result,
    // };

    // =========================== Execution Phrase ===============================
    // We suppose the User has generated his/her ZKP via zkID Wallet,

    // ========================== User Send ZKP To Us ===========================
    // User send its ZKP to us, and we saved it in the `./zkp_result.json` , we only verify the ZKP in rust

    // ========================== Verification Phrase =============================
    // In the Verification Phrase, we check the validity of user's zkp result(if the ZKP is valid, the verify_result should be a u32 which represent security level, i.g. 96)
    let verification_result = miden_vm::verify_zk_program(
        req.0.program_hash,
        req.0.stack_inputs,
        req.0.zkp_result.clone(),
    );

    let roothash: String = restore_roothash(req.0.zkp_result);

    HttpResponse::Ok().json(Resp {
        roothash,
        is_valid: verification_result.is_ok(),
    })
}

// ====================== Helper Function ====================================
#[get("/")]
async fn echo() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

// #[actix_web::main]
// async fn main() -> std::io::Result<()> {
//     env_logger::init_from_env(Env::default().default_filter_or("debug"));

//     HttpServer::new(|| {
//         App::new()
//             .wrap(Logger::default())
//             .wrap(Logger::new("%a %{User-Agent}i"))
//             .service(echo)
//             .service(verify)
//     })
//     .bind(("0.0.0.0", 3000))?
//     .run()
//     .await
// }

#[actix_web::main]
async fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // Initialize env-logger
    env_logger::init();

    // Generate secret key for cookies.
    // Normally you would read this from a configuration file.
    let key = Key::generate();

    let (webauthn, webauthn_users) = startup();

    // if !PathBuf::from(WASM_DIR).exists() {
    //     panic!("{} does not exist, can't serve WASM files.", WASM_DIR);
    // } else {
    //     info!("Found WASM files OK");
    // }

    // Build the webserver and run it
    info!("Listening on: http://0.0.0.0:3000");
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(
                SessionMiddleware::builder(MemorySession, key.clone())
                    .cookie_name("webauthnrs".to_string())
                    .cookie_http_only(true)
                    .cookie_secure(false)
                    .build(),
            )
            .app_data(JsonConfig::default())
            .app_data(webauthn.clone())
            .app_data(webauthn_users.clone())
            // .route("/", get().to(index))
            // .route("/pkg/{filename:.*}", get().to(serve_wasm))
            .route("/register_start/{username}", post().to(start_register))
            .route("/register_finish", post().to(finish_register))
            .route("/login_start/{username}", post().to(start_authentication))
            .route("/login_finish", post().to(finish_authentication))
    })
    .bind(("0.0.0.0", 3000))
    .expect("Failed to start a listener on 0.0.0.0:3000")
    .run()
    .await
    .unwrap();
}
