use neon::prelude::*;
use pqcrypto_traits::kem::{SharedSecret, Ciphertext, SecretKey, PublicKey};
use aes_gcm::aead::rand_core::RngCore;
use base64;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};

fn encrypt_string(mut cx: FunctionContext) -> JsResult<JsObject> {
    let data_raw: Handle<JsString> = cx.argument(0)?;
    let data = data_raw.value(&mut cx);

    let (pk, sk) = pqcrypto_kyber::kyber512::keypair();

    let keys = cx.empty_object();
    let pk_string = cx.string(base64::encode(pk.as_bytes()));
    let sk_string = cx.string(base64::encode(sk.as_bytes()));
    keys.set(&mut cx, "private", sk_string)?;
    keys.set(&mut cx, "public", pk_string)?;

    let (ss1, ct) = pqcrypto_kyber::kyber512::encapsulate(&pk);

    let cipher = Aes256Gcm::new_from_slice(&ss1.as_bytes()).unwrap();

    let mut nonce_bytes = [0; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, data.as_ref()).unwrap();

    let encrypted = format!("ev:pq:{}:{}:{}:$", base64::encode(nonce_bytes), base64::encode(&ct.as_bytes()), base64::encode(ciphertext));
    let encrypted_str = cx.string(encrypted);

    let response = cx.empty_object();
    response.set(&mut cx, "keys", keys)?;
    response.set(&mut cx, "result", encrypted_str)?;

    Ok(response)
}

fn decrypt_string(mut cx: FunctionContext) -> JsResult<JsString> {
    let data_raw: Handle<JsString> = cx.argument(0)?;
    let data = data_raw.value(&mut cx);
    let data_iter = data.split(":").collect::<Vec<_>>();

    let data_nonce = data_iter[2];
    let data_kyberct = data_iter[3];
    let data_cipher = data_iter[4];

    let keys_raw: Handle<JsObject> = cx.argument(1)?;
    let sk_str: Handle<JsString> = keys_raw.get(&mut cx, "private")?;
 
    let sk = pqcrypto_kyber::kyber512::SecretKey::from_bytes(&base64::decode(sk_str.value(&mut cx)).unwrap()).unwrap();

    let ss = pqcrypto_kyber::kyber512::decapsulate(&pqcrypto_kyber::kyber512::Ciphertext::from_bytes(&base64::decode(data_kyberct).unwrap()).unwrap(), &sk);

    let cipher = Aes256Gcm::new_from_slice(ss.as_bytes()).unwrap();

    let nonce_bytes = base64::decode(&data_nonce).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes); // 96-bits; unique per message
    let plaintext = cipher.decrypt(nonce, &base64::decode(data_cipher).unwrap()[..]).unwrap();
    

    let response = cx.string(std::str::from_utf8(&plaintext[..]).unwrap());

    Ok(response)
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("encrypt", encrypt_string)?;
    cx.export_function("decrypt", decrypt_string)?;
    Ok(())
}