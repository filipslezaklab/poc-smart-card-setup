use std::fs::OpenOptions;
use std::io::Write;

use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::UploadableKey;
use pgp::ser::Serialize;
use pgp::types::{PublicKeyTrait, PublicParams, SecretKeyTrait};
use pgp::{
    SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SignedSecretSubKey, SubkeyParams,
    SubkeyParamsBuilder,
};
use tracing::debug;

pub(crate) fn save_ssh(openssh: String) {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("ssh.asc")
        .unwrap();
    file.write_all(openssh.as_bytes()).unwrap();
}

fn pad_ssh_mpint(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        vec![0]
    } else if bytes[0] & 0x80 != 0 {
        let mut v = Vec::with_capacity(bytes.len() + 1);
        v.push(0);
        v.extend_from_slice(bytes);
        v
    } else {
        bytes.to_vec()
    }
}

pub(crate) fn key_to_ssh(key: SignedSecretSubKey) -> anyhow::Result<String> {
    let public = key.public_key();
    let params = public.public_params();
    if let PublicParams::RSA { n, e } = params {
        let n_bytes = n.as_bytes();
        let e_bytes = e.as_bytes();

        // Debug:
        println!("n_bytes: {:?}", n_bytes);
        println!("e_bytes: {:?}", e_bytes);

        let n_bytes_padded = pad_ssh_mpint(n_bytes);
        let e_bytes_padded = pad_ssh_mpint(e_bytes);

        println!("n_bytes_padded: {:?}", n_bytes_padded);
        println!("e_bytes_padded: {:?}", e_bytes_padded);

        let n_mpint = ssh_key::Mpint::from_bytes(&n_bytes_padded)?;
        let e_mpint = ssh_key::Mpint::from_bytes(&e_bytes_padded)?;

        let rsa_pub = ssh_key::public::RsaPublicKey { n: n_mpint, e: e_mpint };
        let pubkey = ssh_key::PublicKey::from(rsa_pub);

        Ok(pubkey.to_openssh()?)
    } else {
        anyhow::bail!("public is not RSA");
    }
}

pub(crate) fn save_pubkey(
    pubkey: &pgp::composed::signed_key::SignedPublicKey,
    filename: &str,
) -> anyhow::Result<()> {
    let armored = pubkey.to_armored_string(pgp::ArmorOptions {
        headers: None,
        include_checksum: true,
    })?;
    let mut file = OpenOptions::new()
        .read(true)
        .create(true)
        .truncate(true)
        .write(true)
        .open(filename)?;
    file.write_all(&armored.into_bytes())?;
    Ok(())
}

pub(crate) fn generate_rsa_importable_key(
    key_type: KeyType,
    primary_user_id: String,
) -> UploadableKey {
    let key_algo = pgp::KeyType::Rsa(4096);
    let mut rng = rand::thread_rng();
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(key_algo.clone())
        .primary_user_id(primary_user_id);
    match key_type {
        KeyType::Authentication => {
            key_params.can_sign(true);
            key_params.can_certify(false);
            key_params.can_encrypt(false);
        }
        KeyType::Decryption => {
            key_params.can_sign(false);
            key_params.can_certify(false);
            key_params.can_encrypt(true);
        }
        KeyType::Signing => {
            key_params.can_sign(true);
            key_params.can_certify(true);
            key_params.can_encrypt(false);
        }
        KeyType::Attestation => {
            key_params.can_sign(true);
            key_params.can_certify(true);
            key_params.can_encrypt(false);
        }
    }
    let secret_key_params = key_params.build().unwrap();
    let secret_key = secret_key_params.generate(&mut rng).unwrap();
    let passwd_fn = || String::new();
    let signed_secret = secret_key.sign(&mut rng, passwd_fn).unwrap();
    let primary_packet = signed_secret.primary_key.clone();
    let public_key = signed_secret.public_key();
    let signed_public_key = public_key
        .sign(&mut rng, &signed_secret, passwd_fn)
        .unwrap();
    match key_type {
        KeyType::Authentication => {
            save_pubkey(&signed_public_key, "authentication.asc").unwrap();
        }
        KeyType::Decryption => {
            save_pubkey(&signed_public_key, "decryption.asc").unwrap();
        }
        KeyType::Signing => {
            save_pubkey(&signed_public_key, "signing.asc").unwrap();
        }
        _ => {}
    }

    UploadableKey::from(primary_packet)
}

pub(crate) fn generate_rsa_importable_master_key(
    primary_user_id: String,
) -> (SignedSecretKey, SignedPublicKey) {
    let key_algo = pgp::KeyType::Rsa(4096);
    let mut rng = rand::thread_rng();
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(key_algo.clone())
        .primary_user_id(primary_user_id)
        .can_certify(true)
        .can_encrypt(false)
        .can_sign(true);
    let mut subkeys: Vec<SubkeyParams> = Vec::with_capacity(3);
    // make auth
    {
        let mut subkey_builder = SubkeyParamsBuilder::default();
        subkey_builder
            .can_authenticate(true)
            .can_sign(false)
            .can_certify(false)
            .can_encrypt(false)
            .key_type(key_algo.clone());
        let subkey = subkey_builder.build().unwrap();
        subkeys.push(subkey);
    }
    // make sign
    // {
    //     let mut subkey_builder = SubkeyParamsBuilder::default();
    //     subkey_builder
    //         .can_authenticate(false)
    //         .can_sign(true)
    //         .can_certify(false)
    //         .can_encrypt(false)
    //         .key_type(key_algo.clone());
    //     let subkey = subkey_builder.build().unwrap();
    //     subkeys.push(subkey);
    // }
    // make encrypt
    {
        let mut subkey_builder = SubkeyParamsBuilder::default();
        subkey_builder
            .can_authenticate(false)
            .can_sign(false)
            .can_certify(false)
            .can_encrypt(true)
            .key_type(key_algo.clone());
        let subkey = subkey_builder.build().unwrap();
        subkeys.push(subkey);
    }
    key_params.subkeys(subkeys);
    let secret_key_params = key_params.build().unwrap();
    let secret_key = secret_key_params.generate(&mut rng).unwrap();
    let passwd_fn = || String::new();
    let signed_secret = secret_key.sign(&mut rng, passwd_fn).unwrap();
    let public_key = signed_secret.public_key();
    let signed_public_key = public_key
        .sign(&mut rng, &signed_secret, passwd_fn)
        .unwrap();
    save_pubkey(&signed_public_key, "public.asc").unwrap();
    (signed_secret, signed_public_key)
}
