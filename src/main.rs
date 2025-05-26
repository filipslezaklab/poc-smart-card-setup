use std::str::FromStr;

use anyhow::Result;
use card::{get_card, get_yubikey_firmware, set_ident};
use logs::init_logging;
use openpgp_card_rpgp::UploadableKey;
use rsa::{generate_rsa_importable_master_key, key_to_ssh, save_ssh};
use tracing::{debug, info};

mod card;
mod logs;
mod rsa;

pub(crate) const ADMIN_PIN: &str = "12345678";

pub(crate) const USER_PIN: &str = "123456";

fn main() -> Result<()> {
    init_logging();
    let mut card = get_card();
    {
        let mut transaction = card.transaction()?;
        let firmware = get_yubikey_firmware(&mut transaction);
        info!("Detected Smart card firmware: {firmware}");
    }
    // check_supported_rsa_lengths(&mut card)?;
    // set_ident(&mut card)?;
    // import_fresh_keys(&mut card)?;
    let user_id = "FirstName LastName <dummy@example.com>";
    debug!("Making RSA keys");
    let (secret, _) = generate_rsa_importable_master_key(user_id.to_string());
    debug!("Made RSA keys");
    let subkeys = secret.secret_subkeys;
    let auth = subkeys[0].clone();
    debug!("Running key to SSH");
    let auth_ssh = key_to_ssh(auth.clone())?;
    debug!("Auth key converted to SSH pub key: {}", auth_ssh.clone());
    debug!("Saving SSH");
    save_ssh(auth_ssh);
    debug!("SSH saved to file");
    debug!("Transporting keys to card");
    debug!("Transporting Auth key");
    // let sign = subkeys[1].clone();
    let encrypt = subkeys[1].clone();
    // import auth
    {
        let uploadable = Box::new(UploadableKey::from(auth.key.clone()));
        let mut transaction = card.transaction()?;
        let pin = secrecy::Secret::from_str(ADMIN_PIN)?;
        let mut admin = transaction.to_admin_card(pin)?;
        admin.import_key(uploadable, openpgp_card::ocard::KeyType::Authentication)?;
    }
    debug!("Auth key Imported to the card");
    debug!("Transporting Decryption key");
    // import decrypt/encrypt
    {
        let uploadable = Box::new(UploadableKey::from(encrypt.key.clone()));
        let mut transaction = card.transaction()?;
        let pin = secrecy::Secret::from_str(ADMIN_PIN)?;
        let mut admin = transaction.to_admin_card(pin)?;
        admin.import_key(uploadable, openpgp_card::ocard::KeyType::Decryption)?;
    }
    debug!("Decryption key Imported to the card");
    debug!("Transporting Primary Signing/Cert key");
    // import primary-key (sign slot)
    {
        let uploadable = Box::new(UploadableKey::from(secret.primary_key.clone()));
        let mut transaction = card.transaction()?;
        let pin = secrecy::Secret::from_str(ADMIN_PIN)?;
        let mut admin = transaction.to_admin_card(pin)?;
        admin.import_key(uploadable, openpgp_card::ocard::KeyType::Signing)?;
    }
    debug!("Primary Sign/Cert key Imported to the card");
    // import sign
    // {
    //     let uploadable = Box::new(UploadableKey::from(sign.key.clone()));
    //     let mut transaction = card.transaction()?;
    //     let pin = secrecy::Secret::from_str(ADMIN_PIN)?;
    //     let mut admin = transaction.to_admin_card(pin)?;
    //     admin.import_key(uploadable, openpgp_card::ocard::KeyType::Signing)?;
    // }
    set_ident(&mut card)?;
    Ok(())
}
