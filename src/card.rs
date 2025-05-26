use std::str::FromStr;

use card_backend_pcsc::PcscBackend;
use openpgp_card::{
    Card,
    ocard::{
        KeyType,
        algorithm::AlgorithmAttributes,
        data::Sex,
    },
    state::{Open, Transaction},
};
use tracing::{debug, info};

use crate::{ADMIN_PIN, rsa::generate_rsa_importable_key};

pub fn check_supported_rsa_lengths(card: &mut Card<Open>) -> anyhow::Result<()> {
    let mut transaction = card.transaction().unwrap();
    if let Some(info) = transaction.algorithm_information().unwrap() {
        let keys = &[
            KeyType::Authentication,
            KeyType::Decryption,
            KeyType::Signing,
        ];
        for key in keys {
            let mut rsa_4096_found = false;
            for info in info.for_keytype(*key) {
                if let AlgorithmAttributes::Rsa(attr) = info {
                    if attr.len_n() == 4096 {
                        rsa_4096_found = true;
                    }
                }
            }
            if rsa_4096_found {
                info!("Key {:?} compatible with RSA 4096", key);
            } else {
                info!("Key {:?} NOT with RSA 4096", key);
            }
        }
    }
    Ok(())
}

pub(crate) fn get_card() -> Card<Open> {
    let mut cards = PcscBackend::cards(Some(pcsc::ShareMode::Exclusive)).unwrap();
    if let Some(Ok(card)) = cards.next() {
        
        Card::new(card).unwrap()
    } else {
        panic!("No cards found");
    }
}

pub(crate) fn get_yubikey_firmware(transaction: &mut Card<Transaction<'_>>) -> String {
    let firmware = transaction.firmware_version().unwrap();
    
    firmware
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

pub(crate) fn import_fresh_keys(card: &mut Card<Open>) -> anyhow::Result<()> {
    let key_types = [
        KeyType::Authentication,
        KeyType::Signing,
        KeyType::Decryption,
    ];
    let user_id = String::from_str("Filip Ślęzak <fslezak@teonite.com>")?;
    for key_type in key_types {
        debug!("Importing key {:?}", &key_type);
        let importable_key = Box::new(generate_rsa_importable_key(key_type, user_id.clone()));
        debug!(
            "Key generated ! Ready for import. Key locked ? ({0})",
            importable_key.is_locked()
        );
        {
            let mut transaction = card.transaction()?;
            let pin = secrecy::Secret::from_str(ADMIN_PIN)?;
            let mut admin = transaction.to_admin_card(pin)?;
            debug!("Setting key slot");
            admin.set_algorithm(key_type, openpgp_card::ocard::algorithm::AlgoSimple::RSA4k)?;
            debug!("Slot configured");
            admin.import_key(importable_key, key_type)?;
        };
        debug!("Key imported");
    }
    Ok(())
}

pub(crate) fn set_ident(card: &mut Card<Open>) -> anyhow::Result<()> {
    {
        let mut transaction = card.transaction()?;
        let pin = secrecy::Secret::from_str(ADMIN_PIN)?;
        let mut admin = transaction.to_admin_card(pin)?;
        debug!("Setting touch policy.");
        admin.set_touch_policy(
            KeyType::Authentication,
            openpgp_card::ocard::data::TouchPolicy::On,
        )?;
        admin.set_touch_policy(KeyType::Signing, openpgp_card::ocard::data::TouchPolicy::On)?;
        debug!("Touch policy set");
        let name = "Filip<<Slezak";
        admin.set_cardholder_name(name)?;
        debug!("Card holder name set");
        admin.set_sex(Sex::Male)?;
        debug!("Sex set to male");
    }
    info!("Card configured.");
    Ok(())
}
