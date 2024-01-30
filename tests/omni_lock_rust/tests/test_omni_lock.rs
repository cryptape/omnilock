#![allow(unused_imports)]
#![allow(dead_code)]

mod misc;

use std::fs::File;
use std::hash::Hash;
use std::io::Read;

use blake2b_rs::{Blake2b, Blake2bBuilder};
use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier, TxVerifyEnv};
use ckb_types::core::hardfork::HardForks;
use ckb_types::packed::ScriptOpt;
use ckb_types::{
    bytes::Bytes,
    bytes::BytesMut,
    core::{cell::ResolvedTransaction, EpochNumberWithFraction, HeaderView},
    packed::WitnessArgs,
    prelude::*,
    H256,
};
use lazy_static::lazy_static;
use misc::*;
use omni_lock_test::schemas::{basic::*, blockchain::WitnessArgsBuilder, top_level::*};
use std::sync::Arc;

//
// owner lock section
//
#[test]
fn test_simple_owner_lock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    // For ckb 0.40.0
    // let mut verifier =
    //     TransactionScriptsVerifier::new(&resolved_tx, data_loader);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_owner_lock_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_simple_owner_lock_mismatched() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);
    config.scheme = TestScheme::OwnerLockMismatched;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_LOCK_SCRIPT_HASH_NOT_FOUND)
}

#[test]
fn test_owner_lock_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_owner_lock_on_wl_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::OnWhiteList;
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_owner_lock_not_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::NotOnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NOT_ON_WHITE_LIST)
}

#[test]
fn test_owner_lock_no_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    // only black list is used, but not on it.
    // but omni_lock requires at least one white list
    config.scheme = TestScheme::NotOnBlackList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NO_WHITE_LIST)
}

#[test]
fn test_owner_lock_on_bl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::BothOn;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_ON_BLACK_LIST)
}

#[test]
fn test_owner_lock_emergency_halt_mode() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::EmergencyHaltMode;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_RCE_EMERGENCY_HALT)
}

//
// pubkey hash section
//

#[test]
fn test_pubkey_hash_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_pubkey_hash_without_omni_identity() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.set_omni_identity(false);
    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_pubkey_hash_on_wl_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_pubkey_hash_not_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::NotOnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NOT_ON_WHITE_LIST)
}

#[test]
fn test_pubkey_hash_no_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    // only black list is used, but not on it.
    // but omni_lock requires at least one white list
    config.scheme = TestScheme::NotOnBlackList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NO_WHITE_LIST)
}

#[test]
fn test_pubkey_hash_on_bl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::BothOn;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_ON_BLACK_LIST)
}

#[test]
fn test_pubkey_hash_emergency_halt_mode() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::EmergencyHaltMode;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_RCE_EMERGENCY_HALT)
}

#[test]
fn test_rsa_via_dl_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rsa_via_dl_wrong_sig() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();
    config.scheme = TestScheme::RsaWrongSignature;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_RSA_VERIFY_FAILED);
}

#[test]
fn test_rsa_via_dl_unlock_with_time_lock() {
    let mut data_loader = DummyDataLoader::new();

    let args_since = 0x2000_0000_0000_0000u64 + 200;
    let input_since = 0x2000_0000_0000_0000u64 + 200;
    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();
    config.set_since(args_since, input_since);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rsa_via_dl_unlock_with_time_lock_failed() {
    let mut data_loader = DummyDataLoader::new();

    let args_since = 0x2000_0000_0000_0000u64 + 200;
    let input_since = 0x2000_0000_0000_0000u64 + 100;
    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();
    config.set_since(args_since, input_since);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);

    assert_script_error(verify_result.unwrap_err(), ERROR_INCORRECT_SINCE_VALUE);
}

// currently, the signature can only be signed via hardware.
// Here we can only provide a failed case.
#[test]
fn test_iso9796_2_batch_via_dl_unlock_failed() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_iso9796_2();

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_eth_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_ETHEREUM, false);
    config.set_chain_config(Box::new(EthereumConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn test_btc_success(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: vtype,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn test_cobuild_btc_success(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: vtype,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn test_btc_err_pubkey(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: vtype,
        pubkey_err: true,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
    assert_script_error(verify_result.unwrap_err(), ERROR_PUBKEY_BLAKE160_HASH);
}

fn test_btc(vtype: u8) {
    test_btc_success(vtype);
    test_btc_err_pubkey(vtype);
}

#[test]
fn test_btc_unlock() {
    test_btc(BITCOIN_V_TYPE_P2PKHUNCOMPRESSED);
    test_btc(BITCOIN_V_TYPE_P2PKHCOMPRESSED);
    test_btc(BITCOIN_V_TYPE_SEGWITP2SH);
    test_btc(BITCOIN_V_TYPE_SEGWITBECH32);
}

#[test]
fn test_cobuild_btc_native_segwit() {
    test_cobuild_btc_success(BITCOIN_V_TYPE_P2PKHCOMPRESSED);
}

#[test]
fn test_dogecoin_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DOGECOIN, false);
    config.set_chain_config(Box::new(DogecoinConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dogecoin_err_pubkey() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DOGECOIN, false);
    let mut dogecoin = DogecoinConfig::default();
    dogecoin.0.pubkey_err = true;
    config.set_chain_config(Box::new(dogecoin));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err())
}

fn test_eos_success(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_EOS, false);
    let mut eos = EOSConfig::default();
    eos.0.sign_vtype = vtype;
    config.set_chain_config(Box::new(EOSConfig::default()));

    let tx: ckb_types::core::TransactionView = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn test_eos_err_pubkey(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_EOS, false);
    let mut eos = EOSConfig::default();
    eos.0.sign_vtype = vtype;
    eos.0.pubkey_err = true;
    config.set_chain_config(Box::new(eos));

    let tx: ckb_types::core::TransactionView = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
    assert_script_error(verify_result.unwrap_err(), ERROR_PUBKEY_BLAKE160_HASH);
}

fn test_eos(vtype: u8) {
    test_eos_success(vtype);
    test_eos_err_pubkey(vtype)
}

#[test]
fn test_eos_unlock() {
    test_eos(BITCOIN_V_TYPE_P2PKHCOMPRESSED);
    test_eos(BITCOIN_V_TYPE_P2PKHUNCOMPRESSED);
}

#[test]
fn test_tron_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_TRON, false);
    config.set_chain_config(Box::new(TronConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_tron_err_pubkey() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_TRON, false);
    let mut tron = TronConfig::default();
    tron.pubkey_err = true;
    config.set_chain_config(Box::new(tron));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
    assert_script_error(verify_result.unwrap_err(), ERROR_PUBKEY_BLAKE160_HASH);
}

#[test]
fn test_eth_displaying_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_ETHEREUM_DISPLAYING, false);
    config.set_chain_config(Box::new(EthereumDisplayConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

// this test can fail during development
#[test]
fn test_binary_unchanged() {
    let mut buf = [0u8; 8 * 1024];
    // build hash
    let mut blake2b = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();

    let mut fd = File::open("../../build/omni_lock").expect("open file");
    loop {
        let read_bytes = fd.read(&mut buf).expect("read file");
        if read_bytes > 0 {
            blake2b.update(&buf[..read_bytes]);
        } else {
            break;
        }
    }

    let mut hash = [0u8; 32];
    blake2b.finalize(&mut hash);

    let actual_hash = faster_hex::hex_string(&hash);
    assert_eq!(
        "091cd5995b23f1f1e5041b88f302a1c25bc4aa2a7e223358084d1ae0f990369e",
        &actual_hash
    );
}

#[test]
fn test_cobuild_no_has_message() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    config.custom_extension_witnesses = Some(vec![Bytes::from([00, 00].to_vec())]);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_append_witnessed_less_than_4() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    config.custom_extension_witnesses = Some(vec![
        Bytes::from([00, 01, 00].to_vec()),
        Bytes::from([00, 00, 00, 00].to_vec()),
        Bytes::new(),
    ]);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_non_empty_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let lock_args = config.gen_args();
    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(lock_args, 2)], &mut config);

    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_MOL2_ERR_OVERFLOW);
}

#[test]
fn test_cobuild_input_cell_data_size_0() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_input_cell_data_size_1() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let inputs_len = tx.inputs().len();
    for i in 0..inputs_len {
        let input_cell = tx.inputs().get(i).unwrap();
        let input_cell_out_point = input_cell.previous_output();
        let (input_cell_output, _) = data_loader.cells.get(&input_cell_out_point).unwrap();
        data_loader.cells.insert(
            input_cell_out_point,
            (input_cell_output.clone(), Bytes::from(vec![0x42; 1])),
        );
    }
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_input_cell_data_size_2048() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let inputs_len = tx.inputs().len();
    for i in 0..inputs_len {
        let input_cell = tx.inputs().get(i).unwrap();
        let input_cell_out_point = input_cell.previous_output();
        let (input_cell_output, _) = data_loader.cells.get(&input_cell_out_point).unwrap();
        data_loader.cells.insert(
            input_cell_out_point,
            (input_cell_output.clone(), Bytes::from(vec![0x42; 2048])),
        );
    }
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_input_cell_data_size_2049() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let inputs_len = tx.inputs().len();
    for i in 0..inputs_len {
        let input_cell = tx.inputs().get(i).unwrap();
        let input_cell_out_point = input_cell.previous_output();
        let (input_cell_output, _) = data_loader.cells.get(&input_cell_out_point).unwrap();
        data_loader.cells.insert(
            input_cell_out_point,
            (input_cell_output.clone(), Bytes::from(vec![0x42; 2049])),
        );
    }
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_input_cell_data_size_500k() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let inputs_len = tx.inputs().len();
    for i in 0..inputs_len {
        let input_cell = tx.inputs().get(i).unwrap();
        let input_cell_out_point = input_cell.previous_output();
        let (input_cell_output, _) = data_loader.cells.get(&input_cell_out_point).unwrap();
        data_loader.cells.insert(
            input_cell_out_point,
            (
                input_cell_output.clone(),
                Bytes::from(vec![0x42; 500 * 1024]),
            ),
        );
    }
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_wrong_union_id() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);

    let witness = tx.witnesses().get(0).unwrap();
    let mut witness_builder = witness.as_builder();
    witness_builder.replace(0, 0x03.into());
    let witness = witness_builder.build();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_MOL2_ERR_OVERFLOW);
}

#[test]
fn test_cobuild_sighash_all_only() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.cobuild_message = None;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_append_witnessargs() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    config.custom_extension_witnesses = Some(vec![WitnessArgsBuilder::default()
        .lock(Some(Bytes::from([0u8; 65].to_vec())).pack())
        .build()
        .as_bytes()]);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_append_other_witnesslayout() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    config.custom_extension_witnesses = Some(vec![WitnessLayoutBuilder::default()
        .set(WitnessLayoutUnion::SighashAllOnly(
            SighashAllOnlyBuilder::default()
                .seal(Bytes::from([0u8; 32].to_vec()).pack())
                .build(),
        ))
        .build()
        .as_bytes()]);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_sighashall_dup() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    const WSITNESS_LAYOUT_SIGHASH_ALL: u32 = 4278190081;
    let mut witness = Vec::new();
    witness.resize(6, 0);
    witness[..4].copy_from_slice(&WSITNESS_LAYOUT_SIGHASH_ALL.to_le_bytes());

    config.custom_extension_witnesses = Some(vec![Bytes::from(witness)]);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), MOL2_ERR_OVERFLOW);
}

#[test]
fn test_cobuild_no_cobuild_append_sighash_all() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    config.custom_extension_witnesses = Some(vec![Bytes::from(
        WitnessLayoutBuilder::default()
            .set(WitnessLayoutUnion::SighashAll(
                SighashAllBuilder::default()
                    .message(MessageBuilder::default().build())
                    .seal(Bytes::from([0u8; 32].to_vec()).pack())
                    .build(),
            ))
            .build()
            .as_bytes(),
    )]);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_insert_witness_less_4_before_sighashall() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    config.custom_extension_witnesses_beginning = Some(vec![Bytes::from([00, 01, 02].to_vec())]);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.unwrap_err();
}

#[test]
fn test_cobuild_big_message() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;

    let always_success_script = build_always_success_script();
    let always_success_script_hash = always_success_script.calc_script_hash();
    let always_success_script_opt = ScriptOpt::new_builder()
        .set(Some(always_success_script))
        .build();

    let mut action_vec = Vec::<Action>::new();
    for _ in 0..3072 {
        let action_builder = Action::new_builder();
        let action_builder = action_builder
            .script_info_hash(ckb_types::packed::Byte32::from_slice(&[0x00; 32]).unwrap());
        let action_builder = action_builder.script_hash(always_success_script_hash.clone());
        let action_builder = action_builder.data(ckb_types::packed::Bytes::new_unchecked(
            Bytes::from(vec![0x42; 128]),
        ));
        let action = action_builder.build();
        action_vec.push(action);
    }
    let action_vec = ActionVec::new_builder().extend(action_vec).build();
    let message = Message::new_builder().actions(action_vec).build();
    config.cobuild_message = Some(message); // Message is 651300 bytes in molecule type.

    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);

    let output0 = tx
        .output(0)
        .unwrap()
        .as_builder()
        .type_(always_success_script_opt)
        .build();
    let tx = tx.as_advanced_builder().set_outputs(vec![output0]).build();

    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    // Print tx in json format.
    //
    // [dependencies]
    // ckb-jsonrpc-types = "0.113.0"
    // serde = "*"
    // serde_json = "*"
    //
    // let tx_json = ckb_jsonrpc_types::TransactionView::from(resolved_tx.transaction.clone());
    // println!("{}", serde_json::to_string(&tx_json).unwrap());

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_simple_owner_lock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);
    config.cobuild_enabled = true;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_simple_owner_lock_mismatched() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);
    config.cobuild_enabled = true;
    config.scheme = TestScheme::OwnerLockMismatched;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_LOCK_SCRIPT_HASH_NOT_FOUND)
}

#[test]
fn test_cobuild_owner_lock_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.cobuild_enabled = true;
    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_owner_lock_on_wl_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.cobuild_enabled = true;
    config.scheme = TestScheme::OnWhiteList;
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_cobuild_rsa_via_dl_unlock_with_time_lock() {
    let mut data_loader = DummyDataLoader::new();

    let args_since = 0x2000_0000_0000_0000u64 + 200;
    let input_since = 0x2000_0000_0000_0000u64 + 200;
    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.cobuild_enabled = true;
    config.set_rsa();
    config.set_since(args_since, input_since);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_rsa_via_dl_unlock_with_time_lock_failed() {
    let mut data_loader = DummyDataLoader::new();

    let args_since = 0x2000_0000_0000_0000u64 + 200;
    let input_since = 0x2000_0000_0000_0000u64 + 100;
    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.cobuild_enabled = true;
    config.set_rsa();
    config.set_since(args_since, input_since);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);

    assert_script_error(verify_result.unwrap_err(), ERROR_INCORRECT_SINCE_VALUE);
}

#[test]
fn test_cobuild_append_witnessargs_acp() {
    let mut data_loader: DummyDataLoader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));
    config.set_acp_config(Some((0, 0)));

    config.custom_extension_witnesses = Some(vec![WitnessArgsBuilder::default()
        .lock(Some(Bytes::from([0u8; 65].to_vec())).pack())
        .build()
        .as_bytes()]);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_append_witnessargs_since() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let args_since = 0x2000_0000_0000_0000u64 + 200;
    let input_since = 0x2000_0000_0000_0000u64 + 200;
    config.set_since(args_since, input_since);

    config.custom_extension_witnesses = Some(vec![WitnessArgsBuilder::default()
        .lock(Some(Bytes::from([0u8; 65].to_vec())).pack())
        .build()
        .as_bytes()]);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_append_other_witnesslayout_acp() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));
    config.set_acp_config(Some((0, 0)));

    config.custom_extension_witnesses = Some(vec![WitnessLayoutBuilder::default()
        .set(WitnessLayoutUnion::SighashAllOnly(
            SighashAllOnlyBuilder::default()
                .seal(Bytes::from([0u8; 32].to_vec()).pack())
                .build(),
        ))
        .build()
        .as_bytes()]);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_eth_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_ETHEREUM, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(EthereumConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_eth_displaying_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_ETHEREUM_DISPLAYING, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(EthereumDisplayConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_check_action_script_hash_is_in_inputs() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;

    let always_success_script = build_always_success_script();
    let always_success_script_hash = always_success_script.calc_script_hash();
    let always_success_script_opt = ScriptOpt::new_builder()
        .set(Some(always_success_script))
        .build();

    let mut action_vec = Vec::<Action>::new();
    let action_builder = Action::new_builder();
    let action_builder = action_builder
        .script_info_hash(ckb_types::packed::Byte32::from_slice(&[0x00; 32]).unwrap());
    let action_builder = action_builder.script_hash(always_success_script_hash.clone());
    let action_builder = action_builder.data(ckb_types::packed::Bytes::new_unchecked(Bytes::from(
        vec![0x42; 128],
    )));
    let action = action_builder.build();
    action_vec.push(action);
    let action_vec = ActionVec::new_builder().extend(action_vec).build();
    let message = Message::new_builder().actions(action_vec).build();
    config.cobuild_message = Some(message);

    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let (cell, cell_data) = data_loader
        .cells
        .get(&tx.inputs().get(0).unwrap().previous_output())
        .unwrap();
    let cell = cell
        .clone()
        .as_builder()
        .type_(always_success_script_opt)
        .build();
    data_loader.cells.insert(
        tx.inputs().get(0).unwrap().previous_output(),
        (cell.clone(), cell_data.clone()),
    );

    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_cobuild_check_action_script_hash_is_in_2_outputs() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;

    let always_success_script_0 = build_always_success_script();
    let always_success_script_1 = build_always_success_script();
    let always_success_script_0 = always_success_script_0
        .as_builder()
        .args(vec![0x00].pack())
        .build();
    let always_success_script_1 = always_success_script_1
        .as_builder()
        .args(vec![0x01].pack())
        .build();
    let always_success_script_hash_0 = always_success_script_0.calc_script_hash();
    let always_success_script_hash_1 = always_success_script_1.calc_script_hash();
    let always_success_script_opt_0 = ScriptOpt::new_builder()
        .set(Some(always_success_script_0))
        .build();
    let always_success_script_opt_1 = ScriptOpt::new_builder()
        .set(Some(always_success_script_1))
        .build();

    let mut action_vec = Vec::<Action>::new();
    let action_builder_0 = Action::new_builder();
    let action_builder_0 = action_builder_0
        .script_info_hash(ckb_types::packed::Byte32::from_slice(&[0x00; 32]).unwrap());
    let action_builder_0 = action_builder_0.script_hash(always_success_script_hash_0.clone());
    let action_builder_0 = action_builder_0.data(ckb_types::packed::Bytes::new_unchecked(
        Bytes::from(vec![0x42; 128]),
    ));
    let action_0 = action_builder_0.build();
    action_vec.push(action_0.clone());
    let action_builder_1 = Action::new_builder();
    let action_builder_1 = action_builder_1
        .script_info_hash(ckb_types::packed::Byte32::from_slice(&[0x00; 32]).unwrap());
    let action_builder_1 = action_builder_1.script_hash(always_success_script_hash_1.clone());
    let action_builder_1 = action_builder_1.data(ckb_types::packed::Bytes::new_unchecked(
        Bytes::from(vec![0x42; 128]),
    ));
    let action_1 = action_builder_1.build();
    action_vec.push(action_1);

    let action_vec = ActionVec::new_builder().extend(action_vec).build();
    let message = Message::new_builder().actions(action_vec).build();
    config.cobuild_message = Some(message); // Message is 651300 bytes in molecule type.

    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);

    let output0 = tx
        .output(0)
        .unwrap()
        .as_builder()
        .type_(always_success_script_opt_0)
        .build();
    let output1 = tx
        .output(0)
        .unwrap()
        .as_builder()
        .type_(always_success_script_opt_1)
        .build();
    let tx = tx
        .as_advanced_builder()
        .set_outputs(vec![output0, output1])
        .outputs_data(vec![vec![0x00].pack(), vec![0x00].pack()])
        .build();

    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}
