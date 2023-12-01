use did_key::{Ed25519KeyPair, Fingerprint, KeyMaterial, PatchedKeyPair};
use ed25519_zebra::{SigningKey, VerificationKey};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use ucan::builder::UcanBuilder;
use ucan::capability::{Capabilities, Capability};
use ucan::crypto::did::{DidParser, KeyConstructorSlice};
use ucan::Ucan;
use ucan_key_support::ed25519::{bytes_to_ed25519_key, Ed25519KeyMaterial};

pub const SUPPORTED_UCAN_KEYS: &KeyConstructorSlice = &[
    // https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L94
    (&[0xed, 0x01], bytes_to_ed25519_key),
];

pub fn did_to_issuer_key(did: &PatchedKeyPair) -> Ed25519KeyMaterial {
    let pub_key: VerificationKey =
        VerificationKey::try_from(did.public_key_bytes().as_slice()).unwrap();
    let mut pk_slice: [u8; 32] = [0; 32];
    let pk_bytes = did.private_key_bytes();

    pk_slice[..32].copy_from_slice(&pk_bytes[..32]);

    let private_key: SigningKey = SigningKey::from(pk_slice);
    Ed25519KeyMaterial(pub_key, Some(private_key))
}

pub fn did_uri(did: &PatchedKeyPair) -> String {
    format!("did:key:{}", did.fingerprint())
}

// A basic abstraction of a service that will use UCANs to control
// resource access. For UCAN purposes it keeps track of:
// - The set of registered users, using they DID url.
// - The set of proofs that have been submitted by registered users.
//   In a real implementation this should likely be stored in a block store.
#[derive(Default)]
struct Service {
    owners: HashSet<String>,       // Pub keys of the owners DIDs.
    proofs: HashMap<String, Ucan>, // Proof CID -> UCAN.
}

impl Service {
    fn new_owner(&mut self) -> PatchedKeyPair {
        let key_pair = did_key::generate::<Ed25519KeyPair>(None);
        self.owners.insert(did_uri(&key_pair));
        key_pair
    }

    fn remove_owner(&mut self, did: &PatchedKeyPair) {
        self.owners.remove(&did_uri(did));
    }

    // TODO: add a way to ensure only valid owners can add proofs, eg. signing the cid.
    fn add_proof(&mut self, cid: &str, payload: Ucan) {
        self.proofs.insert(cid.to_owned(), payload);
    }

    // Returns the capabilities for this UCAN if we find it's from a known user.
    async fn get_capabilities(&self, ucan: &Ucan) -> Result<Capabilities, String> {
        let mut parser = DidParser::new(SUPPORTED_UCAN_KEYS);
        // Check timestamps and signature.
        if ucan.validate(None, &mut parser).await.is_err() {
            return Err("Invalid UCAN".into());
        }

        // Check if there is a proof that matches a known valid issuer.
        for proof in ucan.proofs().clone().unwrap_or_default() {
            if let Some(owner_ucan) = self.proofs.get(&proof) {
                if owner_ucan.validate(None, &mut parser).await.is_err() {
                    return Err("Invalid owner UCAN".into());
                }
                // Check that the issuer DID is still a valid owner.
                if !self.owners.contains(ucan.issuer()) {
                    return Err("Issuer is not a valid owner".into());
                }
                // TODO: more checks?

                return Ok(ucan.capabilities().clone());
            }
        }
        Err("No proof found".into())
    }
}

#[tokio::main]
async fn main() {
    // Setup data server, data owner and 3rd party app DID.
    let mut server = Service::default();

    let valid_owner_did = server.new_owner();

    let app_did = did_key::generate::<Ed25519KeyPair>(None);

    // ======================================================
    // 1. THE HAPPY PATH
    // ======================================================

    // Create a UCAN delegating from owner to app.

    let capability = Capability::new(
        "wnfs://Pictures".into(),
        "crud/read".into(),
        Value::Object(Default::default()),
    );

    let owner_issuer = did_to_issuer_key(&valid_owner_did);

    let signable = UcanBuilder::default()
        .issued_by(&owner_issuer)
        .for_audience(&did_uri(&app_did))
        .claiming_capability(&capability)
        .build()
        .unwrap();

    let ucan_from_owner = signable.sign().await.unwrap();

    // Add the cid for this UCAN to the server proofs store.
    let cid = ucan_from_owner
        .to_cid(UcanBuilder::<Ed25519KeyMaterial>::default_hasher())
        .unwrap();
    server.add_proof(&cid.to_string(), ucan_from_owner.clone());

    // Create a UCAN delegating from app to owner, adding the previous UCAN as a proof.
    let app_issuer = did_to_issuer_key(&app_did);

    let signable = UcanBuilder::default()
        .issued_by(&app_issuer)
        .for_audience(&did_uri(&valid_owner_did))
        .claiming_capability(&capability)
        .witnessed_by(&ucan_from_owner, None)
        .build()
        .unwrap();

    let ucan_from_app = signable.sign().await.unwrap();
    println!(
        "UCAN capabilities from valid owner: {:?}",
        server.get_capabilities(&ucan_from_app).await
    );

    // ======================================================
    // 2. APP UCAN BYPASS
    // Now let's consider the app wants to spoof access. For that it creates
    // another did for an invalid user.
    // ======================================================

    let invalid_owner_did = did_key::generate::<Ed25519KeyPair>(None);

    // This new user creates a UCAN for the app
    let invalid_owner_issuer = did_to_issuer_key(&invalid_owner_did);

    let signable = UcanBuilder::default()
        .issued_by(&invalid_owner_issuer)
        .for_audience(&did_uri(&app_did))
        .claiming_capability(&capability)
        .build()
        .unwrap();

    let ucan_from_invalid_owner = signable.sign().await.unwrap();

    // Create a UCAN delegating from app to owner, adding the previous UCAN as a proof.

    let signable = UcanBuilder::default()
        .issued_by(&app_issuer)
        .for_audience(&did_uri(&invalid_owner_did))
        .claiming_capability(&capability)
        .witnessed_by(&ucan_from_invalid_owner, None)
        .build()
        .unwrap();
    let invalid_ucan_from_app = signable.sign().await.unwrap();
    println!(
        "UCAN capabilities from invalid owner: {:?}",
        server.get_capabilities(&invalid_ucan_from_app).await
    );

    // ======================================================
    // 3. UNKNOWN USER
    // The user that created the UCANs is not registered
    // anymore.
    // ======================================================
    server.remove_owner(&valid_owner_did);
    println!(
        "UCAN capabilities from now unknown owner: {:?}",
        server.get_capabilities(&ucan_from_app).await
    );
}
