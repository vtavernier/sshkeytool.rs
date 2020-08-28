use crate::schema::secrets;

use super::Host;

pub trait EncryptableSecret {
    fn encrypted_mut(&mut self) -> &mut i32;
    fn secret_mut(&mut self) -> &mut Vec<u8>;
}

#[derive(Identifiable, Queryable, Associations, PartialEq, Debug)]
#[belongs_to(Host)]
pub struct Secret {
    pub id: i32,
    pub host_id: i32,
    pub secret: Vec<u8>,
    pub encrypted: i32,
}

impl EncryptableSecret for Secret {
    fn encrypted_mut(&mut self) -> &mut i32 {
        &mut self.encrypted
    }

    fn secret_mut(&mut self) -> &mut Vec<u8> {
        &mut self.secret
    }
}

#[derive(Insertable, PartialEq, Debug)]
#[table_name = "secrets"]
pub struct NewSecret {
    pub host_id: i32,
    pub secret: Vec<u8>,
    pub encrypted: i32,
}

impl EncryptableSecret for NewSecret {
    fn encrypted_mut(&mut self) -> &mut i32 {
        &mut self.encrypted
    }

    fn secret_mut(&mut self) -> &mut Vec<u8> {
        &mut self.secret
    }
}

pub struct SecretKey {
    key: [u8; 32],
}

impl SecretKey {
    pub fn new(password: &str) -> Self {
        use ring::pbkdf2::*;

        let mut key = [0; 32];

        // Keys
        let salt = [0, 1, 2, 3, 4, 5, 6, 7];

        derive(
            PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(100).unwrap(),
            &salt,
            password.as_bytes(),
            &mut key,
        );

        Self { key }
    }

    fn to_unbound_key(&self, alg: &'static ring::aead::Algorithm) -> ring::aead::UnboundKey {
        ring::aead::UnboundKey::new(alg, &self.key).unwrap()
    }
}

struct NonceSeq {
    seed: i32,
    rand: rand::rngs::StdRng,
}

impl NonceSeq {
    pub fn new() -> Self {
        use rand::RngCore;

        let seed = rand::rngs::OsRng.next_u64() as i32;
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: i32) -> Self {
        use rand::SeedableRng;

        let rand = rand::rngs::StdRng::seed_from_u64(seed as u64);
        Self { seed, rand }
    }
}

impl ring::aead::NonceSequence for NonceSeq {
    fn advance(&mut self) -> std::result::Result<ring::aead::Nonce, ring::error::Unspecified> {
        use rand::Rng;
        use ring::aead::Nonce;

        // Encryption nonce
        let mut nonce = [0; 12];
        self.rand.fill(&mut nonce);
        Ok(Nonce::assume_unique_for_key(nonce))
    }
}

static RING_ALG: &ring::aead::Algorithm = &ring::aead::CHACHA20_POLY1305;

pub trait EncryptableSecretExt {
    // TODO: Should also be a result
    fn encrypt(&mut self, key: &SecretKey);
    // TODO: Should be a Result
    fn decrypt(&mut self, key: Option<&SecretKey>) -> Option<()>;
}

impl<T: EncryptableSecret> EncryptableSecretExt for T {
    fn encrypt(&mut self, key: &SecretKey) {
        use ring::aead::*;

        let nonce_seq = NonceSeq::new();
        let seed = nonce_seq.seed;

        if *self.encrypted_mut() != 0 {
            panic!("secret is already encrypted!");
        }

        // Get key from password
        let key = key.to_unbound_key(RING_ALG);

        //let opening_key = OpeningKey::new(key, nonce_seq);
        let mut sealing_key = SealingKey::new(key, nonce_seq);

        // Seal secret
        sealing_key
            .seal_in_place_append_tag(Aad::empty(), self.secret_mut())
            .unwrap();

        *self.encrypted_mut() = seed;
    }

    fn decrypt(&mut self, key: Option<&SecretKey>) -> Option<()> {
        use ring::aead::*;

        let (key, nonce_seq) = if *self.encrypted_mut() == 0 {
            return Some(());
        } else if let Some(key) = key {
            (key, NonceSeq::from_seed(*self.encrypted_mut()))
        } else {
            return None;
        };

        // Get key from password
        let key = key.to_unbound_key(RING_ALG);

        let mut opening_key = OpeningKey::new(key, nonce_seq);

        // Seal secret
        match opening_key.open_in_place(Aad::empty(), self.secret_mut()) {
            Ok(plaintext) => {
                let len = plaintext.len();
                self.secret_mut().resize(len, 0);
                *self.encrypted_mut() = 0;

                Some(())
            }
            Err(e) => {
                error!("{}", e);
                None
            }
        }
    }
}
