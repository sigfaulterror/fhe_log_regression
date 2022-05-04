//! A module containing the different kind of keys used in the program.
use crate::zqz;
use crate::PARAMS;
use concrete::crypto_api;
use std::rc::Rc;

const SECRET_FILE: &str = "secret_key.json";
const BOOTSTRAPPING_FILE: &str = "bootstrapping_key.txt";
const KEYSWITCHING_FILE: &str = "keyswitching_key.txt";

/// A set of keys publicly available, allowing to perform bootstrap and keyswitch operations on
/// ciphertext.
#[derive(Debug, PartialEq)]
pub struct HomomorphicKey {
    pub(super) bootstrapping: crypto_api::LWEBSK,
    pub(super) keyswitching: crypto_api::LWEKSK,
}

/// A secret key available only to the user side, allowing to encrypt ant decrypt data.
#[derive(Debug, PartialEq)]
pub struct EncryptKey {
    pub(super) secret: crypto_api::LWESecretKey,
    pub(super) evaluation: Rc<HomomorphicKey>,
}

impl EncryptKey {
    /// Generates a new encrypt key
    pub fn new() -> EncryptKey {
        // We generate the lwe secret key
        let rlwe_sk: crypto_api::RLWESecretKey =
            crypto_api::RLWESecretKey::new(&PARAMS.rlwe_setting);
        let lwe_sk: crypto_api::LWESecretKey = if PARAMS.with_ks {
            crypto_api::LWESecretKey::new(&PARAMS.lwe_setting)
        } else {
            rlwe_sk.to_lwe_secret_key()
        };
        // We generats the bootstrapping and keyswitching keys
        let bsk: crypto_api::LWEBSK =
            crypto_api::LWEBSK::new(&lwe_sk, &rlwe_sk, PARAMS.bs_base_log, PARAMS.bs_level);
        let ksk: crypto_api::LWEKSK = if PARAMS.with_ks {
            crypto_api::LWEKSK::new(
                &rlwe_sk.to_lwe_secret_key(),
                &lwe_sk,
                PARAMS.ks_base_log,
                PARAMS.ks_level,
            )
        } else {
            crypto_api::LWEKSK::zero(
                &rlwe_sk.to_lwe_secret_key(),
                &lwe_sk,
                PARAMS.ks_base_log,
                PARAMS.ks_level,
            )
        };
        // We pack the homomorphic keys
        let hk = HomomorphicKey {
            bootstrapping: bsk,
            keyswitching: ksk,
        };

        EncryptKey {
            secret: lwe_sk,
            evaluation: Rc::new(hk),
        }
    }

    /// Generates a new encrypt key
    #[allow(dead_code)]
    pub fn new_zero() -> EncryptKey {
        // We generate the lwe secret key
        let rlwe_sk: crypto_api::RLWESecretKey =
            crypto_api::RLWESecretKey::new(&PARAMS.rlwe_setting);
        let lwe_sk: crypto_api::LWESecretKey = rlwe_sk.to_lwe_secret_key();
        // We generats the bootstrapping and keyswitching keys
        let bsk: crypto_api::LWEBSK =
            crypto_api::LWEBSK::zero(&lwe_sk, &rlwe_sk, PARAMS.bs_base_log, PARAMS.bs_level);
        let ksk: crypto_api::LWEKSK =
            crypto_api::LWEKSK::zero(&lwe_sk, &lwe_sk, PARAMS.ks_base_log, PARAMS.ks_level);
        // We pack the homomorphic keys
        let hk = HomomorphicKey {
            bootstrapping: bsk,
            keyswitching: ksk,
        };

        EncryptKey {
            secret: lwe_sk,
            evaluation: Rc::new(hk),
        }
    }

    /// Checks whether the keys with this prefix exist or not.
    pub fn keys_exist(prefix: &str) -> bool {
        use std::path::Path;
        Path::new(format!("{}_{}", prefix, SECRET_FILE).as_str()).exists()
            && Path::new(format!("{}_{}", prefix, BOOTSTRAPPING_FILE).as_str()).exists()
            && Path::new(format!("{}_{}", prefix, KEYSWITCHING_FILE).as_str()).exists()
    }

    /// Saves the encryption keys to files
    pub fn save_to_files(&self, prefix: &str) {
        self.secret
            .save(format!("{}_{}", prefix, SECRET_FILE).as_str())
            .unwrap();
        self.evaluation
            .bootstrapping
            .save(format!("{}_{}", prefix, BOOTSTRAPPING_FILE).as_str());
        self.evaluation
            .keyswitching
            .save(format!("{}_{}", prefix, KEYSWITCHING_FILE).as_str());
    }

    /// Loads the encryption keys from files
    pub fn load_from_files(prefix: &str) -> EncryptKey {
        let secret_key =
            crypto_api::LWESecretKey::load(format!("{}_{}", prefix, SECRET_FILE).as_str())
                .expect("No Secret Key File");
        let bsk = crypto_api::LWEBSK::load(format!("{}_{}", prefix, BOOTSTRAPPING_FILE).as_str());
        let ksk = crypto_api::LWEKSK::load(format!("{}_{}", prefix, KEYSWITCHING_FILE).as_str());
        let hk = HomomorphicKey {
            bootstrapping: bsk,
            keyswitching: ksk,
        };
        EncryptKey {
            secret: secret_key,
            evaluation: Rc::new(hk),
        }
    }

    /// Encrypt the given message
    pub fn encrypt_float(&self, message: f64,min: f64, max:f64,nb_bit_precision:usize, nb_bit_padding:usize) -> zqz::cipherfloat::Cipherfloat {
            let m = message % (PARAMS.modulo as f64);
            let encoder: crypto_api::Encoder = crypto_api::Encoder::new_rounding_context(
                min,
                max,
                nb_bit_precision,
                nb_bit_padding
                )
            .unwrap();
            let ct: crypto_api::LWE =
                crypto_api::LWE::encode_encrypt(&self.secret, m, &encoder).unwrap();
            zqz::cipherfloat::Cipherfloat {
                cipherfloat: ct,
                evaluation_key: self.evaluation.clone(),
            }
        }
    //
    pub fn encrypt_vector(&self, v: &Vec<f64>, min: f64, max:f64,nb_bit_precision:usize, nb_bit_padding:usize) -> zqz::vector::CipherVector {

        let mut cv :Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();
        for i in 0..v.len(){
            let c : zqz::cipherfloat::Cipherfloat  = self.encrypt_float(v[i],min,max,nb_bit_precision,nb_bit_padding);
            cv.push(c);
        }
        zqz::vector::CipherVector {
            ciphervector: cv,
            dim: v.len(),
            evaluation_key: self.evaluation.clone(),
        }
    }

    pub fn encrypt_matrix(&self, matrix: &Vec<Vec<f64>>, min: f64, max:f64,nb_bit_precision:usize, nb_bit_padding:usize) -> zqz::matrix::CipherMatrix {

        //TODO check length of matrix

        let n: usize = matrix.len();
        let m: usize = matrix[0].len();

        let mut cm :Vec<Vec<zqz::cipherfloat::Cipherfloat>> = Vec::new();
        for i in 0..n{
            let mut cmr :Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();
            for j in 0..m{
                let c : zqz::cipherfloat::Cipherfloat  = self.encrypt_float(matrix[i][j],min,max,nb_bit_precision,nb_bit_padding);
                cmr.push(c);
            }
            cm.push(cmr);
        }
        zqz::matrix::CipherMatrix {
            ciphermatrix: cm,
            dim_n: n,
            dim_m: m,
            evaluation_key: self.evaluation.clone(),
        }
    }

    pub fn decrypt_vector(&self, cv: &zqz::vector::CipherVector) -> Vec<f64> {
        
        let mut v :Vec<f64> = Vec::new();
        
        for i in 0..cv.dim{
            let dec: f64 = cv.ciphervector[i].cipherfloat.decrypt_decode(&self.secret).unwrap();
            v.push(dec);
        }
        return v;
    }

    #[allow(dead_code)]
    pub fn decrypt_matrix(&self, cm: &zqz::matrix::CipherMatrix) -> Vec<Vec<f64>> {
        
        let mut m :Vec<Vec<f64>> = Vec::new();
        
        for i in 0..cm.dim_n{
            let mut row :Vec<f64> = Vec::new();
            for j in 0..cm.dim_m{
                let dec: f64 = cm.ciphermatrix[i][j].cipherfloat.decrypt_decode(&self.secret).unwrap();
                row.push(dec);
            }
            m.push(row);
        }
        return m;
    }
    #[allow(dead_code)]
    /// We decrypt the cipherfloat
    pub fn decrypt_float(&self, ct: &zqz::cipherfloat::Cipherfloat) -> f64 {
        let dec: f64 = ct.cipherfloat.decrypt_decode(&self.secret).unwrap();
        return dec;
    }
}
