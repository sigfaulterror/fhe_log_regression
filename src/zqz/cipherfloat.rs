//! A module containing a cipherfloat structure.
use crate::zqz;
use crate::PARAMS;
use concrete::crypto_api;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use std::rc::Rc;
use zqz::keys::HomomorphicKey;

/// An encrypted message.
#[derive(Debug, Clone, PartialEq)]
pub struct Cipherfloat {
    pub(super) cipherfloat: crypto_api::LWE,
    pub(super) evaluation_key: Rc<HomomorphicKey>,
}

fn bs_ks<F: Fn(f64) -> f64>(
    cipherfloat: &crypto_api::LWE,
    bootstrapping_key: &crypto_api::LWEBSK,
    func: F,
    encoder: &crypto_api::Encoder,
    keyswitching_key: &crypto_api::LWEKSK,
) -> crypto_api::LWE {
    let res = cipherfloat
        .bootstrap_with_function(bootstrapping_key, func, encoder)
        .unwrap();

    if PARAMS.with_ks {
        let res_ks = res.keyswitch(keyswitching_key).unwrap();
        return res_ks;
    } else {
        return res;
    }
}

// Adds two cipherfloats using the `+` operator.
impl Add<&Cipherfloat> for &Cipherfloat {
    type Output = Cipherfloat;

    fn add(self, other: &Cipherfloat) -> Self::Output {
        // addition
        let sum = self
            .cipherfloat
            .add_with_padding_exact(&other.cipherfloat)
            .unwrap();

        Cipherfloat {
            cipherfloat: sum,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Adds an integer to a cipherfloat using the `+` operator.
impl Add<f64> for &Cipherfloat {
    type Output = Cipherfloat;

    fn add(self, other: f64) -> Self::Output {
        let res: crypto_api::LWE = self
            .cipherfloat
            .add_constant_dynamic_encoder(other)
            .unwrap();

        Cipherfloat {
            cipherfloat: res,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Adds two cipherfloats using the `+=` operator.
impl AddAssign<&Cipherfloat> for Cipherfloat {
    fn add_assign(&mut self, other: &Cipherfloat) {
        let res = &*self + other;
        self.cipherfloat = res.cipherfloat;
    }
}

// Adds an integer to a cipherfloat using the `+=` operator.
impl AddAssign<f64> for Cipherfloat {
    fn add_assign(&mut self, other: f64) {
        let res = &*self + other;
        self.cipherfloat = res.cipherfloat;
    }
}

// Substracts two cipherfloats using the `-` operator.
impl Sub<&Cipherfloat> for &Cipherfloat {
    type Output = Cipherfloat;

    fn sub(self, other: &Cipherfloat) -> Self::Output {
        // subtraction
        let sub = self
            .cipherfloat
            .sub_with_padding_exact(&other.cipherfloat)
            .unwrap();

        Cipherfloat {
            cipherfloat: sub,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Substracts an integer to a cipherfloat using the `-` operator.
impl Sub<f64> for &Cipherfloat {
    type Output = Cipherfloat;

    fn sub(self, other: f64) -> Self::Output {
        let res: crypto_api::LWE = self
            .cipherfloat
            .add_constant_dynamic_encoder(-other)
            .unwrap();

        Cipherfloat {
            cipherfloat: res,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Substracts two cipherfloats using the `-=` operator.
impl SubAssign<&Cipherfloat> for Cipherfloat {
    fn sub_assign(&mut self, other: &Cipherfloat) {
        let res = &*self - other;
        self.cipherfloat = res.cipherfloat;
    }
}

// Substracts an integer to a cipherfloat using the `-=` operator.
impl SubAssign<f64> for Cipherfloat {
    fn sub_assign(&mut self, other: f64) {
        let res = &*self - other;
        self.cipherfloat = res.cipherfloat;
    }
}

// Multiplies two cipherfloats using the `*` operator.
impl Mul<&Cipherfloat> for &Cipherfloat {
    type Output = Cipherfloat;

    fn mul(self, other: &Cipherfloat) -> Self::Output {
        // addition
        let posi = self
            .cipherfloat
            .add_with_padding_exact(&other.cipherfloat)
            .unwrap();

        // subtraction
        let nega = self
            .cipherfloat
            .sub_with_padding_exact(&other.cipherfloat)
            .unwrap();

        // modulo
        let mut res_posi = bs_ks(
            &posi,
            &self.evaluation_key.bootstrapping,
            |x| (x * x / 4.),
            &self.cipherfloat.encoder,
            &self.evaluation_key.keyswitching,
        );

        // modulo
        let res_nega = bs_ks(
            &nega,
            &self.evaluation_key.bootstrapping,
            |x| (x * x / 4.),
            &self.cipherfloat.encoder,
            &self.evaluation_key.keyswitching,
        );

        // subtraction
        res_posi.sub_with_padding_exact_inplace(&res_nega).unwrap();


        Cipherfloat {
            cipherfloat: res_posi,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Multiplies an integer with a cipherfloat using the `*` operator.
impl Mul<f64> for &Cipherfloat {
    type Output = Cipherfloat;

    fn mul(self, other: f64) -> Self::Output {
        let res = bs_ks(
            &self.cipherfloat,
            &self.evaluation_key.bootstrapping,
            |x| (x * other),
            &self.cipherfloat.encoder,
            &self.evaluation_key.keyswitching,
        );

        Cipherfloat {
            cipherfloat: res,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Multiplies two cipherfloats using the `*=` operator.
impl MulAssign<&Cipherfloat> for Cipherfloat {
    fn mul_assign(&mut self, other: &Cipherfloat) {
        let res = &*self * other;
        self.cipherfloat = res.cipherfloat;
    }
}

// Multiplies an integer with a cipherfloat using the `*=` operator.
impl MulAssign<f64> for Cipherfloat {
    fn mul_assign(&mut self, other: f64) {
        let res = &*self * other;
        self.cipherfloat = res.cipherfloat;
    }
}