//! A module containing a ciphertext structure.
use crate::zqz;
use std::ops::{Add, AddAssign, Mul, Sub, SubAssign};
use std::rc::Rc;
use zqz::keys::HomomorphicKey;

/// An encrypted message.
#[derive(Debug, Clone, PartialEq)]
pub struct CipherVector {
    pub ciphervector: Vec<zqz::cipherfloat::Cipherfloat>,
    pub dim: usize,
    pub evaluation_key: Rc<HomomorphicKey>,
}
impl CipherVector {
    #[allow(dead_code)]
    pub fn get(&self, i: usize) -> zqz::cipherfloat::Cipherfloat {
        return self.ciphervector[i].clone();
    }
}

// Adds two ciphervector using the `+` operator.
impl Add<&CipherVector> for &CipherVector {
    type Output = CipherVector;

    fn add(self, other: &CipherVector) -> Self::Output {
        // addition
        let mut result: Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();
        for i in 0..self.dim {
            let other: &zqz::cipherfloat::Cipherfloat = &other.ciphervector[i];
            let sum = &self.ciphervector[i] + other;
            result.push(sum);
        }

        CipherVector {
            ciphervector: result,
            dim: self.dim,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}
// Add cipherfloat to all values in the ciphervector using the `+` operator.
impl Add<&zqz::cipherfloat::Cipherfloat> for &CipherVector {
    type Output = CipherVector;

    fn add(self, other: &zqz::cipherfloat::Cipherfloat) -> Self::Output {
        // addition
        let mut result: Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();
        for i in 0..self.dim {
            let sum = &self.ciphervector[i] + other;
            result.push(sum);
        }

        CipherVector {
            ciphervector: result,
            dim: self.dim,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Add f64 to all values in the ciphervector using the `+` operator.
impl Add<f64> for &CipherVector {
    type Output = CipherVector;

    fn add(self, other: f64) -> Self::Output {
        // addition
        let mut result: Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();
        for i in 0..self.dim {
            let sum = &self.ciphervector[i] + other;
            result.push(sum);
        }

        CipherVector {
            ciphervector: result,
            dim: self.dim,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}
// Adds two ciphervectors value by value using the `+=` operator.
impl AddAssign<&CipherVector> for CipherVector {
    fn add_assign(&mut self, other: &CipherVector) {
        let res = &*self + other;
        self.ciphervector = res.ciphervector;
    }
}

// Adds a float to a ciphertext using the `+=` operator.
impl AddAssign<f64> for CipherVector {
    fn add_assign(&mut self, other: f64) {
        let res = &*self + other;
        self.ciphervector = res.ciphervector;
    }
}
// Adds a cipherfloat to all values of ciphervector using the `+=` operator.
impl AddAssign<&zqz::cipherfloat::Cipherfloat> for CipherVector {
    fn add_assign(&mut self, other: &zqz::cipherfloat::Cipherfloat) {
        let res = &*self + other;
        self.ciphervector = res.ciphervector;
    }
}

// Multiply this vector by the transpose of other vector to return a cipherfloat using `*` operator.
impl Mul<&CipherVector> for &CipherVector {
    type Output = zqz::cipherfloat::Cipherfloat;

    fn mul(self, other: &CipherVector) -> Self::Output {
        // addition
        let mut result: zqz::cipherfloat::Cipherfloat =
            &other.ciphervector[0] * &self.ciphervector[0];
        for i in 1..self.dim {
            let other: &zqz::cipherfloat::Cipherfloat = &other.ciphervector[i];
            let product = &self.ciphervector[i] * other;
            result += &product;
        }
        return result;
    }
}
// Muliply a cipherfloat with all values of the ciphervector using `*` operator.
impl Mul<&zqz::cipherfloat::Cipherfloat> for &CipherVector {
    type Output = CipherVector;
    fn mul(self, other: &zqz::cipherfloat::Cipherfloat) -> Self::Output {
        // multiplication
        let mut result: Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();
        for i in 0..self.dim {
            let product = &self.ciphervector[i] * other;
            result.push(product);
        }

        CipherVector {
            ciphervector: result,
            dim: self.dim,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Multiply float to all values of ciphervector using `*` operator.
impl Mul<f64> for &CipherVector {
    type Output = CipherVector;

    fn mul(self, other: f64) -> Self::Output {
        // multiplication
        let mut result: Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();
        for i in 0..self.dim {
            let product = &self.ciphervector[i] * other;
            result.push(product);
        }

        CipherVector {
            ciphervector: result,
            dim: self.dim,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}
// Substract two ciphervectors using the `-` operator.
impl Sub<&CipherVector> for &CipherVector {
    type Output = CipherVector;

    fn sub(self, other: &CipherVector) -> Self::Output {
        // substraction
        let mut result: Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();
        for i in 0..self.dim {
            let other: &zqz::cipherfloat::Cipherfloat = &other.ciphervector[i];
            let sub = &self.ciphervector[i] - other;
            result.push(sub);
        }

        CipherVector {
            ciphervector: result,
            dim: self.dim,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}
// Substract cipherfloat from all values of ciphervector using the `-` operator.
impl Sub<&zqz::cipherfloat::Cipherfloat> for &CipherVector {
    type Output = CipherVector;

    fn sub(self, other: &zqz::cipherfloat::Cipherfloat) -> Self::Output {
        // addition
        let mut result: Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();
        for i in 0..self.dim {
            let sub = &self.ciphervector[i] - other;
            result.push(sub);
        }

        CipherVector {
            ciphervector: result,
            dim: self.dim,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}
// Substract float from all values of ciphervector using the `-` operator.
impl Sub<f64> for &CipherVector {
    type Output = CipherVector;

    fn sub(self, other: f64) -> Self::Output {
        // addition
        let mut result: Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();
        for i in 0..self.dim {
            let sub = &self.ciphervector[i] - other;
            result.push(sub);
        }

        CipherVector {
            ciphervector: result,
            dim: self.dim,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Substract two ciphervectors using the `-=` operator.
impl SubAssign<&CipherVector> for CipherVector {
    fn sub_assign(&mut self, other: &CipherVector) {
        let res = &*self - other;
        self.ciphervector = res.ciphervector;
    }
}

// Substract float from all values of ciphervector using the `-=` operator.
impl SubAssign<f64> for CipherVector {
    fn sub_assign(&mut self, other: f64) {
        let res = &*self - other;
        self.ciphervector = res.ciphervector;
    }
}
// Substract cipherfloat from all values of ciphervector using the `-=` operator.
impl SubAssign<&zqz::cipherfloat::Cipherfloat> for CipherVector {
    fn sub_assign(&mut self, other: &zqz::cipherfloat::Cipherfloat) {
        let res = &*self - other;
        self.ciphervector = res.ciphervector;
    }
}
