//! A module containing a ciphertext structure.
use crate::zqz;
use std::ops::{Add, AddAssign, Mul, Sub, SubAssign};
use std::rc::Rc;
use zqz::keys::HomomorphicKey;

/// An encrypted message.
#[derive(Debug, Clone, PartialEq)]
pub struct CipherMatrix {
    pub ciphermatrix: Vec<Vec<zqz::cipherfloat::Cipherfloat>>,
    pub dim_n: usize,
    pub dim_m: usize,
    pub evaluation_key: Rc<HomomorphicKey>,
}
impl CipherMatrix {
    #[allow(dead_code)]
    pub fn get_row(&self, i: usize) -> zqz::vector::CipherVector {
        zqz::vector::CipherVector {
            ciphervector: self.ciphermatrix[i].clone(),
            dim: self.dim_m,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Adds two ciphermatrix using the `+` operator.
impl Add<&CipherMatrix> for &CipherMatrix {
    type Output = CipherMatrix;

    fn add(self, other: &CipherMatrix) -> Self::Output {
        // addition
        let mut result: Vec<Vec<zqz::cipherfloat::Cipherfloat>> = Vec::new();
        for i in 0..self.dim_n {
            let mut result_row: Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();
            for j in 0..self.dim_m {
                let other: &zqz::cipherfloat::Cipherfloat = &other.ciphermatrix[i][j];
                let sum = &self.ciphermatrix[i][j] + other;
                result_row.push(sum);
            }
            result.push(result_row);
        }

        CipherMatrix {
            ciphermatrix: result,
            dim_n: self.dim_n,
            dim_m: self.dim_m,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}
// Adds two ciphermatrix using the `+=` operator.
impl AddAssign<&CipherMatrix> for CipherMatrix {
    fn add_assign(&mut self, other: &CipherMatrix) {
        let res = &*self + other;
        self.ciphermatrix = res.ciphermatrix;
    }
}

// Sub two ciphermatrix using the `-` operator.
impl Sub<&CipherMatrix> for &CipherMatrix {
    type Output = CipherMatrix;

    fn sub(self, other: &CipherMatrix) -> Self::Output {
        // addition
        let mut result: Vec<Vec<zqz::cipherfloat::Cipherfloat>> = Vec::new();
        for i in 0..self.dim_n {
            let mut result_row: Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();
            for j in 0..self.dim_m {
                let other: &zqz::cipherfloat::Cipherfloat = &other.ciphermatrix[i][j];
                let sum = &self.ciphermatrix[i][j] - other;
                result_row.push(sum);
            }
            result.push(result_row);
        }

        CipherMatrix {
            ciphermatrix: result,
            dim_n: self.dim_n,
            dim_m: self.dim_m,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}
// Sub two ciphertexts using the `-=` operator.
impl SubAssign<&CipherMatrix> for CipherMatrix {
    fn sub_assign(&mut self, other: &CipherMatrix) {
        let res = &*self - other;
        self.ciphermatrix = res.ciphermatrix;
    }
}

// Multiplies ciphermatrix with ciphervector using the `*` operator.
impl Mul<&zqz::vector::CipherVector> for &CipherMatrix {
    type Output = zqz::vector::CipherVector;

    fn mul(self, other: &zqz::vector::CipherVector) -> Self::Output {
        let mut result: Vec<zqz::cipherfloat::Cipherfloat> = Vec::new();

        for i in 0..self.dim_n {
            let row: &Vec<zqz::cipherfloat::Cipherfloat> = &self.ciphermatrix[i];
            let mut v: zqz::cipherfloat::Cipherfloat = &row[0] * &other.ciphervector[0];
            for j in 1..self.dim_m {
                let m: zqz::cipherfloat::Cipherfloat = &row[j] * &other.ciphervector[j];
                v = &m + &v;
            }
            result.push(v);
        }
        zqz::vector::CipherVector {
            ciphervector: result,
            dim: other.dim,
            evaluation_key: other.evaluation_key.clone(),
        }
    }
}
