//! A module containing a ciphertext structure.
use crate::zqz;
use std::ops::{Add, AddAssign, Mul, Sub, SubAssign};
use std::rc::Rc;
use zqz::keys::HomomorphicKey;

/// An encrypted message.
#[derive(Debug, Clone, PartialEq)]
pub struct CipherMatrix {
    pub(super) ciphermatrix: Vec<Vec<zqz::cipherfloat::Cipherfloat>>,
    pub(super) dim_n: usize,
    pub(super) dim_m: usize,
    pub(super) evaluation_key: Rc<HomomorphicKey>,
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
                //let self_padding = self.ciphermatrix[i][j].cipherfloat.encoder.nb_bit_padding;
                let other: &zqz::cipherfloat::Cipherfloat = &other.ciphermatrix[i][j];
                //let other_padding = other.cipherfloat.encoder.nb_bit_padding;
                //println!("self_padding: {}", self_padding);
                //println!("other_padding: {}", other_padding);
                let sum = &self.ciphermatrix[i][j] + other;
                //println!("sum_padding: {}", &sum.cipherfloat.encoder.nb_bit_padding);
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
            //println!("v = {} * {}",secret_key.decrypt(&row[0]),secret_key.decrypt(&vector[0]));
            //println!("V[0][0]={}",secret_key.decrypt(&v));
            for j in 0..self.dim_m {
                let m: zqz::cipherfloat::Cipherfloat = &row[j] * &other.ciphervector[j];
                //println!("M[{}][{}]={}",i,j,secret_key.decrypt(&m));
                //println!("m = {} * {}",secret_key.decrypt(&row[j]),secret_key.decrypt(&vector[j]));
                //println!("VB[{}][{}]={}",i,j,secret_key.decrypt(&v));
                v = &m + &v;
                //println!("VA[{}][{}]={}",i,j,secret_key.decrypt(&v));
            }
            //println!("V[{}]={}",i,secret_key.decrypt(&v));
            result.push(v);
        }
        zqz::vector::CipherVector {
            ciphervector: result,
            dim: other.dim,
            evaluation_key: other.evaluation_key.clone(),
        }
    }
}
