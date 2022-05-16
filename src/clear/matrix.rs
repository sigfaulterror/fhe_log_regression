//! A module containing a plaintext structure.
use crate::clear;
use std::ops::{Add, AddAssign, Mul, Sub, SubAssign};

/// An encrypted message.
#[derive(Debug, Clone, PartialEq)]
pub struct PlainMatrix {
    pub plainmatrix: Vec<Vec<f64>>,
    pub dim_n: usize,
    pub dim_m: usize,
}
impl PlainMatrix {
    #[allow(dead_code)]
    pub fn get_row(&self, i: usize) -> clear::vector::PlainVector {
        clear::vector::PlainVector {
            plainvector: self.plainmatrix[i].clone(),
            dim: self.dim_m,
        }
    }
    pub fn new(v_matrix: Vec<Vec<f64>>) -> PlainMatrix {
        let n = v_matrix.len();
        let m = v_matrix[0].len();
        PlainMatrix {
            plainmatrix: v_matrix,
            dim_n: n,
            dim_m: m,
        }
    }
}

// Adds two plainmatrix using the `+` operator.
impl Add<&PlainMatrix> for &PlainMatrix {
    type Output = PlainMatrix;

    fn add(self, other: &PlainMatrix) -> Self::Output {
        // addition
        let mut result: Vec<Vec<f64>> = Vec::new();
        for i in 0..self.dim_n {
            let mut result_row: Vec<f64> = Vec::new();
            for j in 0..self.dim_m {
                let other: &f64 = &other.plainmatrix[i][j];
                let sum = self.plainmatrix[i][j] + other;
                result_row.push(sum);
            }
            result.push(result_row);
        }

        PlainMatrix {
            plainmatrix: result,
            dim_n: self.dim_n,
            dim_m: self.dim_m,
        }
    }
}
// Adds two plainmatrix using the `+=` operator.
impl AddAssign<&PlainMatrix> for PlainMatrix {
    fn add_assign(&mut self, other: &PlainMatrix) {
        let res = &*self + other;
        self.plainmatrix = res.plainmatrix;
    }
}

// Sub two plainmatrix using the `-` operator.
impl Sub<&PlainMatrix> for &PlainMatrix {
    type Output = PlainMatrix;

    fn sub(self, other: &PlainMatrix) -> Self::Output {
        // addition
        let mut result: Vec<Vec<f64>> = Vec::new();
        for i in 0..self.dim_n {
            let mut result_row: Vec<f64> = Vec::new();
            for j in 0..self.dim_m {
                let other: &f64 = &other.plainmatrix[i][j];
                let sum = &self.plainmatrix[i][j] - other;
                result_row.push(sum);
            }
            result.push(result_row);
        }

        PlainMatrix {
            plainmatrix: result,
            dim_n: self.dim_n,
            dim_m: self.dim_m,
        }
    }
}
// Sub two ciphertexts using the `-=` operator.
impl SubAssign<&PlainMatrix> for PlainMatrix {
    fn sub_assign(&mut self, other: &PlainMatrix) {
        let res = &*self - other;
        self.plainmatrix = res.plainmatrix;
    }
}

// Multiplies plainmatrix with ciphervector using the `*` operator.
impl Mul<&clear::vector::PlainVector> for &PlainMatrix {
    type Output = clear::vector::PlainVector;

    fn mul(self, other: &clear::vector::PlainVector) -> Self::Output {
        let mut result: Vec<f64> = Vec::new();
        if other.dim != self.dim_m {
            println!(
                "The dimensions of matrix and vector don't match Matrix[{}x{}] Vector[{}]",
                self.dim_n, self.dim_m, other.dim
            );
        }
        for i in 0..self.dim_n {
            let row: &Vec<f64> = &self.plainmatrix[i];
            let mut v: f64 = row[0] * other.plainvector[0];
            for j in 1..self.dim_m {
                let m: f64 = row[j] * other.plainvector[j];
                v = m + v;
            }
            result.push(v);
        }
        clear::vector::PlainVector {
            plainvector: result,
            dim: other.dim,
        }
    }
}
