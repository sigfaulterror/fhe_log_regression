//! A module containing a ciphertext structure.
use std::ops::{Add, AddAssign, Mul, Sub, SubAssign};
/// An encrypted message.
#[derive(Debug, Clone, PartialEq)]
pub struct PlainVector {
    pub plainvector: Vec<f64>,
    pub dim: usize,
}
impl PlainVector {
    #[allow(dead_code)]
    pub fn get(&self, i: usize) -> f64 {
        return self.plainvector[i].clone();
    }
    pub fn new(v:Vec<f64> ) -> PlainVector {
        PlainVector{
            dim:v.len(),
            plainvector: v
        }
    }
}

// Adds two plainvector using the `+` operator.
impl Add<&PlainVector> for &PlainVector {
    type Output = PlainVector;

    fn add(self, other: &PlainVector) -> Self::Output {
        // addition
        let mut result: Vec<f64> = Vec::new();
        for i in 0..self.dim {
            let other: f64 = other.plainvector[i];
            let sum = self.plainvector[i] + other;
            result.push(sum);
        }

        PlainVector {
            plainvector: result,
            dim: self.dim,
        }
    }
}
// Add float to all values in the plainvector using the `+` operator.
impl Add<&f64> for &PlainVector {
    type Output = PlainVector;

    fn add(self, other: &f64) -> Self::Output {
        // addition
        let mut result: Vec<f64> = Vec::new();
        for i in 0..self.dim {
            let sum = &self.plainvector[i] + other;
            result.push(sum);
        }

        PlainVector {
            plainvector: result,
            dim: self.dim,
        }
    }
}

// Add f64 to all values in the plainvector using the `+` operator.
impl Add<f64> for &PlainVector {
    type Output = PlainVector;

    fn add(self, other: f64) -> Self::Output {
        // addition
        let mut result: Vec<f64> = Vec::new();
        for i in 0..self.dim {
            let sum = &self.plainvector[i] + other;
            result.push(sum);
        }

        PlainVector {
            plainvector: result,
            dim: self.dim,
        }
    }
}
// Adds two plainvectors value by value using the `+=` operator.
impl AddAssign<&PlainVector> for PlainVector {
    fn add_assign(&mut self, other: &PlainVector) {
        let res = &*self + other;
        self.plainvector = res.plainvector;
    }
}

// Adds a float to a ciphertext using the `+=` operator.
impl AddAssign<f64> for PlainVector {
    fn add_assign(&mut self, other: f64) {
        let res = &*self + other;
        self.plainvector = res.plainvector;
    }
}
// Adds a float to all values of plainvector using the `+=` operator.
impl AddAssign<&f64> for PlainVector {
    fn add_assign(&mut self, other: &f64) {
        let res = &*self + other;
        self.plainvector = res.plainvector;
    }
}

// Multiply this vector by the transpose of other vector to return a float using `*` operator.
impl Mul<&PlainVector> for &PlainVector {
    type Output = f64;

    fn mul(self, other: &PlainVector) -> Self::Output {
        // addition
        let mut result: f64 = 0.;
        for i in 0..self.dim {
            let other: f64 = other.plainvector[i];
            let product = self.plainvector[i] * other;
            result += &product;
        }
        return result;
    }
}

// Multiply float to all values of plainvector using `*` operator.
impl Mul<f64> for &PlainVector {
    type Output = PlainVector;

    fn mul(self, other: f64) -> Self::Output {
        // multiplication
        let mut result: Vec<f64> = Vec::new();
        for i in 0..self.dim {
            let product = &self.plainvector[i] * other;
            result.push(product);
        }

        PlainVector {
            plainvector: result,
            dim: self.dim,
        }
    }
}
// Substract two plainvectors using the `-` operator.
impl Sub<&PlainVector> for &PlainVector {
    type Output = PlainVector;

    fn sub(self, other: &PlainVector) -> Self::Output {
        // substraction
        let mut result: Vec<f64> = Vec::new();
        for i in 0..self.dim {
            let other: &f64 = &other.plainvector[i];
            let sub = &self.plainvector[i] - other;
            result.push(sub);
        }

        PlainVector {
            plainvector: result,
            dim: self.dim,
        }
    }
}

// Substract float from all values of plainvector using the `-` operator.
impl Sub<f64> for &PlainVector {
    type Output = PlainVector;

    fn sub(self, other: f64) -> Self::Output {
        // addition
        let mut result: Vec<f64> = Vec::new();
        for i in 0..self.dim {
            let sub = &self.plainvector[i] - other;
            result.push(sub);
        }

        PlainVector {
            plainvector: result,
            dim: self.dim,
        }
    }
}

// Substract two plainvectors using the `-=` operator.
impl SubAssign<&PlainVector> for PlainVector {
    fn sub_assign(&mut self, other: &PlainVector) {
        let res = &*self - other;
        self.plainvector = res.plainvector;
    }
}

// Substract float from all values of plainvector using the `-=` operator.
impl SubAssign<f64> for PlainVector {
    fn sub_assign(&mut self, other: f64) {
        let res = &*self - other;
        self.plainvector = res.plainvector;
    }
}