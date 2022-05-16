use crate::clear;
use crate::reg;
use crate::zqz;

use clear::matrix::PlainMatrix;
use clear::vector::PlainVector;

use reg::utils::{load_encoded_vector, parse_data_file, save_vector};

use crate::measure_duration;
use crate::PARAMS;

use zqz::keys::EncryptKey;
use zqz::matrix::CipherMatrix;
use zqz::vector::CipherVector;

pub fn classify_data_plain(data_file: &str, model_file: &str, prediction_file: &str) -> Vec<f64> {
    let (mut x, _) = parse_data_file(&data_file);
    let beta = load_encoded_vector(model_file);
    let mut predictions: Vec<f64> = Vec::new();
    //Extending the columns of the matrix to be the size of beta
    for i in 0..x.len() {
        if x[i].len() < beta.len() {
            for _ in x[i].len()..beta.len() {
                x[i].push(0.);
            }
        }
    }
    let p_x = PlainMatrix::new(x);
    let p_beta = PlainVector::new(beta);

    for i in 0 as usize..p_x.dim_n {
        let (class, _) = sigmoid_classification(&p_beta, &p_x.get_row(i));
        predictions.push(class as f64);
    }
    save_vector(&predictions, prediction_file);
    predictions
}

pub fn classify_data_fhe(data_file: &str, model_file: &str, prediction_file: &str) -> Vec<f64> {
    let (x, _) = parse_data_file(&data_file);
    let mut predictions: Vec<f64> = Vec::new();
    let beta = load_encoded_vector(model_file);
    let mut encoding_limit = 0.;
    
    for b in &beta {
        encoding_limit += b;
    }
    encoding_limit = encoding_limit.floor().abs();

    measure_duration!("1. Key Loading...",[
        let sk = if !EncryptKey::keys_exist(&PARAMS.gen_prefix()) {
            let key = EncryptKey::new();
            key.save_to_files(&PARAMS.gen_prefix());
            key
        } else {
            EncryptKey::load_from_files(&PARAMS.gen_prefix())
        };
    ]);
    measure_duration!("2. Encryption... ",[
        let e_x : CipherMatrix          = sk.encrypt_matrix(&x,-encoding_limit ,encoding_limit);
        let e_beta : CipherVector       = sk.encrypt_vector(&beta,-encoding_limit,encoding_limit);
    ]);
    measure_duration!(
        "3. Classification... ",
        [for i in 0..e_x.dim_n {
            let xbeta = &e_x.get_row(i) * &e_beta;
            let e_class = xbeta.bs_ks(|x| sigmoid(x));
            let mut p_class = sk.decrypt_float(&e_class);
            p_class = if p_class > 0. { 1. } else { -1. };
            predictions.push(p_class);
        }]
    );
    save_vector(&predictions, prediction_file);
    predictions
}

//Sigmoid function with poly approximation
fn sigmoid_classification(
    beta: &clear::vector::PlainVector,
    x: &clear::vector::PlainVector,
) -> (i32, f64) {
    let y = 1.;
    let threashold = 0.5;
    let percent_y_1 = 1. / 2. + 1. / 4. * y * (beta * x);
    let percent_y_neg_1 = 1. / 2. - 1. / 4. * y * (beta * x);
    if percent_y_1 > threashold {
        (1, percent_y_1)
    } else {
        (-1, percent_y_neg_1)
    }
}

//Sigmoid function to pass to fhe as a bootstrap function
fn sigmoid(x: f64) -> f64 {
    let y = 1.;
    let threashold = 0.5;
    let percent_y_1 = 1. / 2. + 1. / 4. * y * x;
    if percent_y_1 > threashold {
        1.
    } else {
        -1.
    }
}
