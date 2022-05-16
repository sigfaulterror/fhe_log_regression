use crate::clear;
use crate::reg;
use crate::zqz;

use clear::matrix::PlainMatrix;
use clear::vector::PlainVector;

use reg::utils::{parse_data_file, save_encoded_vector, save_vector};

use crate::measure_duration;
use crate::PARAMS;

use zqz::keys::EncryptKey;
use zqz::matrix::CipherMatrix;
use zqz::vector::CipherVector;

pub fn train_data_plain(data_file: &str, model_file: &str) -> Vec<f64> {
    let (x, y) = parse_data_file(&data_file);
    //TODO check if len X == 0 , than throw back error
    let n = x.len();
    let d = x[0].len();

    let beta: Vec<f64> = vec![0.001; d];
    //A BAD APPROXIMATION IN THE HESSIAN INVERSE MATRIX
    //WILL CAUSE US TO HAVE A SLOW PROGRESS TO THE OPTIMUM SOLUTION FOR BETA
    //THIS IS WHY WE CAN TOLERATE TO DO MANY ITERATIONS IN CALCULATING THE INVERSE MATRIX
    //WE WILL GAIN IN CALCULATION OF THE BETA
    let nbr_iters = 20;

    let mut h_tild: Vec<Vec<f64>> = vec![vec![0.0; d]; d];
    let mut h_tild_inv: Vec<Vec<f64>> = vec![vec![0.0; d]; d];
    let mut sum: Vec<f64> = vec![0.0; n];

    //Calculation of the hessian matrix
    for i in 0..n {
        for j in 0..d {
            sum[i] = sum[i] + x[i][j];
        }
    }
    for j in 0..d {
        let mut temp = 0.0;
        for i in 1..n {
            temp = temp + x[i][j] * sum[i];
        }
        h_tild[j][j] = -temp / 4.0;
        h_tild_inv[j][j] = invers_number_using_newton_raphson(h_tild[j][j]);
    }

    //Encoding 1D vectors and 2D vectors into Vector object and Matrix for easy calculations
    let p_x = PlainMatrix::new(x);
    let p_y = PlainVector::new(y);
    let p_h_tild_inv = PlainMatrix::new(h_tild_inv);
    let mut p_beta = PlainVector::new(beta);

    let mut p_deltas_history: Vec<PlainVector> = Vec::new();
    for _ in 1..nbr_iters {
        let g: Vec<f64> = vec![0.0; d];
        let mut p_g = PlainVector::new(g);
        for i in 1..n {
            let a = (0.5 - 0.25 * p_y.get(i) * (&p_x.get_row(i) * &p_beta)) * p_y.get(i);
            p_g = &p_g + &(&p_x.get_row(i) * a);
        }
        let p_delta = &p_h_tild_inv * &p_g;
        p_beta = &p_beta + &(&p_delta * -1.0);
        p_deltas_history.push(p_delta);
    }

    save_encoded_vector(&p_beta.plainvector, model_file);
    save_vector(&p_beta.plainvector,&format!("{}.debug.txt", model_file));
    p_beta.plainvector
}

pub fn train_data_fhe(data_file: &str, model_file: &str) -> Vec<f64> {
    let (x, y) = parse_data_file(&data_file);
    let n = x.len();
    let d = y.len();
    //A BAD APPROIMATION IN THE HESSIAN INVERSE MATRIX
    //WILL CAUSE US TO HAVE A SLOW PROGRESS TO THE OPTIMUM SOLUTION FOR BETA
    //THIS IS WHY WE CAN TOLERATE TO DO MANY ITERATIONS IN CALCULATING THE INVERSE MATRIX
    //WE WILL GAIN IN CALCULATION OF THE BETA
    let nbr_iters = 10;

    let mut h_tild: Vec<Vec<f64>> = vec![vec![0.0; d]; d];
    let mut h_tild_inv: Vec<Vec<f64>> = vec![vec![0.0; d]; d];
    let beta: Vec<f64> = vec![0.001; d];
    let g: Vec<f64> = vec![0.0; d];
    let mut sum: Vec<f64> = vec![0.0; n];
    //Calculating the Hessian matrix
    for i in 0..n {
        for j in 0..d {
            sum[i] = sum[i] + x[i][j];
        }
    }

    for j in 0..d {
        let mut temp = 0.0;
        for i in 1..n {
            temp = temp + x[i][j] * sum[i];
        }
        h_tild[j][j] = -temp / 4.0;
        h_tild_inv[j][j] = invers_number_using_newton_raphson(h_tild[j][j]);
    }

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
        let e_h_tild_inv : CipherMatrix = sk.encrypt_matrix(&h_tild_inv,-60.,60.);
        let e_x : CipherMatrix          = sk.encrypt_matrix(&x,-60.,60.);
        let e_y : CipherVector          = sk.encrypt_vector(&y,-60.,60.);
        let e_g : CipherVector          = sk.encrypt_vector(&g,-60.,60.);
        let mut e_beta : CipherVector   = sk.encrypt_vector(&beta,-60.,60.);
    ]);

    //let mut e_deltas_history: Vec<CipherVector> = Vec::new();
    for _ in 1..nbr_iters {
        let mut g_tmp = e_g.clone();
        for i in 1..n {
            let e_a: zqz::cipherfloat::Cipherfloat =
                &(&(&(&e_y.get(i) * &(&e_x.get_row(i) * &e_beta)) * (-0.25 as f64)) + 0.5)
                    * &e_y.get(i);
            g_tmp = &g_tmp + &(&e_x.get_row(i) * &e_a);
        }
        let e_delta = &e_h_tild_inv * &g_tmp;
        e_beta = &e_beta + &(&e_delta * (-1.0 as f64));
        //e_deltas_history.push(e_delta);
    }

    let d_beta = sk.decrypt_vector(&e_beta);

    save_encoded_vector(&d_beta, model_file);

    d_beta
}

fn invers_number_using_newton_raphson(a: f64) -> f64 {
    // the initial value should be silghtly greater than -1/((d+1)*(n + 1) * max * max)
    // where max is the max value in the X matrix
    // this is due how temp is calculated
    // a is negative so we should chose starting value to be slightly > 1/a
    // otherwise we will not converge into a value, because we are closer to critical point
    // https://blogs.sas.com/content/iml/2015/06/24/sensitivity-newtons-method.html#:~:text=If%20you%20provide%20a%20guess,away%20from%20the%20initial%20guess.

    let mut xk: f64 = if a > 0. { 0.0001 } else { -0.0001 };
    for _ in 0..20 {
        xk = xk * (2.0 - a * xk);
        //println!("xk: {}", xk);
    }
    //println!("inv of : {} is {}", a, xk);
    return xk;
}
