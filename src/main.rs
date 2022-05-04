use colored::Colorize;
#[allow(unused)]
use concrete::crypto_api::{
    CryptoAPIError, LWEParams, LWE128_1024, LWE128_750, LWE80_1024, RLWE128_1024_1, RLWE128_2048_1,
    RLWE128_4096_1,
};
#[macro_use]
mod zqz;
use zqz::keys::EncryptKey;
use zqz::matrix::CipherMatrix;
use zqz::vector::CipherVector;

// We determine the cryptographic parameters depending on the compilation flag used.
const PARAMS: zqz::Parameters =
    /*
    
    */
    new_parameters!(
        5,             // $nb_bit_precision,
        2,             // $nb_bit_padding,
        7,             // $bs_base_log,
        3,             // $bs_level,
        2,             // $ks_base_log,
        7,             // $ks_level,
        RLWE128_2048_1,// $rlwe_setting:expr,
        LWE128_750,    // $lwe_setting,
        true           // $with_ks
    );

fn invers_number_using_newton_raphson(a: f64) -> f64 {
    // the initial value should be silghtly greater than -1/((d+1)*(n + 1) * max * max)
    // where max is the max value in the X matrix
    // this is due how temp is calculated
    // a is negative so we should chose starting value to be slightly > 1/a
    // otherwise we will not converge into a value, because we are closer to critical point
    // https://blogs.sas.com/content/iml/2015/06/24/sensitivity-newtons-method.html#:~:text=If%20you%20provide%20a%20guess,away%20from%20the%20initial%20guess. 

    let mut xk: f64 = -0.001;
    for _ in 0..10 {
        xk = xk * (2.0 - a * xk);
        //println!("xk: {}", xk);
    }
    //println!("inv of : {} is {}", a, xk);
    return xk;
}

fn main() -> Result<(), CryptoAPIError> {
    let n = 5;
    let d = 3;
    //A BAD APPROIMATION IN THE HESSIAN INVERSE MATRIX
    //WILL CAUSE US TO HAVE A SLOW PROGRESS TO THE OPTIMUM SOLUTION FOR BETA
    //THIS IS WHY WE CAN TOLERATE TO DO MANY ITERATIONS IN CALCULATING THE INVERSE MATRIX
    //WE WILL GAIN IN CALCULATION OF THE BETA
    let nbr_iters = 10;
    let x: Vec<Vec<f64>> = vec![
        vec![0.0, 0.0, 4.0, 4.0],
        vec![0.0, 0.0, 4.0, 4.0],
        vec![0.0, 0.0, 4.0, 4.0],
        vec![1.0, 1.0, 0.0, 0.0],
        vec![1.0, 1.0, 0.0, 0.0],
    ];

    let y: Vec<f64> = vec![1.0, 1.0, 1.0, -1.0, -1.0];
    let mut h_tild: Vec<Vec<f64>> = vec![vec![0.0; d + 1]; d + 1];
    let mut h_tild_inv: Vec<Vec<f64>> = vec![vec![0.0; d + 1]; d + 1];
    let mut beta: Vec<f64> = vec![0.001; d + 1];
    let g: Vec<f64> = vec![0.0; d + 1];
    let mut sum: Vec<f64> = vec![0.0; n];
    for i in 0..n {
        for j in 0..d + 1 {
            sum[i] = sum[i] + x[i][j];
        }
    }

    for j in 0..d + 1 {
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
        let e_h_tild_inv : CipherMatrix = sk.encrypt_matrix(&h_tild_inv,-1.,0.,6,2);
        let e_x : CipherMatrix          = sk.encrypt_matrix(&x,0.,10.,6,2);
        let e_y : CipherVector          = sk.encrypt_vector(&y,-1.,1.,6,2);
        let e_g : CipherVector          = sk.encrypt_vector(&g,-2.,2.,6,2);
        let mut e_beta : CipherVector   = sk.encrypt_vector(&beta,-2.,2.,6,2);
    ]);

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
    }
    beta = sk.decrypt_vector(&e_beta);
    println!("beta: {:?}", beta);
    Ok(())
}
