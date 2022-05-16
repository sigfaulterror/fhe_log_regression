use crate::reg;

use reg::utils::{load_vector, parse_data_file};

pub fn calculate_accuracy(prediction_file: &str, data_file: &str) -> (f64, f64) {
    let predictions: Vec<f64> = load_vector(prediction_file);
    let (_, y) = parse_data_file(&data_file);
    if y.len() != predictions.len() {
        //TODO throw Error
        println!("The size of the files don't match!");
        return (-1.,-1.);
    }
    let mut correct_answers = 0.;
    let mut total_answers = 0.;

    for i in 0..y.len() {
        if y[i] == predictions[i] {
            correct_answers += 1.;
        }
        total_answers += 1.;
    }
    (correct_answers / total_answers, total_answers )
}
