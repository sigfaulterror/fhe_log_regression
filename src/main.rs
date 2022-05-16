#[allow(unused)]
use concrete::crypto_api::{
    CryptoAPIError, LWEParams, LWE128_1024, LWE128_750, LWE80_1024, RLWE128_1024_1, RLWE128_2048_1,
    RLWE128_4096_1,
};
#[macro_use]
mod zqz;
mod clear;
mod reg;

use clap::{ArgEnum, Parser};
use reg::accuracy::calculate_accuracy;
use reg::classifier::{classify_data_fhe, classify_data_plain};
use reg::trainer::{train_data_fhe, train_data_plain};

// We determine the cryptographic parameters depending on the compilation flag used.
const PARAMS: zqz::Parameters =
    /*
     */
    new_parameters!(
        6,              // $nb_bit_precision,
        2,              // $nb_bit_padding,
        7,              // $bs_base_log,
        3,              // $bs_level,
        2,              // $ks_base_log,
        7,              // $ks_level,
        RLWE128_4096_1, // $rlwe_setting:expr,
        LWE128_1024,    // $lwe_setting,
        true            // $with_ks
    );

fn main() -> Result<(), CryptoAPIError> {
    let args = Args::parse();
    let data_file = args.data;
    let model_file = args.model;
    let prediction_file = args.prediction;
    let enable_encryption = args.enable_encryption;
    let operation = args.command;
    match &operation {
        &Commands::Train if enable_encryption => {
            if data_file.is_none() {
                println!("Please fill the data_file option using -d");
                std::process::exit(1);
            }
            if model_file.is_none() {
                println!("Please fill the model_file option using -m");
                std::process::exit(1);
            }
            train_data_fhe(&data_file.unwrap(), &model_file.unwrap());
            println!("Trained successfully!");
            println!("generated model file!");
        }
        &Commands::Train if !enable_encryption => {
            if data_file.is_none() {
                println!("Please fill the data_file option using -d");
                std::process::exit(1);
            }
            if model_file.is_none() {
                println!("Please fill the model_file option using -m");
                std::process::exit(1);
            }
            train_data_plain(&data_file.unwrap(), &model_file.unwrap());
            println!("Trained successfully!");
            println!("generated model file!");
        }
        &Commands::Classify if enable_encryption => {
            if data_file.is_none() {
                println!("Please fill the data_file option using -d");
                std::process::exit(1);
            }
            if model_file.is_none() {
                println!("Please fill the model_file option using -m");
                std::process::exit(1);
            }
            if prediction_file.is_none() {
                println!("Please fill the prediction_file option using -p");
                std::process::exit(1);
            }
            classify_data_fhe(
                &data_file.unwrap(),
                &model_file.unwrap(),
                &prediction_file.unwrap(),
            );
            println!("Classified successfully!");
            println!("generated prediction file!");
        }
        &Commands::Classify if !enable_encryption => {
            if data_file.is_none() {
                println!("Please fill the data_file option using -d");
                std::process::exit(1);
            }
            if model_file.is_none() {
                println!("Please fill the model_file option using -m");
                std::process::exit(1);
            }
            if prediction_file.is_none() {
                println!("Please fill the prediction_file option using -p");
                std::process::exit(1);
            }
            classify_data_plain(
                &data_file.unwrap(),
                &model_file.unwrap(),
                &prediction_file.unwrap(),
            );
            println!("Classified successfully!");
            println!("generated prediction file!");
        }
        &Commands::Accuracy => {
            if data_file.is_none() {
                println!("Please fill the data_file option using -d");
                std::process::exit(1);
            }
            if prediction_file.is_none() {
                println!("Please fill the prediction_file option using -p");
                std::process::exit(1);
            }
            let (accuracy, total_records) =
                calculate_accuracy(&prediction_file.unwrap(), &data_file.unwrap());
            if accuracy < 0. {
                println!("Error happened!");
                std::process::exit(1);
            }
            println!(
                "Accuracy: {}%, over {} records",
                accuracy * 100.,
                total_records
            );
        }
        &_ => {}
    }
    Ok(())
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]

struct Args {
    #[clap(arg_enum)]
    command: Commands,
    /// training data file
    #[clap(short, long)]
    data: Option<String>,
    /// training model file
    #[clap(short, long)]
    model: Option<String>,
    /// predictions file
    #[clap(short, long)]
    prediction: Option<String>,

    /// enable, disable fhe, disabled by default
    #[clap(short, long)]
    enable_encryption: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum, Debug)]
enum Commands {
    /// Adds files to myapp
    Train,
    Classify,
    Accuracy,
}
