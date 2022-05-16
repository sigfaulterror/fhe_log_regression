use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn save_encoded_vector(vector: &Vec<f64>, filename: &str) {
    let encoded: Vec<u8> = bincode::serialize(&vector).unwrap();
    std::fs::write(filename, &encoded);
}

pub fn load_encoded_vector(filename: &str) -> Vec<f64> {
    let data = std::fs::read(filename).unwrap();
    let decoded: Vec<f64> = bincode::deserialize(&data[..]).unwrap();
    return decoded;
}

pub fn save_vector(vector: &Vec<f64>, filename: &str) {
    let mut f = File::create(filename).unwrap();
    for i in vector {
        writeln!(f, "{}", i);
    }
}
pub fn load_vector(filename: &str) -> Vec<f64> {
    let mut result: Vec<f64> = Vec::new();
    let lines: io::Lines<io::BufReader<File>> = read_lines(filename).unwrap();
    for line in lines {
        if let Ok(l) = line {
            result.push(l.parse().unwrap());
        }
    }
    return result;
}

pub fn parse_data_file(data_file: &str) -> (Vec<Vec<f64>>, Vec<f64>) {
    let lines: io::Lines<io::BufReader<File>> = read_lines(Path::new(data_file)).unwrap();
    //Training data
    let mut x: Vec<Vec<f64>> = Vec::new();
    //Predictions vecctor
    let mut y: Vec<f64> = Vec::new();

    let mut max_car: i32 = 0;
    for line in lines {
        // the new row that will be pushed into the matrix
        let mut row: Vec<f64> = Vec::new();
        if let Ok(l) = line {
            let ls: Vec<&str> = l.split(' ').collect();
            let class: f64 = ls[0].parse().unwrap();
            if class == 1. {
                y.push(1.);
            } else {
                y.push(-1.);
            }
            //The last pushed characteristic in the row of the matrix
            let mut index: i32 = 0;
            for i in 1..ls.len() {
                let cell = ls[i];
                let car_value: Vec<&str> = cell.split(':').collect();
                if car_value.len() != 2 {
                    println!("The file is malformated in the region : {}", cell);
                    //TODO
                    //Should be a warning and throw Error
                }
                //Charcteristic's index
                let car: i32 = car_value[0].parse().unwrap();
                //The value linked to that characteristic in general it is a 1, 0s are left blank
                let value: f64 = car_value[1].parse().unwrap();
                //Filling the missed characteristics with 0 so that we construct a valid X matrix
                //of all the characteristics
                for _ in index + 1..car {
                    row.push(0.);
                }
                //the current index filled in the row + 1
                index = car;
                //Pushing the current characteristic into the row with index: index - 1
                row.push(value);
                //Keeping track of the longest row in the matrix so at the end we square it up
                if index > max_car {
                    max_car = index;
                }
            }
            //pushing the new line into the x matrix
            x.push(row);
        }
    }
    //Squaring the matrix
    for i in 0..x.len() {
        for _ in x[i].len()..max_car as usize {
            x[i].push(0.);
        }
    }

    (x, y)
}
