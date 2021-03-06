# Dependencies

If the build does not succeed by default you need to install these dependencies:
https://docs.rs/openssl/latest/openssl/
```sh
apt-get install pkg-config libssl-dev
```
# Install Concrete dependency

https://docs.zama.ai/concrete/lib/user/installation.html
# FHE Logistical Regression

This project is an attempt to implement logistical regression using zama library for FHE encryption
# Build the project

```sh
make build
```


# Train
Training using logistical regression and saving the model in `model` file
```sh
./bin/fhe_log_regression train -d datasets/bio.train -m model
```

# Classification in plaintext
Generate the classification and saving it into prediction file
```sh
./bin/fhe_log_regression classify -d datasets/bio.dev -m model -p prediction
```
# Classification in FHE
Generate the classification and saving it into prediction file, it can take up to 5 min to classify one record with 284 as its dimension , it is better to use small data file
```sh
head -1 datasets/bio.dev >datasets/bio-small.dev
./bin/fhe_log_regression classify -d datasets/bio-small.dev -m model -p prediction_fhe -e
```
# Find Classification accuracy
```sh
./bin/fhe_log_regression accuracy -d datasets/bio-small.dev -p prediction_fhe
```
