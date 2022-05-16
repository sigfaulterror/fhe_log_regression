build:
	RUSTFLAGS="-C target-cpu=native" cargo build --release && cp target/release/fhe_log_regression bin