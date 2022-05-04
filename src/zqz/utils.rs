//! A module containing utilities functions and macros.
// use crate::PARAMS;


// This macro allows to compute the duration of the execution of the expressions enclosed. Note that
// the variables are not captured.
#[macro_export]
macro_rules! measure_duration{
    ($title: tt, [$($block:tt)+]) => {
        println!("{}", $title);
        let __now = std::time::SystemTime::now();
        $(
           $block
        )+
        let __time = __now.elapsed().unwrap().as_millis() as f64 / 1000.;
        let __s_time = format!("{} s", __time);
        println!("Duration: {}", __s_time.green().bold());
    }
}
