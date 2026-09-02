use totp_rs::{Algorithm, Secret, TOTP};
fn main() {
    let secret = Secret::generate_secret();
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        Some("Github".to_string()),
        "constantoine@github.com".to_string(),
    )
    .unwrap();
    let base32_secret = secret.to_encoded().to_string();
    println!("{}", base32_secret);
    println!();
    let uri = totp.get_url();
    println!("{}", uri);
    println!();
    if let Ok(qr_code) = totp.get_qr_base64() {
        println!("{}", qr_code);
    } else {
        println!("BAD");
    }
}
