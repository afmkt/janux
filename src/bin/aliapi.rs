#[path = "../aliclient.rs"]
mod aliclient;

#[tokio::main]
async fn main() {
    // 创建 HTTP 客户端
    match aliclient::send_otp(
        "***********",
        "***********",
        "dysmsapi.aliyuncs.com",
        "cn-shanghai",
        "***********",
        "123456",
        "<your-sign-name>",
        "<your-template-code>",
    )
    .await
    {
        Ok(s) => println!("Ok {}", s),
        Err(e) => println!("Err {}", e),
    }
}
