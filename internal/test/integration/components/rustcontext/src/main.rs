// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};

fn outgoing_request(client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
    let mut request = client.get(url);
    if let Ok(padding) = std::env::var("OBI_RUST_HEADER_PADDING") {
        request = request.header("x-obi-padding", "x".repeat(padding.parse().unwrap()));
    }
    if std::env::var_os("OBI_RUST_APP_HEADER").is_some() {
        let number = url.rsplit('/').next().unwrap().parse::<u64>().unwrap() + 1;
        request.header(
            "traceparent",
            format!("00-{number:032x}-1111111111111111-01"),
        )
    } else {
        request
    }
}

async fn fetch(client: reqwest::Client, url: String) {
    #[cfg(not(feature = "reqwest_010"))]
    outgoing_request(&client, &url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();

    #[cfg(feature = "reqwest_010")]
    let task = {
        static RUNTIME: std::sync::OnceLock<std::sync::Mutex<tokio02::runtime::Runtime>> =
            std::sync::OnceLock::new();
        let runtime = RUNTIME
            .get_or_init(|| std::sync::Mutex::new(tokio02::runtime::Runtime::new().unwrap()))
            .lock()
            .unwrap();
        runtime.spawn(async move {
            outgoing_request(&client, &url)
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
        })
    };
    #[cfg(feature = "reqwest_010")]
    task.await.unwrap();
}

async fn serve() {
    let listen = std::env::var("OBI_RUST_LISTEN").unwrap_or_else(|_| "127.0.0.1:18090".to_owned());
    let listener = TcpListener::bind(listen).await.unwrap();
    let downstream = Arc::new(std::env::args().nth(1).expect("downstream URL"));
    let builder = reqwest::Client::builder();
    let client = builder.build().unwrap();
    println!("READY {}", listener.local_addr().unwrap());
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let client = client.clone();
        let downstream = downstream.clone();
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let len = stream.read(&mut chunk).await.unwrap();
                if len == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..len]);
            }
            let request = String::from_utf8(request).unwrap();
            let path = request.split_whitespace().nth(1).unwrap().to_owned();
            let child = tokio::spawn(async move {
                tokio::task::yield_now().await;
                sleep(Duration::from_millis(5)).await;
                let nested = tokio::spawn(async move {
                    fetch(client, format!("{downstream}{path}")).await;
                });
                nested.await.unwrap();
            });
            child.await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
    }
}

fn main() {
    let runtime = if std::env::var_os("OBI_RUST_CURRENT_THREAD").is_some() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
    };
    runtime.block_on(serve());
}
