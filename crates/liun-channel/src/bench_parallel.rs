use liuproto_core::pool::Pool;
use liuproto_core::noise;
use liun_channel::exchange::{ExchangeParams, run_as_alice, run_as_bob};
use tokio::net::{TcpListener, TcpStream};
use std::time::Instant;

#[tokio::main]
async fn main() {
    let batch_size = 50_000;
    let params = ExchangeParams::new(batch_size, 0.1, 0.5);

    for n in [1, 5, 10, 20, 50] {
        let mut listeners = Vec::new();
        let mut addrs = Vec::new();
        let mut psks: Vec<Vec<u8>> = Vec::new();
        for _ in 0..n {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            addrs.push(listener.local_addr().unwrap());
            listeners.push(listener);
            psks.push(noise::random_bytes(32 + 50_000 / 8 + 1024)); // header + OTP for batch + margin
        }

        let start = Instant::now();
        let mut bobs = Vec::new();
        for _ in 0..n {
            let psk = psks[bobs.len()].clone();
            let p = params.clone();
            let l = listeners.remove(0);
            bobs.push(tokio::spawn(async move {
                let (mut s, _) = l.accept().await.unwrap();
                s.set_nodelay(true).unwrap();
                let mut pool = Pool::from_psk(&psk, &[0u8; 16]);
                run_as_bob(&mut s, &mut pool, &p).await.unwrap().sign_bits.len()
            }));
        }
        let mut alices = Vec::new();
        for i in 0..n {
            let psk = psks[i].clone();
            let p = params.clone();
            let a = addrs[i];
            alices.push(tokio::spawn(async move {
                let mut s = TcpStream::connect(a).await.unwrap();
                s.set_nodelay(true).unwrap();
                let mut pool = Pool::from_psk(&psk, &[0u8; 16]);
                run_as_alice(&mut s, &mut pool, &p).await.unwrap().sign_bits.len()
            }));
        }
        let mut total = 0usize;
        for h in alices { total += h.await.unwrap(); }
        for h in bobs { h.await.unwrap(); }
        let elapsed = start.elapsed();
        let mbps = total as f64 / elapsed.as_secs_f64() / 1e6;
        println!("{:>3} channels × {batch_size} batch: {:>8} bits in {:>7.1}ms = {:>8.2} Mbps",
            n, total, elapsed.as_millis(), mbps);
    }
}
