//           ,____           \'/
//       .-'` .   |        -= * =-
//     .'  '    ./           /.\
//    /  '    .'
//   ;  '    /
//  :  '  _ ;
// ;  :  /(\ \
// |  .       '.
// |  ' /     --'
// |  .   '.__\
// ;  :       /
//  ;  .     |            ,
//   ;  .    \           /|
//    \  .    '.       .'/
//     '.  '  . `'---'`.'
//       `'-..._____.-`
//
// Care about the emission. It’s freedom in code.
// Just a pulse in the network, a chance to be heard.
//
#[cfg(not(target_env = "msvc"))]
use jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;
mod api;
mod ascii_art;
mod cpp_bridge;
mod graph_bridge;
mod hasher;
mod models;
mod utils;

use crate::api::MinerState;
use crate::cpp_bridge::CppSearcher;
use ascii_art::*;
use colored::*;
use futures_util::{SinkExt, StreamExt};
use hasher::*;
use models::*;
use rand::Rng;
use std::sync::Arc;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    mpsc,
};
use std::thread;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use utils::*;

#[tokio::main]
async fn main() {
    #[cfg(not(target_env = "msvc"))]
    std::env::set_var("MALLOC_CONF", "thp:always");
    let args = Args::parse_and_validate();
    std::panic::set_hook(Box::new(|_info| {}));

    let max_workers = num_cpus::get();
    assert!(max_workers > 0);

    let num_workers = match args.threads {
        Some(t) => {
            if t >= max_workers {
                println!(
                    "{}",
                    "Requested number of threads exceeds available cores. Using maximum allowed"
                        .bold()
                        .red()
                );
                max_workers
            } else {
                t
            }
        }
        None => max_workers,
    };

    println!("{}", "STARTING MINER".bold().green());
    println!(
        "{} {}",
        "USING WORKERS: ".bold().cyan(),
        format!("{}", num_workers).bold().cyan()
    );
    print_startup_art();

    // Handle Ctrl+C signal
    tokio::spawn(handle_exit_signals());

    let miner_id = args.address.unwrap();

    let (server_sender, server_receiver) = mpsc::channel::<String>();

    let current_job: Arc<Mutex<Option<Job>>> = Arc::new(Mutex::new(None));

    let miner_state = Arc::new(MinerState {
        hash_count: Arc::new(AtomicUsize::new(0)),
        accepted_shares: Arc::new(AtomicUsize::new(0)),
        rejected_shares: Arc::new(AtomicUsize::new(0)),
        hashrate_samples: Arc::new(Mutex::new(Vec::new())),
        version: String::from("2.0.0"),
    });

    let job_version = Arc::new(AtomicU64::new(0));

    // Initialize hugepages if using C++ optimization
    let pool_size_mb = num_workers * 30 + 50;
    let is_hugepage = cpp_bridge::init_hugepages(pool_size_mb);
    if is_hugepage {
        println!("{} {} MB", "HUGEPAGE MEMORY:".bold().green(), pool_size_mb);
    } else {
        println!(
            "{} {} MB (fallback to regular memory)",
            "MEMORY POOL:".bold().yellow(),
            pool_size_mb
        );
    }

    // Spawn worker threads for processing jobs
    let hash_count = Arc::new(AtomicUsize::new(0));
    for _ in 0..num_workers {
        let current_job_loop = Arc::clone(&current_job);
        let job_version_loop = Arc::clone(&job_version);
        let hash_count = Arc::clone(&hash_count);
        let server_sender_clone = server_sender.clone();
        let miner_id = miner_id.clone();
        let api_hash_count = Arc::clone(&miner_state.hash_count);

        thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(move || {
                let cpp_searcher = CppSearcher::new().expect("Failed to initialize C++ searcher");

                loop {
                    let job_option = {
                        let job_guard = current_job_loop.blocking_lock();
                        job_guard.clone()
                    };

                    if let Some(job) = job_option {
                        let expected_version = job_version_loop.load(Ordering::Relaxed);

                        loop {
                            let nonce = generate_nonce();

                            let data_with_nonce = format!("{}{}", job.data, nonce);

                            let result = compute_hash_no_vdf_cpp(
                                &data_with_nonce,
                                &hash_count,
                                &api_hash_count,
                                &job,
                                &nonce,
                                &miner_id,
                                &server_sender_clone,
                                &cpp_searcher,
                                &job_version_loop,
                                expected_version,
                            );

                            match result {
                                Some(true) => {
                                    // Found a valid solution and submitted it; clear the current job.
                                    let mut job_guard = current_job_loop.blocking_lock();
                                    *job_guard = None;
                                    break;
                                }
                                Some(false) => {
                                    // Found a solution but it doesn't meet the difficulty; keep mining.
                                    // Check whether a new job arrived.
                                    let new_job_option = {
                                        let job_guard = current_job_loop.blocking_lock();
                                        job_guard.clone()
                                    };

                                    if new_job_option.is_none()
                                        || new_job_option.unwrap().job_id != job.job_id
                                    {
                                        break;
                                    }
                                }
                                None => {
                                    // No solution found; keep trying.
                                }
                            }
                        }
                    }
                }
            });
    }

    // Spawn hash rate monitoring task
    tokio::spawn(async move {
        let mut last_count = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let count = hash_count.load(Ordering::Relaxed);
            println!(
                "{}: {:.2} hashes/second",
                "Hash rate".cyan(),
                (count - last_count) as f64 / 5.0
            );
            last_count = count;
        }
    });

    // Spawn api hash rate monitoring task
    let api_hashrate_clone = miner_state.clone();
    tokio::spawn(async move {
        let mut last_count = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await; // Measure every second
            let current_count = api_hashrate_clone.hash_count.load(Ordering::Relaxed);
            let hashes_per_second = current_count - last_count;
            let mut samples = api_hashrate_clone.hashrate_samples.lock().await;
            samples.push(hashes_per_second as u64);
            if samples.len() > 10 {
                samples.remove(0);
            }
            last_count = current_count;
        }
    });

    let api_state = miner_state.clone();
    tokio::spawn(api::start_http_server(api_state));

    let current_job_clone = Arc::clone(&current_job);
    let job_version_clone = Arc::clone(&job_version);
    let request_clone = args.pool.unwrap().clone();

    let server_receiver = Arc::new(Mutex::new(server_receiver));

    loop {
        let request = request_clone.clone().into_client_request().unwrap();
        let (ws_stream, _) = match connect_async(request).await {
            Ok((ws_stream, response)) => (ws_stream, response),
            Err(_e) => {
                let delay_secs = rand::thread_rng().gen_range(5..30);
                println!(
                    "{}",
                    format!("Failed to connect will retry in {} seconds...", delay_secs).red()
                );
                tokio::time::sleep(Duration::from_secs(delay_secs)).await;
                continue;
            }
        };

        let (write, mut read) = ws_stream.split();

        // Spawn write task to send solutions to the server
        let server_receiver_clone = Arc::clone(&server_receiver);
        tokio::spawn(async move {
            let mut write = write;
            while let Ok(msg) = {
                let receiver = server_receiver_clone.lock().await;
                receiver.recv()
            } {
                write.send(Message::Text(msg)).await.unwrap();
            }
        });

        loop {
            match read.next().await {
                Some(Ok(msg)) => match msg {
                    Message::Text(text_msg) => {
                        let server_message: ServerMessage =
                            serde_json::from_str(&text_msg).unwrap();
                        match server_message.r#type.as_str() {
                            "job" => {
                                if let (Some(job_id), Some(data), Some(target)) = (
                                    server_message.job_id.clone(),
                                    server_message.data.clone(),
                                    server_message.target.clone(),
                                ) {
                                    let new_job = Job {
                                        job_id: job_id.clone(),
                                        data: data.clone(),
                                        target: target.clone(),
                                    };

                                    let mut job_guard = current_job_clone.lock().await;
                                    *job_guard = Some(new_job);

                                    println!(
                                        "{} {}",
                                        "Received new job:".bold().blue(),
                                        format!(
                                            "ID = {}, Data = {}, Target = {}",
                                            job_id, data, target
                                        )
                                        .bold()
                                        .yellow()
                                    );
                                }
                            }
                            "accepted" => {
                                miner_state.accepted_shares.fetch_add(1, Ordering::Relaxed);
                                println!("{}", format!("Share accepted").bold().green());
                                display_share_accepted();
                            }
                            "rejected" => {
                                miner_state.rejected_shares.fetch_add(1, Ordering::Relaxed);
                                println!("{}", "Share rejected.".red());
                            }
                            _ => {}
                        }
                    }
                    Message::Close(_) => {
                        println!("{}", "You are now a frog.".green());
                        std::process::exit(0);
                    }
                    _ => {}
                },
                Some(Err(_e)) => {
                    println!(
                        "{}",
                        "WebSocket connection closed. Will sleep then try to reconnect.".red()
                    );
                    break;
                }
                None => {
                    println!(
                        "{}",
                        "WebSocket connection closed. Will sleep then try to reconnect.".red()
                    );
                    break;
                }
            }
        }

        let mut job_guard = current_job_clone.lock().await;
        *job_guard = None;

        let delay_secs = rand::thread_rng().gen_range(11..42);
        println!(
            "{}",
            format!("Reconnecting in {} seconds...", delay_secs).yellow()
        );
        tokio::time::sleep(Duration::from_secs(delay_secs)).await;
        println!("{}", "Attempting to reconnect...".red());
    }
}
