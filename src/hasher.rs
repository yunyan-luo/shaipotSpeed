use super::cpp_bridge::CppSearcher;
use super::models::Job;
use colored::Colorize;
use hex;
use primitive_types::U256;
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;
use std::sync::Arc;

const GRAPH_SIZE: u16 = 2008;

/// C++ CPU hash computation using the full HC1+HC2 pipeline.
pub fn compute_hash_no_vdf_cpp(
    data: &str,
    hash_count: &Arc<AtomicUsize>,
    api_hash_count: &Arc<AtomicUsize>,
    job: &Job,
    nonce: &str,
    miner_id: &str,
    server_sender: &mpsc::Sender<String>,
    cpp_searcher: &CppSearcher,
    job_version: &std::sync::atomic::AtomicU64,
    expected_version: u64,
) -> Option<bool> {
    // Create the initial vdfSolution (all 0xFFFF).
    let vdf_solution: Vec<u16> = vec![0xFFFF; GRAPH_SIZE.into()];
    let vdf_solution_hex: String = vdf_solution
        .iter()
        .map(|&val| format!("{:04x}", val))
        .collect();

    let data_with_vdf = format!("{}{}", data, vdf_solution_hex);
    let data_bytes = hex::decode(&data_with_vdf).expect("Invalid hex input");

    // First SHA256 hash.
    let mut hasher = Sha256::new();
    hasher.update(&data_bytes);
    let hash1 = hasher.finalize();

    let hash1_reversed = hex::encode(hash1.iter().rev().cloned().collect::<Vec<u8>>());
    let graph_hash_u256 = U256::from_str_radix(&hash1_reversed, 16).unwrap();
    let first_hash_hex = format!("{:064x}", graph_hash_u256);

    // Run the full C++ search (HC1 + HC2).
    let (status, _path, solution_hex, cpp_hash_count) = cpp_searcher.search_full(
        &first_hash_hex,
        500, // worker_percentage_x10 (50%)
        125, // queen_percentage_x10 (12.5%)
        100, // max_worker_paths
        data,
        &job.target,
        Some(job_version),
        expected_version,
    );

    // Update hash counters.
    hash_count.fetch_add(
        cpp_hash_count as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    api_hash_count.fetch_add(
        cpp_hash_count as usize,
        std::sync::atomic::Ordering::Relaxed,
    );

    match status {
        0 => None, // HC1 failed
        1 => {
            // Valid solution found; send it to the server.
            println!("{}", "SUBMITTING SHARE TO BACKEND!".bold().green());

            let submit_msg = serde_json::json!({
                "type": "submit",
                "miner_id": miner_id,
                "job_id": job.job_id,
                "nonce": nonce,
                "path": solution_hex,
            })
            .to_string();

            if let Err(e) = server_sender.send(submit_msg) {
                eprintln!("Failed to send solution: {}", e);
            }

            Some(true)
        }
        2 => Some(false), // Exhausted without a valid solution
        3 => None,        // Canceled due to job change
        _ => None,
    }
}
