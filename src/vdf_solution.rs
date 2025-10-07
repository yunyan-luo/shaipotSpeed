use primitive_types::U256;
use rand_mt::Mt19937GenRand64;
use crate::graph_bridge::ffi;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use sha2::{Digest, Sha256};
use crate::models::{SubmitMessage, Job};
use crate::utils::meets_target;
use hex;
use serde_json;
use std::collections::HashSet;

pub const GRAPH_SIZE: u16 = 2008;

pub struct HCGraphUtil {
    start_time: Instant,
    vdf_bailout: u64
}

impl HCGraphUtil {
    // Helper function to reverse a subpath (2-opt optimization)
    fn reverse_subpath(path: &mut Vec<u16>, i: usize, j: usize) {
        path[i..=j].reverse();
    }
    pub fn check_and_submit_solution(
        &self,
        queen_path: &Vec<u16>,
        worker_path: &Vec<u16>,
        data: &str,
        job: &Job,
        miner_id: &str,
        nonce: &str,
        server_sender: &mpsc::Sender<String>,
        hash_count: &AtomicUsize,
        api_hash_count: &AtomicUsize
    ) -> Option<bool> {
        // 组合worker_path和queen_path
        let mut combined_path = worker_path.clone();
        combined_path.extend(queen_path.clone());

        // 确保combined_path大小匹配GRAPH_SIZE
        if combined_path.len() < GRAPH_SIZE.into() {
            combined_path.resize(GRAPH_SIZE.into(), u16::MAX);
        }

        // 格式化为little-endian hex字符串
        let vdf_solution_hex_solved: String = combined_path
            .iter()
            .map(|&val| {
                let little_endian_val = val.to_le_bytes();
                format!("{:02x}{:02x}", little_endian_val[0], little_endian_val[1])
            })
            .collect();
        
        let data_with_vdf_solved = format!("{}{}", data, vdf_solution_hex_solved);

        let data_bytes_solved = hex::decode(data_with_vdf_solved).expect("Invalid hex input");

        // 最终SHA256 hash
        let mut hasher2 = Sha256::new();
        hasher2.update(&data_bytes_solved);
        let hash2 = hasher2.finalize();

        let final_hash_reversed = hex::encode(hash2.iter().rev().cloned().collect::<Vec<u8>>());

        // 检查是否满足难度要求
        if meets_target(&final_hash_reversed, &job.target) {
            println!("SUBMITTING SHARE TO BACKEND!");
            println!("final_hash_reversed: {}", final_hash_reversed);
            
            // 创建提交消息
            let submit_msg = SubmitMessage {
                r#type: String::from("submit"),
                miner_id: miner_id.to_string(),
                nonce: nonce.to_string(),
                job_id: job.job_id.clone(),
                path: vdf_solution_hex_solved,
            };

            // 发送提交消息
            if let Ok(msg) = serde_json::to_string(&submit_msg) {
                let _ = server_sender.send(msg);
            }

            // 返回true表示找到有效解并已提交
            Some(true)
        } else {
            // 增加hash计数
            hash_count.fetch_add(1, Ordering::Relaxed);
            api_hash_count.fetch_add(1, Ordering::Relaxed);
            // 返回false表示找到解但不满足难度要求
            Some(false)
        }
    }

    pub fn new(vdf_bailout: Option<u64>) -> Self {
        let bailout_timer: u64 = match vdf_bailout {
            Some(timer) => { timer },
            None => { 1000 } // default to 1 second
        };
        HCGraphUtil {
            start_time: Instant::now(),
            vdf_bailout: bailout_timer
        }
    }

    fn hex_to_u64(&self, hex_string: &str) -> u64 {
        u64::from_str_radix(hex_string, 16).expect("Failed to convert hex to u64")
    }

    // fn extract_seed_from_hash(&self, hash: &U256) -> u64 {
    //     hash.low_u64()
    // }

    fn extract_seed_from_hash_hex(&self, hash_hex: &str) -> u64 {
        let mut bytes = hex::decode(hash_hex).expect("invalid hex");
        bytes.reverse(); // Match C++ implementation that reverses hash bytes
        let arr: [u8; 8] = bytes[0..8].try_into().expect("slice len");
        u64::from_le_bytes(arr)
    }
    
    pub fn get_worker_grid_size(&self, hash_hex: &str) -> u16 {
        let grid_size_segment = &hash_hex[0..8];
        let grid_size: u64 = self.hex_to_u64(grid_size_segment);
        let min_grid_size = 1892u64;
        let max_grid_size = 1920u64;
        let grid_size_final = min_grid_size + (grid_size % (max_grid_size - min_grid_size));
        grid_size_final as u16
    }

    pub fn get_queen_bee_grid_size(&self, worker_size: u16) -> u16 {
        GRAPH_SIZE - worker_size
    }


    fn generate_graph_v3_from_seed(&self, seed: u64, grid_size: u16, percentage_x10: u16) -> Vec<Vec<bool>> {
        let grid_size_usize = grid_size as usize;
        let mut graph = vec![vec![false; grid_size_usize]; grid_size_usize];

        let range: u64 = 1000;
        let threshold: u64 = (percentage_x10 as u64 * range) / 1000;

        // Use C++ std::uniform_int_distribution through FFI bridge
        let mut generator = ffi::create_graph_generator(seed, range);
        
        for i in 0..grid_size_usize {
            for j in (i + 1)..grid_size_usize {
                let random_value = generator.pin_mut().next_random();
                let edge_exists = random_value < threshold;
                
                graph[i][j] = edge_exists;
                graph[j][i] = edge_exists;
            }
        }

        graph
    }
    // fn generate_graph_v3_from_seed(&self, seed: u64, grid_size: u16, percentage_x10: u16) -> Vec<Vec<bool>> {
    //     let grid_size_usize = grid_size as usize;
    //     let mut graph = vec![vec![false; grid_size_usize]; grid_size_usize];

    //     let range: u64 = 1000;
    //     let threshold: u64 = (percentage_x10 as u64 * range) / 1000;

    //     // Use C++ std::uniform_int_distribution through FFI bridge
    //     let mut generator = ffi::create_graph_generator(seed, range);
        
    //     for i in 0..grid_size_usize {
    //         for j in (i + 1)..grid_size_usize {
    //             let random_value = generator.pin_mut().next_random();
    //             let edge_exists = random_value < threshold;
                
    //             graph[i][j] = edge_exists;
    //             graph[j][i] = edge_exists;
    //         }
    //     }

    //     graph
    // }

    pub fn find_hamiltonian_cycle_v3_hex(&self, graph_hash_hex: &str, graph_size: u16, percentage_x10: u16, timeout_ms: u64) -> Vec<u16> {
        let mut path: Vec<u16> = Vec::with_capacity(graph_size as usize);
        let mut visited = vec![false; graph_size as usize];
        let seed = self.extract_seed_from_hash_hex(graph_hash_hex);
        
        let edges = self.generate_graph_v3_from_seed(seed, graph_size, percentage_x10);

        let start_node: u16 = 0;
        let start_time = Instant::now();

        fn dfs(
            current: u16,
            visited: &mut [bool],
            path: &mut Vec<u16>,
            edges: &Vec<Vec<bool>>,
            start_time: Instant,
            timeout_ms: u64,
            graph_size: u16,
        ) -> bool {
            if start_time.elapsed() > Duration::from_millis(timeout_ms) {
                return false;
            }

            path.push(current);
            visited[current as usize] = true;

            if path.len() == graph_size as usize && edges[current as usize][0] {
                return true;
            }

            for next in 0..graph_size as usize {
                if edges[current as usize][next] && !visited[next] {
                    if dfs(next as u16, visited, path, edges, start_time, timeout_ms, graph_size) {
                        return true;
                    }
                }
            }

            visited[current as usize] = false;
            path.pop();
            false
        }

        if dfs(start_node, &mut visited, &mut path, &edges, start_time, timeout_ms, graph_size) {
            return path;
        }

        Vec::new()
    }

    pub fn find_hamiltonian_cycle_v3_hex_multi(
        &self, 
        graph_hash_hex: &str, 
        graph_size: u16, 
        percentage_x10: u16, 
        timeout_ms: u64,
        max_paths: usize
    ) -> Vec<Vec<u16>> {
        let mut path: Vec<u16> = Vec::with_capacity(graph_size as usize);
        let mut visited = vec![false; graph_size as usize];
        let seed = self.extract_seed_from_hash_hex(graph_hash_hex);
        
        let edges = self.generate_graph_v3_from_seed(seed, graph_size, percentage_x10);

        let start_node: u16 = 0;
        let start_time = Instant::now();

        fn dfs(
            current: u16,
            visited: &mut [bool],
            path: &mut Vec<u16>,
            edges: &Vec<Vec<bool>>,
            start_time: Instant,
            timeout_ms: u64,
            graph_size: u16,
        ) -> bool {
            if start_time.elapsed() > Duration::from_millis(timeout_ms) {
                return false;
            }

            path.push(current);
            visited[current as usize] = true;

            if path.len() == graph_size as usize && edges[current as usize][0] {
                return true;
            }

            for next in 0..graph_size as usize {
                if edges[current as usize][next] && !visited[next] {
                    if dfs(next as u16, visited, path, edges, start_time, timeout_ms, graph_size) {
                        return true;
                    }
                }
            }

            visited[current as usize] = false;
            path.pop();
            false
        }

        // 尝试找到基础的哈密顿路径
        if !dfs(start_node, &mut visited, &mut path, &edges, start_time, timeout_ms, graph_size) {
            return Vec::new(); // 没有找到基础路径，返回空列表
        }

        let base_path = path;
        let mut result_paths: Vec<Vec<u16>> = Vec::new();
        
        // 首先添加基础路径
        result_paths.push(base_path.clone());
        
        // 如果已经达到最大路径数，直接返回
        if result_paths.len() >= max_paths {
            return result_paths;
        }
        
        // 使用2-opt优化生成额外的路径（只进行一层优化）
        for ii in 1..(graph_size as usize - 1) {
            for jj in (ii + 1)..(graph_size as usize - 1) {
                // 检查2-opt交换是否有效（保持连通性）
                if edges[base_path[ii - 1] as usize][base_path[jj] as usize] && 
                   edges[base_path[ii] as usize][base_path[jj + 1] as usize] {
                    let mut new_path = base_path.clone();
                    Self::reverse_subpath(&mut new_path, ii, jj);
                    
                    // 添加优化后的路径到结果列表
                    result_paths.push(new_path);
                    
                    // 检查是否达到最大路径数
                    if result_paths.len() >= max_paths {
                        return result_paths;
                    }
                }
            }
        }
        
        result_paths
    }

    pub fn find_hamiltonian_cycle_v3_hex_second(
        &self, 
        graph_hash_hex: &str, 
        graph_size: u16, 
        percentage_x10: u16, 
        timeout_ms: u64,
        third_opt_limit: usize,
        worker_path: &Vec<u16>,
        data: &str,
        job: &Job,
        miner_id: &str,
        nonce: &str,
        server_sender: &mpsc::Sender<String>,
        hash_count: &AtomicUsize,
        api_hash_count: &AtomicUsize
    ) -> Option<bool> {
        let mut path: Vec<u16> = Vec::with_capacity(graph_size as usize);
        let mut visited = vec![false; graph_size as usize];
        let seed = self.extract_seed_from_hash_hex(graph_hash_hex);
        
        let edges = self.generate_graph_v3_from_seed(seed, graph_size, percentage_x10);

        let start_node: u16 = 0;
        let start_time = Instant::now();

        fn dfs(
            current: u16,
            visited: &mut [bool],
            path: &mut Vec<u16>,
            edges: &Vec<Vec<bool>>,
            start_time: Instant,
            timeout_ms: u64,
            graph_size: u16,
        ) -> bool {
            if start_time.elapsed() > Duration::from_millis(timeout_ms) {
                return false;
            }

            path.push(current);
            visited[current as usize] = true;

            if path.len() == graph_size as usize && edges[current as usize][0] {
                return true;
            }

            for next in 0..graph_size as usize {
                if edges[current as usize][next] && !visited[next] {
                    if dfs(next as u16, visited, path, edges, start_time, timeout_ms, graph_size) {
                        return true;
                    }
                }
            }

            visited[current as usize] = false;
            path.pop();
            false
        }

        // 尝试找到queen路径
        if !dfs(start_node, &mut visited, &mut path, &edges, start_time, timeout_ms, graph_size) {
            return None; // 没有找到queen路径
        }

        let base_queen_path = path;
        
        // 首先尝试原始路径
        if let Some(result) = self.check_and_submit_solution(
            &base_queen_path,
            worker_path,
            data,
            job,
            miner_id,
            nonce,
            server_sender,
            hash_count,
            api_hash_count
        ) {
            if result {
                return Some(true); // 找到有效解，立即返回
            }
        }
        
        // 使用2-opt优化生成额外的路径并立即检查
        // 创建HashSet来存储已处理的交换对组合，避免重复计算
        let mut processed_swaps_2: HashSet<(usize, usize, usize, usize)> = HashSet::new();
        let mut processed_swaps_3: HashSet<(usize, usize, usize, usize, usize, usize)> = HashSet::new();
        
        // 为三重2-opt优化添加3秒超时机制
        // let opt_start_time = Instant::now();
        
        for ii in 1..(graph_size as usize - 1) {
            // 第一级循环超时检查
            // if opt_start_time.elapsed() > Duration::from_secs(3) {
            //     break;
            // }
            for jj in (ii + 1)..(graph_size as usize - 1) {
                // 检查2-opt交换是否有效（保持连通性）
                if edges[base_queen_path[ii - 1] as usize][base_queen_path[jj] as usize] && 
                   edges[base_queen_path[ii] as usize][base_queen_path[jj + 1] as usize] {
                    let mut new_path = base_queen_path.clone();
                    Self::reverse_subpath(&mut new_path, ii, jj);
                    
                    // 立即检查这个路径
                    if let Some(result) = self.check_and_submit_solution(
                        &new_path,
                        worker_path,
                        data,
                        job,
                        miner_id,
                        nonce,
                        server_sender,
                        hash_count,
                        api_hash_count
                    ) {
                        if result {
                            return Some(true); // 找到有效解，立即返回
                        }
                    }
                    
                    // 第二级优化：在已优化的路径上再次应用2-opt
                    for iii in 1..(graph_size as usize - 1) {
                        // 第二级循环超时检查
                        // if opt_start_time.elapsed() > Duration::from_secs(3) {
                        //     break;
                        // }
                        for jjj in (iii + 1)..(graph_size as usize - 1) {
                            // 避免重复相同的交换位置
                            if (iii == ii && jjj == jj) || (iii == jj && jjj == ii) {
                                continue;
                            }
                            
                            // 检查是否已经处理过这个交换组合（顺序无关）
                            if processed_swaps_2.contains(&(iii, jjj, ii, jj)) {
                                continue;
                            }
                            
                            // 检查第二次2-opt交换是否有效（保持连通性）
                            if edges[new_path[iii - 1] as usize][new_path[jjj] as usize] && 
                               edges[new_path[iii] as usize][new_path[jjj + 1] as usize] {
                                let mut second_opt_path = new_path.clone();
                                Self::reverse_subpath(&mut second_opt_path, iii, jjj);
                                
                                // 立即检查这个路径
                                if let Some(result) = self.check_and_submit_solution(
                                    &second_opt_path,
                                    worker_path,
                                    data,
                                    job,
                                    miner_id,
                                    nonce,
                                    server_sender,
                                    hash_count,
                                    api_hash_count
                                ) {
                                    if result {
                                        return Some(true); // 找到有效解，立即返回
                                    }
                                }
                                
                                let mut third_opt_count = 0; // 第三级优化计数器
                                // 第三级优化：在第二级优化的路径上再次应用2-opt
                                for iiii in 1..(graph_size as usize - 1) {
                                    // 第三级循环超时检查
                                    // if opt_start_time.elapsed() > Duration::from_secs(3) {
                                    //     break;
                                    // }
                                    for jjjj in (iiii + 1)..(graph_size as usize - 1) {

                                        // 避免重复相同的交换位置
                                        if (iiii == ii && jjjj == jj) || (iiii == jj && jjjj == ii) ||
                                           (iiii == iii && jjjj == jjj) || (iiii == jjj && jjjj == iii) ||
                                           (second_opt_path[iiii] > second_opt_path[jjjj]){
                                            continue;
                                        }
                                        
                                        // 检查是否已经处理过这个交换组合（避免重复计算）
                                        if processed_swaps_3.contains(&(ii, jj, iii, jjj, iiii, jjjj)) {
                                            continue;
                                        }
                                        
                                        // 检查第三次2-opt交换是否有效（保持连通性）
                                        if edges[second_opt_path[iiii - 1] as usize][second_opt_path[jjjj] as usize] && 
                                           edges[second_opt_path[iiii] as usize][second_opt_path[jjjj + 1] as usize] {
                                            third_opt_count += 1; // 增加第三级优化计数器

                                            let mut third_opt_path = second_opt_path.clone();
                                            Self::reverse_subpath(&mut third_opt_path, iiii, jjjj);
                                            
                                            // 立即检查这个路径
                                            if let Some(result) = self.check_and_submit_solution(
                                                &third_opt_path,
                                                worker_path,
                                                data,
                                                job,
                                                miner_id,
                                                nonce,
                                                server_sender,
                                                hash_count,
                                                api_hash_count
                                            ) {
                                                if result {
                                                    return Some(true); // 找到有效解，立即返回
                                                }
                                            }
                                            
                                            // 将这个交换组合标记为已处理
                                            processed_swaps_3.insert((ii, jj, iii, jjj, iiii, jjjj));
                                        }
                                        if third_opt_count >= third_opt_limit {
                                            break;
                                        }
                                    }
                                    if third_opt_count >= third_opt_limit {
                                        break;
                                    }
                                }
                                
                                // 将这个交换组合标记为已处理
                                processed_swaps_2.insert((ii, jj, iii, jjj));
                            }
                        }
                    }
                }
            }
        }
        
        // 如果所有路径都处理完毕但没有找到有效解，返回Some(false)
        // 表示处理了路径但没有找到满足难度要求的解
        Some(false)
    }


}
