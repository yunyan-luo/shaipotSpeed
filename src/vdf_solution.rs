// use primitive_types::U256;
use crate::graph_bridge::ffi;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use sha2::{Digest, Sha256};
use crate::models::{SubmitMessage, Job};
use crate::utils::meets_target;
use hex;
use serde_json;

pub const GRAPH_SIZE: u16 = 2008;

pub struct HCGraphUtil {
    // start_time: Instant,
    // vdf_bailout: u64
}

impl HCGraphUtil {
    // Helper function to reverse a subpath (2-opt optimization)
    // fn reverse_subpath(path: &mut Vec<u16>, i: usize, j: usize) {
    //     path[i..=j].reverse();
    // }
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

    pub fn new(_vdf_bailout: Option<u64>) -> Self {
        // let bailout_timer: u64 = match vdf_bailout {
        //     Some(timer) => { timer },
        //     None => { 1000 } // default to 1 second
        // };
        HCGraphUtil {
            // start_time: Instant::now(),
            // vdf_bailout: bailout_timer
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


    fn generate_graph_v3_from_seed(&self, seed: u64, grid_size: u16, percentage_x10: u16) -> (Vec<Vec<bool>>, Vec<Vec<u16>>) {
        let grid_size_usize = grid_size as usize;
        let mut graph = vec![vec![false; grid_size_usize]; grid_size_usize];
        let mut adj = vec![Vec::with_capacity(grid_size_usize / 2); grid_size_usize];

        let range: u64 = 1000;
        let threshold: u64 = (percentage_x10 as u64 * range) / 1000;

        // Use C++ std::uniform_int_distribution through FFI bridge
        let mut generator = ffi::create_graph_generator(seed, range);
        
        for i in 0..grid_size_usize {
            for j in (i + 1)..grid_size_usize {
                let random_value = generator.pin_mut().next_random();
                let edge_exists = random_value < threshold;
                
                if edge_exists {
                    graph[i][j] = true;
                    graph[j][i] = true;
                    adj[i].push(j as u16);
                    adj[j].push(i as u16);
                }
            }
        }

        (graph, adj)
    }

    pub fn find_hamiltonian_cycle_v3_hex(&self, graph_hash_hex: &str, graph_size: u16, percentage_x10: u16, timeout_ms: u64) -> Vec<u16> {
        let mut path: Vec<u16> = Vec::with_capacity(graph_size as usize);
        let mut visited = vec![false; graph_size as usize];
        let seed = self.extract_seed_from_hash_hex(graph_hash_hex);
        
        let (edges, adj) = self.generate_graph_v3_from_seed(seed, graph_size, percentage_x10);

        let start_node: u16 = 0;
        let start_time = Instant::now();

        fn dfs(
            current: u16,
            visited: &mut [bool],
            path: &mut Vec<u16>,
            edges: &Vec<Vec<bool>>,
            adj: &Vec<Vec<u16>>,
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

            for &next in &adj[current as usize] {
                if !visited[next as usize] {
                    if dfs(next, visited, path, edges, adj, start_time, timeout_ms, graph_size) {
                        return true;
                    }
                }
            }

            visited[current as usize] = false;
            path.pop();
            false
        }

        if dfs(start_node, &mut visited, &mut path, &edges, &adj, start_time, timeout_ms, graph_size) {
            return path;
        }

        Vec::new()
    }

    fn optimize_path(&self, path: &mut Vec<u16>, edges: &Vec<Vec<bool>>) {
        let n = path.len();
        let mut need_check = true;
        while need_check {
            need_check = false;
            for i in 1..(n - 1) {
                for j in (i + 1)..(n - 1) {
                    if edges[path[i - 1] as usize][path[j] as usize]
                        && edges[path[i] as usize][path[j + 1] as usize]
                        && path[i] > path[j]
                    {
                        // 2-opt swap to correct inversion
                        path[i..=j].reverse();
                        need_check = true;
                    }
                }
            }
        }
    }

    pub fn find_hamiltonian_cycle_v3_hex_second(
        &self, 
        graph_hash_hex: &str, 
        graph_size: u16, 
        percentage_x10: u16, 
        timeout_ms: u64,
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
        
        let (edges, node_edges) = self.generate_graph_v3_from_seed(seed, graph_size, percentage_x10);

        let start_node: u16 = 0;
        let start_time = Instant::now();

        // fn dfs(
        //     current: u16,
        //     visited: &mut [bool],
        //     path: &mut Vec<u16>,
        //     node_edges: &Vec<Vec<u16>>,
        //     start_time: Instant,
        //     timeout_ms: u64,
        //     graph_size: u16,
        // ) -> bool {
        //     if start_time.elapsed() > Duration::from_millis(timeout_ms) {
        //         return false;
        //     }

        //     path.push(current);
        //     visited[current as usize] = true;

        //     if path.len() == graph_size as usize {
        //         // 检查是否回到起点
        //         if node_edges[current as usize].contains(&0) {
        //             return true;
        //         }
        //     } else {
        //         // 只遍历当前节点的邻居，避免无意义的判断
        //         for &next in &node_edges[current as usize] {
        //             if !visited[next as usize] {
        //                 if dfs(next, visited, path, node_edges, start_time, timeout_ms, graph_size) {
        //                     return true;
        //                 }
        //             }
        //         }
        //     }

        //     visited[current as usize] = false;
        //     path.pop();
        //     false
        // }

        /// Optimized DFS with pruning heuristics for Hamiltonian cycle finding
        fn dfs(
            current: u16,
            visited: &mut [bool],
            path: &mut Vec<u16>,
            node_edges: &Vec<Vec<u16>>,
            start_time: Instant,
            timeout_ms: u64,
            graph_size: u16,
        ) -> bool {
            if start_time.elapsed() > Duration::from_millis(timeout_ms) {
                return false;
            }
        
            path.push(current);
            visited[current as usize] = true;
        
            if path.len() == graph_size as usize {
                // Check if we can return to start
                if node_edges[current as usize].contains(&0) {
                    return true;
                }
            } else {
                // Early pruning: check if all unvisited nodes are still reachable
                if !is_feasible(current, visited, node_edges) {
                    visited[current as usize] = false;
                    path.pop();
                    return false;
                }
            
                // Collect unvisited neighbors and sort by degree (fewest connections first)
                let mut neighbors: Vec<(u16, usize)> = node_edges[current as usize]
                    .iter()
                    .filter(|&&n| !visited[n as usize])
                    .map(|&n| {
                        let degree = count_unvisited_neighbors(n, visited, node_edges);
                        (n, degree)
                    })
                    .collect();
                
                neighbors.sort_by_key(|&(_, degree)| degree);
                
                for (next, _) in neighbors {
                    if dfs(next, visited, path, node_edges, start_time, timeout_ms, graph_size) {
                        return true;
                    }
                }
            }
        
            visited[current as usize] = false;
            path.pop();
            false
        }

        /// Check if the remaining unvisited nodes can still form a valid path
        #[inline]
        fn is_feasible(current: u16, visited: &[bool], node_edges: &Vec<Vec<u16>>) -> bool {
            for (i, &is_visited) in visited.iter().enumerate() {
                if !is_visited && i != current as usize {
                    // Check if this unvisited node has at least one unvisited neighbor
                    let has_unvisited_neighbor = node_edges[i]
                        .iter()
                        .any(|&n| !visited[n as usize] || n == current);

                    if !has_unvisited_neighbor {
                        return false;
                    }
                }
            }
            true
        }

        /// Count how many unvisited neighbors a node has
        #[inline]
        fn count_unvisited_neighbors(node: u16, visited: &[bool], node_edges: &Vec<Vec<u16>>) -> usize {
            node_edges[node as usize]
                .iter()
                .filter(|&&n| !visited[n as usize])
                .count()
        }
        // 尝试找到queen路径
        if !dfs(start_node, &mut visited, &mut path, &node_edges, start_time, timeout_ms, graph_size) {
            return None; // 没有找到queen路径
        }

        // 对初始路径执行一次2-opt优化
        self.optimize_path(&mut path, &edges);
        if let Some(result) = self.check_and_submit_solution(&path, worker_path, data, job, miner_id, nonce, server_sender, hash_count, api_hash_count) {
            if result { return Some(true); } // 找到有效解，立即返回
        }

        let n = path.len();

        // 1. 全局2-opt搜索 (Global 2-opt Search)
        // 尝试所有可能的2-opt交换，不仅仅是涉及最后一个节点的交换
        'outer_2opt: for i in 0..n-2 {
            // j 从 i+2 开始，避免相邻边交换（无效）
            // j 可以取到 n-1
            for j in (i + 2)..n {
                // 检查时间限制
                if start_time.elapsed() > Duration::from_millis(timeout_ms) {
                    break 'outer_2opt;
                }

                // 2-opt 移动涉及断开 (i, i+1) 和 (j, j+1)
                // 连接 (i, j) 和 (i+1, j+1)
                // 注意：当 j=n-1 时，j+1 为 0
                
                let idx_i = i;
                let idx_i_next = i + 1;
                let idx_j = j;
                let idx_j_next = (j + 1) % n;

                let node_i = path[idx_i];
                let node_i_next = path[idx_i_next];
                let node_j = path[idx_j];
                let node_j_next = path[idx_j_next];

                // 检查新边是否存在
                if edges[node_i as usize][node_j as usize] && 
                   edges[node_i_next as usize][node_j_next as usize] {
                    
                    // 构建新路径：反转 path[i+1...j]
                    let mut new_path = path.clone();
                    
                    // Rust的slice reverse不处理wrap-around，但在2-opt标准定义中，
                    // 我们只需反转中间段。由于我们的循环结构 i < j，这一段是连续的。
                    new_path[idx_i_next..=idx_j].reverse();

                    // 必须调用 optimize_path 满足验证约束
                    self.optimize_path(&mut new_path, &edges);

                    // 检查并提交
                    if let Some(result) = self.check_and_submit_solution(
                        &new_path, worker_path, data, job, miner_id, nonce, server_sender, hash_count, api_hash_count
                    ) {
                        if result { return Some(true); }
                    }
                }
            }
        }

        // 2. 3-opt 搜索 (3-opt Search - Block Move)
        // 尝试将一段路径移动到另一个位置
        // 为了性能，我们限制移动的块大小为 1 到 5
        'outer_3opt: for block_len in 1..=5 {
            // 块的起始位置 i
            for i in 0..n {
                // 块的结束位置 j (处理循环)
                let j = (i + block_len - 1) % n;
                
                // 插入位置 k
                for k in 0..n {
                    if start_time.elapsed() > Duration::from_millis(timeout_ms) {
                        break 'outer_3opt;
                    }

                    // k 不能在块内，也不能是块的前一个节点（移动无效）
                    // 检查 k 是否在 i..=j 范围内（考虑循环）
                    let in_block = if i <= j {
                        k >= i && k <= j
                    } else {
                        k >= i || k <= j
                    };
                    
                    let prev_i = (i + n - 1) % n;
                    if in_block || k == prev_i {
                        continue;
                    }

                    // 3-opt 移动逻辑 (Block Move / Vertex Shift)
                    // 原路径: ... -> prev_i -> [i ... j] -> next_j -> ... -> k -> next_k -> ...
                    // 新路径: ... -> prev_i -> next_j -> ... -> k -> [i ... j] -> next_k -> ...
                    
                    // 断开边: (prev_i, i), (j, next_j), (k, next_k)
                    // 新增边: (prev_i, next_j), (k, i), (j, next_k)
                    
                    let idx_prev_i = prev_i;
                    let idx_i = i;
                    let idx_j = j;
                    let idx_next_j = (j + 1) % n;
                    let idx_k = k;
                    let idx_next_k = (k + 1) % n;

                    let node_prev_i = path[idx_prev_i];
                    let node_i = path[idx_i];
                    let node_j = path[idx_j];
                    let node_next_j = path[idx_next_j];
                    let node_k = path[idx_k];
                    let node_next_k = path[idx_next_k];

                    if edges[node_prev_i as usize][node_next_j as usize] &&
                       edges[node_k as usize][node_i as usize] &&
                       edges[node_j as usize][node_next_k as usize] {
                        
                        // 构建新路径
                        // 新的环顺序是: prev_i -> next_j ... k -> i ... j -> next_k ... prev_i
                        let mut temp_path = Vec::with_capacity(n);
                        temp_path.push(node_prev_i); // Start at prev_i
                        
                        // Append next_j ... k
                        let mut curr = idx_next_j;
                        loop {
                            temp_path.push(path[curr]);
                            if curr == idx_k { break; }
                            curr = (curr + 1) % n;
                        }
                        
                        // Append i ... j
                        let mut curr = idx_i;
                        loop {
                            temp_path.push(path[curr]);
                            if curr == idx_j { break; }
                            curr = (curr + 1) % n;
                        }
                        
                        // Append next_k ... prev_i (excluding prev_i as it's start)
                        let mut curr = idx_next_k;
                        while curr != idx_prev_i {
                             temp_path.push(path[curr]);
                             curr = (curr + 1) % n;
                        }
                        
                        // 确保 0 在路径起始位置 (canonical form)
                        if let Some(pos_zero) = temp_path.iter().position(|&x| x == 0) {
                            temp_path.rotate_left(pos_zero);
                        }

                        // 验证约束: 必须调用 optimize_path
                        self.optimize_path(&mut temp_path, &edges);
                        
                        if let Some(result) = self.check_and_submit_solution(
                            &temp_path, worker_path, data, job, miner_id, nonce, server_sender, hash_count, api_hash_count
                        ) {
                            if result { return Some(true); }
                        }
                    }
                }
            }
        }
                                   
        Some(false)
    }


}
