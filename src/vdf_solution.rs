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
        _third_opt_limit: usize,
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
        
        // 预计算nodeEdges数组：存储每个节点的邻居节点列表，避免重复查询edges矩阵
        // 同时这个可以直接让两重循环的100*100变成100*12.5 加速8倍
        let mut node_edges: Vec<Vec<u16>> = vec![Vec::new(); graph_size as usize];
        for i in 0..graph_size as usize {
            for j in 0..graph_size as usize {
                if edges[i][j] {
                    node_edges[i].push(j as u16);
                }
            }
        }

        let start_node: u16 = 0;
        let start_time = Instant::now();

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
                // 检查是否回到起点
                if node_edges[current as usize].contains(&0) {
                    return true;
                }
            } else {
                // 只遍历当前节点的邻居，避免无意义的判断
                for &next in &node_edges[current as usize] {
                    if !visited[next as usize] {
                        if dfs(next, visited, path, node_edges, start_time, timeout_ms, graph_size) {
                            return true;
                        }
                    }
                }
            }

            visited[current as usize] = false;
            path.pop();
            false
        }

        // 尝试找到queen路径
        if !dfs(start_node, &mut visited, &mut path, &node_edges, start_time, timeout_ms, graph_size) {
            return None; // 没有找到queen路径
        }

        let base_queen_path = path;
        
        // 创建基础路径列表，用于存储所有可能的起始路径
        let mut base_queen_path_list: Vec<Vec<u16>> = Vec::new();
        
        // 添加原始路径到列表
        base_queen_path_list.push(base_queen_path.clone());
        
        // 预处理：检查是否有节点可以与最后一个节点进行路径翻转
        let last_node_index = base_queen_path.len() - 1;
        for i in 1..(base_queen_path.len() - 1) {
            // 检查是否可以与最后一个节点进行翻转（保持连通性）
            if edges[base_queen_path[i - 1] as usize][base_queen_path[last_node_index] as usize] && 
               edges[base_queen_path[i] as usize][base_queen_path[0] as usize] {
                let mut flipped_path = base_queen_path.clone();
                Self::reverse_subpath(&mut flipped_path, i, last_node_index);
                base_queen_path_list.push(flipped_path);
            }
        }
        

        // 对每个基础路径进行处理
        for current_base_path in &base_queen_path_list {
            // 预计算nodeIndex数组：建立节点ID到路径位置的反向映射
            let mut node_index: Vec<usize> = vec![0; graph_size as usize];
            for (pos, &node) in current_base_path.iter().enumerate() {
                node_index[node as usize] = pos;
            }
            
            // 引入HashSet来避免重复路径的计算和提交
            let mut processed_paths: std::collections::HashSet<Vec<u16>> = std::collections::HashSet::new();
            
            // 首先尝试当前基础路径
            processed_paths.insert(current_base_path.clone());
            if let Some(result) = self.check_and_submit_solution(current_base_path, worker_path, data, job, miner_id, nonce, server_sender, hash_count, api_hash_count) {
                if result { return Some(true); } // 找到有效解，立即返回
            }
            
            // 使用预计算数据进行优化的2-opt操作
            for i in 1..(current_base_path.len() - 1) {
                // 应该是比如我们想作ij之间子路径的翻转，那么我们需要判断的是i-1和j链接，i和j+1位置的节点连接
                // 因此，我们第二重循环，不应该是j遍历全部！应该是一个循环变量k，遍历i-1的邻居节点，同时如果这个节点在路径中的位置j，大于i，那么就意味着至少i-1和这个j是链接的，只需要再判断一下i是不是和j+1链接就可以作翻转。
                let node_before_i = current_base_path[i - 1];
                let node_i = current_base_path[i];
                
                // 遍历i-1位置节点的邻居节点k
                for &k in &node_edges[node_before_i as usize] {
                    // 使用nodeIndex快速获取邻居节点k在路径中的位置j
                    let j = node_index[k as usize];
                    
                    // 检查位置有效性：j > i 且 j < current_base_path.len() - 1
                    if j > i && j < current_base_path.len() - 1 {
                        let node_j = current_base_path[j];
                        let node_after_j = current_base_path[j + 1];
                        
                        // 只需要检查i和j+1位置的节点是否连接（i-1和j的连接已经通过邻居遍历保证）
                        if edges[node_i as usize][node_after_j as usize] {
                             let mut new_path = current_base_path.clone();
                             // 执行路径翻转
                             new_path[i..=j].reverse();
                        
                        // 检查路径是否已处理过
                        if !processed_paths.contains(&new_path) {
                            processed_paths.insert(new_path.clone());
                            
                            // 立即检查这个路径
                            if let Some(result) = self.check_and_submit_solution(&new_path, worker_path, data, job, miner_id, nonce, server_sender, hash_count, api_hash_count) {
                                if result { return Some(true); } // 找到有效解，立即返回
                            }
                            
                            // 对new_path再次进行2-opt操作（双重2-opt优化）
                            // 重新计算new_path的node_index映射
                            let mut new_node_index: Vec<usize> = vec![0; graph_size as usize];
                            for (pos, &node) in new_path.iter().enumerate() {
                                new_node_index[node as usize] = pos;
                            }
                            
                            for ii in 1..(new_path.len() - 1) {
                                let node_before_ii = new_path[ii - 1];
                                let node_ii = new_path[ii];
                                
                                // 遍历ii-1位置节点的邻居节点kk
                                for &kk in &node_edges[node_before_ii as usize] {
                                    // 使用new_node_index快速获取邻居节点kk在路径中的位置jj
                                    let jj = new_node_index[kk as usize];
                                    
                                    // 检查位置有效性：jj > ii 且 jj < new_path.len() - 1
                                    if jj > ii && jj < new_path.len() - 1 {
                                        let node_after_jj = new_path[jj + 1];
                                        
                                        // 检查ii和jj+1位置的节点是否连接
                                        if edges[node_ii as usize][node_after_jj as usize] {
                                            let mut double_opt_path = new_path.clone();
                                            // 执行第二次路径翻转
                                            double_opt_path[ii..=jj].reverse();
                                            
                                            // 检查双重优化路径是否已处理过
                                            if !processed_paths.contains(&double_opt_path) {
                                                processed_paths.insert(double_opt_path.clone());
                                                
                                                // 检查双重优化后的路径
                                                if let Some(result) = self.check_and_submit_solution(&double_opt_path, worker_path, data, job, miner_id, nonce, server_sender, hash_count, api_hash_count) {
                                                    if result { return Some(true); } // 找到有效解，立即返回
                                                }
                                                
                                                // 对double_opt_path再次进行2-opt操作（第三重2-opt优化）
                                                // 重新计算double_opt_path的node_index映射
                                                let mut triple_node_index: Vec<usize> = vec![0; graph_size as usize];
                                                for (pos, &node) in double_opt_path.iter().enumerate() {
                                                    triple_node_index[node as usize] = pos;
                                                }
                                                
                                                for iii in 1..(double_opt_path.len() - 1) {
                                                    let node_before_iii = double_opt_path[iii - 1];
                                                    let node_iii = double_opt_path[iii];
                                                    
                                                    // 遍历iii-1位置节点的邻居节点kkk
                                                    for &kkk in &node_edges[node_before_iii as usize] {
                                                        // 使用triple_node_index快速获取邻居节点kkk在路径中的位置jjj
                                                        let jjj = triple_node_index[kkk as usize];
                                                        
                                                        // 检查位置有效性：jjj > iii 且 jjj < double_opt_path.len() - 1
                                                        if jjj > iii && jjj < double_opt_path.len() - 1 {
                                                            let node_after_jjj = double_opt_path[jjj + 1];
                                                            
                                                            // 检查iii和jjj+1位置的节点是否连接
                                                            if edges[node_iii as usize][node_after_jjj as usize] {
                                                                let mut triple_opt_path = double_opt_path.clone();
                                                                // 执行第三次路径翻转
                                                                triple_opt_path[iii..=jjj].reverse();
                                                                
                                                                // 检查三重优化路径是否已处理过
                                                                if !processed_paths.contains(&triple_opt_path) {
                                                                    processed_paths.insert(triple_opt_path.clone());
                                                                    
                                                                    // 检查三重优化后的路径
                                                                    if let Some(result) = self.check_and_submit_solution(&triple_opt_path, worker_path, data, job, miner_id, nonce, server_sender, hash_count, api_hash_count) {
                                                                        if result { return Some(true); } // 找到有效解，立即返回
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
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
