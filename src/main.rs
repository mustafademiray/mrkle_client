use reqwest::blocking::Client;
use reqwest::blocking::multipart::Form;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Error as IoError, Read, Result as IoResult};
use std::path::Path;
use std::fs;

enum UploadResult {
    Success,
    Failure(String),
}

#[derive(Debug, Clone)]
struct MerkleNode {
    hash: String,
    left: Option<usize>,
    right: Option<usize>,
    parent: Option<usize>,
    is_leaf: bool,
}

impl MerkleNode {
    fn new_leaf(data: &str) -> Result<MerkleNode, String> {
        let hash = hash_data(data);
        Ok(MerkleNode {
            hash,
            left: None,
            right: None,
            parent: None,
            is_leaf: true,
        })
    }

    fn new_internal(left: MerkleNode, right: MerkleNode) -> Result<MerkleNode, String> {
        if left.parent.is_none() || right.parent.is_none() {
            return Err("Parent reference missing for child nodes".to_string());
        }

        let combined_hash = hash_data(&format!("{}{}", left.hash, right.hash));
        Ok(MerkleNode {
            hash: combined_hash,
            left: Some(left.parent.unwrap()),
            right: Some(right.parent.unwrap()),
            parent: left.parent, // Set the parent reference for the new internal node
            is_leaf: false,
        })
    }
}


impl Default for MerkleNode {
    fn default() -> Self {
        MerkleNode {
            hash: String::new(),
            left: None,
            right: None,
            parent: None,
            is_leaf: false,
        }
    }
}


#[derive(Debug, Clone)]
struct MerkleTree {
    root: Option<usize>,
    nodes: Vec<MerkleNode>,
}

impl MerkleTree {
    fn new(data: Vec<String>) -> MerkleTree {
        let (root, nodes) = MerkleTree::generate_merkle_tree(&data, Vec::new(), None);
    
        let root_index = root.unwrap_or(0); // Set root to 0 if None
        MerkleTree {
            root: Some(root_index),
            nodes,
        }
    }

    fn generate_merkle_tree(data: &[String], mut nodes: Vec<MerkleNode>, parent: Option<usize>) -> (Option<usize>, Vec<MerkleNode>) {
        if data.is_empty() {
            return (None, nodes);
        }
    
        let node_index = nodes.len();
        
        let new_node = if data.len() == 1 {
            match MerkleNode::new_leaf(&data[0]) {
                Ok(mut leaf_node) => {
                    leaf_node.parent = parent; // Set the parent reference for the leaf node
                    leaf_node
                }
                Err(err_message) => {
                    println!("Error creating leaf node: {}", err_message);
                    return (None, nodes);
                }
            }
        } else {
            match MerkleNode::new_internal(MerkleNode::default(), MerkleNode::default()) {
                Ok(mut internal_node) => {
                    internal_node.parent = parent; // Set the parent reference for the internal node
                    internal_node
                }
                Err(err_message) => {
                    println!("Error creating internal node: {}", err_message);
                    return (None, nodes);
                }
            }
        };
    
        nodes.push(new_node);
    
        if data.len() > 1 {
            let left_index = node_index;
            let (right_index, new_nodes) = MerkleTree::generate_merkle_tree(&data[1..].to_vec(), nodes.clone(), Some(node_index));
            nodes[left_index].parent = Some(node_index); // Set parent for left child
            nodes[node_index].left = Some(left_index);
            nodes[node_index].right = Some(right_index.unwrap());
            nodes[node_index].is_leaf = false;
            nodes.extend_from_slice(&new_nodes);
        }
    
        if nodes[node_index].is_leaf {
            nodes.push(nodes[node_index].clone());
        } else {
            let left_index = nodes[node_index].left;
            let right_index = nodes[node_index].right;
    
            if let (Some(left_idx), Some(right_idx)) = (left_index, right_index) {
                match MerkleNode::new_internal(nodes[left_idx].clone(), nodes[right_idx].clone()) {
                    Ok(mut new_internal_node) => {
                        new_internal_node.parent = parent; // Set the parent reference for the new internal node
                        nodes.push(new_internal_node);
                    }
                    Err(err_message) => {
                        println!("Error creating internal node: {}", err_message);
                        return (None, nodes);
                    }
                }
            } else {
                println!("Error: left or right is None");
            }
        }
    
        (Some(node_index), nodes)
    }
    
    
        

    fn generate_merkle_proof(&self, index_to_verify: usize) -> Option<Vec<(String, String)>> {
        if index_to_verify >= self.nodes.len() {
            return None; // Index is out of bounds
        }
    
        let mut proof: Vec<(String, String)> = Vec::new();
        let mut current_index = index_to_verify;
    
        while let Some(parent_index) = self.nodes[current_index].parent {
            let parent = &self.nodes[parent_index];
    
            let sibling_index = if parent.left == Some(current_index) {
                parent.right
            } else {
                parent.left
            };
    
            if let Some(sibling_index) = sibling_index {
                let sibling = &self.nodes[sibling_index];
                proof.push(("sibling".to_string(), sibling.hash.clone()));
            } else {
                // Handle the case where the sibling is missing (you can choose how to handle this)
                // Here, we just add an empty string as a placeholder.
                proof.push(("sibling".to_string(), String::new()));
            }
    
            if parent.left == Some(current_index) {
                proof.push(("position".to_string(), "left".to_string()));
            } else {
                proof.push(("position".to_string(), "right".to_string()));
            }
    
            current_index = parent_index;
        }
    
        Some(proof)
    }
    
}

fn hash_data(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn hash_content(file_path: &str) -> IoResult<String> {
    let mut file = File::open(file_path)?;

    let mut hasher = Sha256::new();

    let mut buffer = [0u8; 4096];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    let hash = result.iter().map(|byte| format!("{:02x}", byte)).collect::<String>();
    Ok(hash)
}

fn extract_file_name(file_path: &str) -> &str {
    let path = Path::new(file_path);
    if let Some(file_name) = path.file_name() {
        if let Some(file_name_str) = file_name.to_str() {
            return file_name_str;
        }
    }
    "Failed to extract file name"
}

fn scan_directory_for_files(directory_path: &str) -> Vec<String> {
    let mut files_to_send: Vec<String> = Vec::new();

    if let Ok(entries) = fs::read_dir(directory_path) {
        for entry in entries {
            if let Ok(entry) = entry {
                if let Some(file_name) = entry.file_name().to_str() {
                    let file_path = entry.path();
                    if file_path.is_file() {
                        files_to_send.push(file_name.to_string());
                    }
                }
            }
        }
    }

    files_to_send
}

fn upload_file(file_path: &str) -> UploadResult {
    // Clone the file path to avoid lifetime issues
    let file_path = file_path.to_string();

    // Extract the file name as a String
    let file_name = extract_file_name(&file_path).to_string();

    // Calculate the hash of the file's content
    let content_hash = match hash_content(&file_path) {
        Ok(hash) => hash,
        Err(_) => {
            return UploadResult::Failure("Failed to compute the hash of the file's content".to_string());
        }
    };
    println!("File hash: {:?}", content_hash);

    // Initialize the reqwest client
    let client = Client::new();

    // Read the file data
    if let Ok(mut file) = File::open(&file_path) {
        let mut file_data = Vec::new();
        if file.read_to_end(&mut file_data).is_ok() {
            // Create a reqwest Form with the file
            let form = Form::new()
                .part(
                    file_name.clone(),
                    reqwest::blocking::multipart::Part::bytes(file_data)
                        .file_name(file_name.clone())
                        .mime_str("text/csv")
                        .unwrap(),
                );

            // Send the POST request to the server's upload_file endpoint
            if let Ok(response) = client
                .post("http://localhost:8080/upload_file")
                .multipart(form)
                .send()
            {
                // Check the server response
                if response.status().is_success() {
                    // Remove the file after successful upload
                    if let Err(err) = std::fs::remove_file(&file_path) {
                        eprintln!("Failed to remove the local file: {}", err);
                    }
                    UploadResult::Success
                } else {
                    UploadResult::Failure(format!(
                        "File upload failed with status: {:?} for file: {}",
                        response.status(),
                        file_name
                    ))
                }
            } else {
                UploadResult::Failure("Failed to send the file".to_string())
            }
        } else {
            UploadResult::Failure("Failed to read the file".to_string())
        }
    } else {
        UploadResult::Failure("Failed to open the file".to_string())
    }
}

fn verify_hash_using_proof(merkle_proof: &[(String, String)], hash_to_verify: &str) -> bool {
    let mut hash = hash_to_verify.to_string();
    
    for (proof_position, sibling_hash) in merkle_proof {
        if proof_position == "left" {
            hash = hash_data(&format!("{}{}", sibling_hash, hash));
        } else {
            hash = hash_data(&format!("{}{}", hash, sibling_hash));
        }
    }
    
    let last_hash = merkle_proof.last().map(|(_, hash)| hash.to_string()).unwrap_or(hash_to_verify.to_string());
    
    let verification_result = hash == last_hash;
    verification_result
}


fn main() -> Result<(), IoError> {
    let directory_path = "channel";

    let mut content_hashes: Vec<String> = Vec::new();

    let files_to_send = scan_directory_for_files(directory_path);

    if files_to_send.is_empty() {
        println!("No files to send.");
    } else {
        for file_name in &files_to_send {
            let file_path = format!("{}/{}", directory_path, file_name);

            // Hash the file content and add it to content_hashes
            let content_hash = hash_content(&file_path).unwrap();

            content_hashes.push(content_hash);

            // Upload the file and handle the result
            match upload_file(&file_path) {
                UploadResult::Success => {
                    println!("File uploaded successfully: {}", file_name);
                }
                UploadResult::Failure(error_message) => {
                    println!("File upload failed: {}", error_message);
                }
            }
        }

        println!("Content Hashes: {:?}", content_hashes);

        // Generate the Merkle Tree from content_hashes
        let merkle_tree_new = MerkleTree::new(content_hashes.clone());
        println!("Merkle Tree: {:?}", merkle_tree_new);

        // Choose an index to verify (0 in this case)
        let index_to_verify = 2;

        // Generate the Merkle proof for the specified index_to_verify
        if let Some(merkle_proof) = merkle_tree_new.generate_merkle_proof(index_to_verify) {
            println!("Merkle Proof: {:?}", merkle_proof);

            // Verify the hash using the Merkle proof
            let verified = verify_hash_using_proof(&merkle_proof, &content_hashes[index_to_verify]);
            if verified {
                println!("Hash verification successful.");
            } else {
                println!("Hash verification failed.");
            }
        } else {
            println!("No Merkle proof generated.");
        }
    }

    Ok(())
}
