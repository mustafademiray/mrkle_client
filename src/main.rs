use reqwest::blocking::Client;
use reqwest::blocking::multipart::Form;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Error as IoError, Result as IoResult};
use std::path::Path;
use std::fs;
use std::string::String;

enum UploadResult {
    Success,
    Failure(String),
}

#[derive(Debug, Clone)]
struct MerkleNode {
    hash: String,
    left: Option<Box<MerkleNode>>,
    right: Option<Box<MerkleNode>>,
}



impl MerkleNode {
    fn new(data: &str) -> MerkleNode {
        let hash = data.to_string();
        MerkleNode {
            hash,
            left: None,
            right: None,
        }
    }

    fn combine(left: MerkleNode, right: MerkleNode) -> MerkleNode {
        let combined_hash = hash_data(&format!("{}{}", left.hash, right.hash));
        MerkleNode {
            hash: combined_hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }
}


struct MerkleTree {
    root: Option<Box<MerkleNode>>,
}


impl MerkleTree {
    fn new(data: Vec<String>) -> MerkleTree {
        let root = MerkleTree::generate_merkle_tree(&data);
        MerkleTree { root }
    }

    fn generate_merkle_tree(data: &[String]) -> Option<Box<MerkleNode>> {
        let leaf_nodes: Vec<MerkleNode> = data.iter().map(|hash| MerkleNode::new(hash)).collect();

        let mut nodes: Vec<MerkleNode> = leaf_nodes.clone();

        while nodes.len() > 1 {
            let mut new_nodes = Vec::new();
            for i in (0..nodes.len()).step_by(2) {
                let left = nodes[i].clone();
                let right = if i + 1 < nodes.len() {
                    nodes[i + 1].clone()
                } else {
                    left.clone()
                };
                new_nodes.push(MerkleNode::combine(left, right));
            }
            nodes = new_nodes;
        }

        if let Some(root) = nodes.pop() {
            Some(Box::new(root))
        } else {
            None
        }
    }
}

fn hash_data(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}


fn generate_merkle_tree(data: &Vec<String>) -> MerkleNode {
    // Create leaf nodes from the data
    let leaf_nodes: Vec<MerkleNode> = data.iter().map(|hash| MerkleNode::new(hash)).collect();

    // Build the Merkle Tree by combining nodes
    let mut nodes: Vec<MerkleNode> = leaf_nodes.clone();

    while nodes.len() > 1 {
        let mut new_nodes = Vec::new();
        for i in (0..nodes.len()).step_by(2) {
            let left = nodes[i].clone();
            let right = if i + 1 < nodes.len() {
                nodes[i + 1].clone()
            } else {
                left.clone() // For an odd number of nodes, duplicate the last node as the right child
            };
            new_nodes.push(MerkleNode::combine(left, right));
        }
        nodes = new_nodes;
    }

    nodes[0].clone() // Return the root of the Merkle Tree
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

fn generate_merkle_proof(merkle_tree: &MerkleTree, index_to_verify: usize) -> Option<Vec<(String, String)>> {
    let mut proof: Vec<(String, String)> = Vec::new();
    
    let mut current = &merkle_tree.root;
    let mut index = index_to_verify;
    
    while index > 0 {
        // Determine the parent index
        let parent_index = (index - 1) / 2;
        
        // Use pattern matching to get the child node
        let parent_node = match &current {
            Some(node) => {
                if parent_index % 2 == 0 {
                    // The node is the left child of the parent
                    &node.left
                } else {
                    // The node is the right child of the parent
                    &node.right
                }
            }
            None => return None, // Proof generation failed
        };
        
        if parent_index % 2 == 0 {
            if let Some(node) = &parent_node {
                proof.push(("right".to_string(), node.hash.clone()));
            } else {
                return None; // Proof generation failed
            }
        } else {
            if let Some(node) = &parent_node {
                proof.push(("left".to_string(), node.hash.clone()));
            } else {
                return None; // Proof generation failed
            }
        }
        
        current = parent_node; // Move up one level
        index = parent_index; // Update the current index
    }
    
    Some(proof)
}



fn verify_hash_using_proof(merkle_proof: &[(String, String)], hash_to_verify: &str) -> bool {
    let mut hash = hash_to_verify.to_string();
    let mut position = "right"; // Initialize the position as "right".

    for (proof_position, sibling_hash) in merkle_proof {
        println!("Position: {}, Sibling Hash: {}, Current Hash: {}", position, sibling_hash, hash);
        if proof_position == "left" {
            hash = hash_data(&format!("{}{}", sibling_hash, hash));
            position = "left";
        } else {
            hash = hash_data(&format!("{}{}", hash, sibling_hash));
            position = "right";
        }
        println!("Updated Hash: {}", hash);
    }

    let last_hash = merkle_proof.last().map(|(_, hash)| hash.to_string()).unwrap_or(hash_to_verify.to_string());
    println!("Last Hash: {}", last_hash);

    let verification_result = hash == last_hash;
    println!("Verification Result: {}", verification_result);

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
        let root = generate_merkle_tree(&content_hashes);
        println!("Root Hash: {}", root.hash);



        ///NEW MERKLE TREE
        let merkle_tree_new = MerkleTree::new(content_hashes.clone());

        // Choose an index to verify (0 in this case)
        let index_to_verify = 2;
        println!("Root: {:?}", root);
        // Generate the Merkle proof for the specified index_to_verify
        if let Some(merkle_proof) = generate_merkle_proof(&merkle_tree_new, index_to_verify) {
            println!("Merkle Proof: {:?}", merkle_proof);

            // Verify the hash using the Merkle proof
            let verified = verify_hash_using_proof(&merkle_proof, &content_hashes[index_to_verify]);
            //println!("Is verified: {:?}", verified);
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
