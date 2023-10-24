# Merkle Tree/Proof Client
a client that uploads a file to a server, constructs a Merkle Tree out of the content of the files, and removes the files from the local folder. 
before uploading the files, it generates a Merkle Proof to check the completeness of the file later.

it uses sha256 as a hashing algorithm and customized structs for the Merkle Tree construction.
