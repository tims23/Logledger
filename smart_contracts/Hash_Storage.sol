// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract HashStorage {
    // struct for batch processing

    address private owner;
    bytes32[] private numberedHashes;

    // Modifier to restrict functions to the owner
    modifier onlyOwner() {
        require(msg.sender == owner, "You are not the owner");
        _;
    }

    // Constructor sets the deployer as the owner
    constructor() {
        owner = msg.sender;
    }

    // Batch add hashes 
    function addHash(bytes32[] calldata _hashes) external onlyOwner {
        for (uint256 i = 0; i < _hashes.length; i++) {
            bytes32 hashEntry = _hashes[i]; // Use calldata to avoid extra memory copying

            // Associate the number with the hash
            numberedHashes.push(hashEntry);
        }
    }

    // iteratively check if a hash exists 
    function isHashIncluded(bytes32 hash) external view returns (bool) {
        for (uint256 i = 1; i <= type(uint256).max; i++) {
            if (numberedHashes[i] == hash) {
                return true;
            }
        }
        return false;
    }

    // Function to retrieve a hash by index
    function getHashByIndex(uint256 index) external view returns (bytes32) {
        require(index < numberedHashes.length, "Index out of bounds");
        return numberedHashes[index];
    }

    // Function to get the total count of hashes (optional)
    function getHashCount() external view returns (uint256) {
        return numberedHashes.length;
    }
}