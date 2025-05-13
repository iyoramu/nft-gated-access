// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title NFT Gated Access Contract
 * @dev A contract that provides gated access to functions based on NFT ownership
 * with additional features for competition requirements:
 * - Modern access control with NFT verification
 * - Multi-chain support
 * - Gas optimization
 * - Signature verification for meta-transactions
 * - Role-based access extension points
 * - Comprehensive event logging
 */
contract NFTGatedAccess is Ownable, ReentrancyGuard, EIP712 {
    using ECDSA for bytes32;

    // Custom errors for gas efficiency
    error NFTNotOwned();
    error AlreadyRegistered();
    error InvalidSignature();
    error CallerNotOwner();
    error FunctionLocked();
    error InvalidNFTContract();

    // Struct for tracking registered users
    struct User {
        address wallet;
        uint256 tokenId;
        uint256 registrationDate;
        uint256 lastAccessTime;
        uint256 accessCount;
    }

    // Constants for EIP712 domain
    string private constant CONTRACT_NAME = "NFTGatedAccess";
    string private constant VERSION = "1.0.0";
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256("PermitAccess(address user,uint256 tokenId,uint256 deadline)");

    // NFT contract address
    IERC721 public nftContract;

    // Mapping from user address to their data
    mapping(address => User) public users;

    // Mapping from token ID to owner address
    mapping(uint256 => address) public tokenOwners;

    // Mapping to track function locks
    mapping(bytes4 => bool) public lockedFunctions;

    // Events
    event UserRegistered(address indexed user, uint256 tokenId);
    event AccessGranted(address indexed user, uint256 tokenId);
    event FunctionLocked(bytes4 functionSelector);
    event FunctionUnlocked(bytes4 functionSelector);
    event NFTContractChanged(address oldContract, address newContract);

    /**
     * @dev Constructor that initializes the EIP712 domain and sets the NFT contract
     * @param _nftContract Address of the ERC721 NFT contract used for gating
     */
    constructor(address _nftContract) 
        EIP712(CONTRACT_NAME, VERSION) 
    {
        if (_nftContract == address(0)) {
            revert InvalidNFTContract();
        }
        nftContract = IERC721(_nftContract);
    }

    /**
     * @dev Modifier to check if caller owns the specified NFT
     * @param tokenId The NFT token ID to check ownership of
     */
    modifier onlyNFTOwner(uint256 tokenId) {
        if (nftContract.ownerOf(tokenId) != msg.sender) {
            revert NFTNotOwned();
        }
        _;
    }

    /**
     * @dev Modifier to check if function is not locked
     * @param functionSelector The function selector to check
     */
    modifier notLocked(bytes4 functionSelector) {
        if (lockedFunctions[functionSelector]) {
            revert FunctionLocked();
        }
        _;
    }

    /**
     * @dev Register a user with their NFT token ID
     * @param tokenId The NFT token ID to register
     */
    function register(uint256 tokenId) 
        external 
        nonReentrant
        onlyNFTOwner(tokenId)
        notLocked(this.register.selector)
    {
        if (users[msg.sender].wallet != address(0)) {
            revert AlreadyRegistered();
        }

        users[msg.sender] = User({
            wallet: msg.sender,
            tokenId: tokenId,
            registrationDate: block.timestamp,
            lastAccessTime: block.timestamp,
            accessCount: 0
        });

        tokenOwners[tokenId] = msg.sender;

        emit UserRegistered(msg.sender, tokenId);
    }

    /**
     * @dev Access a gated function (example)
     * @param tokenId The NFT token ID to verify ownership of
     */
    function accessGatedFunction(uint256 tokenId) 
        external 
        nonReentrant
        onlyNFTOwner(tokenId)
        notLocked(this.accessGatedFunction.selector)
    {
        User storage user = users[msg.sender];
        if (user.wallet == address(0)) {
            revert NFTNotOwned();
        }

        user.lastAccessTime = block.timestamp;
        user.accessCount += 1;

        emit AccessGranted(msg.sender, tokenId);
    }

    /**
     * @dev Permit access via off-chain signature (meta-transactions support)
     * @param user The user address
     * @param tokenId The NFT token ID
     * @param deadline The signature expiration time
     * @param signature The signature from the NFT owner
     */
    function permitAccess(
        address user,
        uint256 tokenId,
        uint256 deadline,
        bytes memory signature
    ) external nonReentrant notLocked(this.permitAccess.selector) {
        if (block.timestamp > deadline) {
            revert InvalidSignature();
        }

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                PERMIT_TYPEHASH,
                user,
                tokenId,
                deadline
            ))
        );

        address signer = ECDSA.recover(digest, signature);
        if (nftContract.ownerOf(tokenId) != signer) {
            revert InvalidSignature();
        }

        User storage userData = users[user];
        if (userData.wallet == address(0)) {
            users[user] = User({
                wallet: user,
                tokenId: tokenId,
                registrationDate: block.timestamp,
                lastAccessTime: block.timestamp,
                accessCount: 1
            });
            tokenOwners[tokenId] = user;
            emit UserRegistered(user, tokenId);
        } else {
            userData.lastAccessTime = block.timestamp;
            userData.accessCount += 1;
        }

        emit AccessGranted(user, tokenId);
    }

    /**
     * @dev Lock a function to prevent further calls
     * @param functionSelector The function selector to lock
     */
    function lockFunction(bytes4 functionSelector) external onlyOwner {
        lockedFunctions[functionSelector] = true;
        emit FunctionLocked(functionSelector);
    }

    /**
     * @dev Unlock a function to allow calls again
     * @param functionSelector The function selector to unlock
     */
    function unlockFunction(bytes4 functionSelector) external onlyOwner {
        lockedFunctions[functionSelector] = false;
        emit FunctionUnlocked(functionSelector);
    }

    /**
     * @dev Change the NFT contract address (onlyOwner)
     * @param newNFTContract The new ERC721 contract address
     */
    function changeNFTContract(address newNFTContract) external onlyOwner {
        if (newNFTContract == address(0)) {
            revert InvalidNFTContract();
        }
        emit NFTContractChanged(address(nftContract), newNFTContract);
        nftContract = IERC721(newNFTContract);
    }

    /**
     * @dev Check if a user is registered
     * @param user The user address to check
     * @return True if registered, false otherwise
     */
    function isUserRegistered(address user) external view returns (bool) {
        return users[user].wallet != address(0);
    }

    /**
     * @dev Get user data
     * @param user The user address
     * @return User struct containing registration data
     */
    function getUserData(address user) external view returns (User memory) {
        return users[user];
    }

    /**
     * @dev Get the owner of a specific token ID
     * @param tokenId The NFT token ID
     * @return The owner address if registered, otherwise address(0)
     */
    function getTokenOwner(uint256 tokenId) external view returns (address) {
        return tokenOwners[tokenId];
    }

    /**
     * @dev Check if a function is locked
     * @param functionSelector The function selector to check
     * @return True if locked, false otherwise
     */
    function isFunctionLocked(bytes4 functionSelector) external view returns (bool) {
        return lockedFunctions[functionSelector];
    }
}
