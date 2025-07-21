// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IIdentityRegistrySelfricaV1} from "../interfaces/IIdentityRegistrySelfricaV1.sol";
import {ImplRoot} from "../upgradeable/ImplRoot.sol";
/**
 * @notice ⚠️ CRITICAL STORAGE LAYOUT WARNING ⚠️
 * =============================================
 *
 * This contract uses the UUPS upgradeable pattern which makes storage layout EXTREMELY SENSITIVE.
 *
 * 🚫 NEVER MODIFY OR REORDER existing storage variables
 * 🚫 NEVER INSERT new variables between existing ones
 * 🚫 NEVER CHANGE THE TYPE of existing variables
 *
 * ✅ New storage variables MUST be added in one of these two ways ONLY:
 *    1. At the END of the storage layout
 *    2. In a new V2 contract that inherits from this V1
 * ✅ It is safe to rename variables (e.g., changing 'variable' to 'oldVariable')
 *    as long as the type and order remain the same
 *
 * For more detailed information about forbidden changes, please refer to:
 * https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable#modifying-your-contracts
 *
 * ⚠️ VIOLATION OF THESE RULES WILL CAUSE CATASTROPHIC STORAGE COLLISIONS IN FUTURE UPGRADES ⚠️
 * =============================================
*/

/**
 * @title IdentityRegistrySelfricaStorageV1
 * @dev Abstract contract for storage layout of IdentityRegistrySelfricaImplV1.
 * Inherits from ImplRoot to provide upgradeable functionality.
 */
abstract contract IdentityRegistrySelfricaStorageV1 is ImplRoot {
    // =============================================
    // Storage Variables
    // =============================================

    /// @notice Address of the identity verification hub.
    address internal _hub;

    /// @notice Merkle tree data structure for identity commitments.
    LeanIMTData internal _identityCommitmentIMT;

    /// @notice X coordinate of the public key for Selfrica.
    uint256 internal _pubkeyX;

    /// @notice Y coordinate of the public key for Selfrica.
    uint256 internal _pubkeyY;

    /// @notice Current name and date of birth OFAC root.
    uint256 internal _nameAndDobOfacRoot;

    /// @notice Current name and year of birth OFAC root.
    uint256 internal _nameAndYobOfacRoot;
}

/**
 * @title IdentityRegistrySelfricaImplV1
 * @notice Provides functions to register and manage identity commitments using a Merkle tree structure.
 * @dev Inherits from IdentityRegistrySelfricaStorageV1 and implements IIdentityRegistrySelfricaV1.
 */
contract IdentityRegistrySelfricaImplV1 is IdentityRegistrySelfricaStorageV1, IIdentityRegistrySelfricaV1 {
    // ====================================================
    // Events
    // ====================================================

    /// @notice Emitted when the registry is initialized.
    event RegistryInitialized(address hub);
    /// @notice Emitted when the hub address is updated.
    event HubUpdated(address hub);

    /// @notice Emitted when the public key is updated.
    event PubkeyUpdated(uint256 pubkeyX, uint256 pubkeyY);
    /// @notice Emitted when the name and date of birth OFAC root is updated.
    event NameAndDobOfacRootUpdated(uint256 nameAndDobOfacRoot);
    /// @notice Emitted when the name and year of birth OFAC root is updated.
    event NameAndYobOfacRootUpdated(uint256 nameAndYobOfacRoot);

    // ====================================================
    // Errors
    // ====================================================

    /// @notice Thrown when the hub is not set.
    error HUB_NOT_SET();
    /// @notice Thrown when a function is accessed by an address other than the designated hub.
    error ONLY_HUB_CAN_ACCESS();

    // ====================================================
    // Modifiers
    // ====================================================

    /**
     * @notice Modifier to restrict access to functions to only the hub.
     * @dev Reverts if the hub is not set or if the caller is not the hub.
     */
    modifier onlyHub() {
        if (address(_hub) == address(0)) revert HUB_NOT_SET();
        if (msg.sender != address(_hub)) revert ONLY_HUB_CAN_ACCESS();
        _;
    }

    // ====================================================
    // Constructor
    // ====================================================

    /**
     * @notice Constructor that disables initializers.
     * @dev Prevents direct initialization of the implementation contract.
     */
    constructor() {
        _disableInitializers();
    }

    // ====================================================
    // Initializer
    // ====================================================

    /**
     * @notice Initializes the registry implementation.
     * @dev Sets the hub address and initializes the UUPS upgradeable feature.
     * @param _hub The address of the identity verification hub.
     */
    function initialize(address _hub) external initializer {
        __ImplRoot_init();
        _hub = _hub;
        emit RegistryInitialized(_hub);
    }

    // ====================================================
    // External Functions - View & Checks
    // ====================================================

    /**
     * @notice Retrieves the hub address.
     * @return The current identity verification hub address.
     */
    function hub() external view virtual onlyProxy returns (address) {
        return _hub;
    }

    /**
     * @notice Retrieves the public key for Selfrica.
     * @return The current public key for Selfrica.
     */
    function pubkey() external view virtual onlyProxy returns (uint256, uint256) {
        return (_pubkeyX, _pubkeyY);
    }

    /**
     * @notice Retrieves the name and date of birth OFAC root.
     * @return The current name and date of birth OFAC root.
     */
    function nameAndDobOfacRoot() external view virtual onlyProxy returns (uint256) {
        return _nameAndDobOfacRoot;
    }

    /**
     * @notice Retrieves the name and year of birth OFAC root.
     * @return The current name and year of birth OFAC root.
     */
    function nameAndYobOfacRoot() external view virtual onlyProxy returns (uint256) {
        return _nameAndYobOfacRoot;
    }

    // ====================================================
    // External Functions - Only Owner
    // ====================================================

    /**
     * @notice Updates the hub address.
     * @dev Callable only via a proxy and restricted to the contract owner.
     * @param newHubAddress The new address of the hub.
     */
    function updateHub(address newHubAddress) external onlyProxy onlyOwner {
        _hub = newHubAddress;
        emit HubUpdated(newHubAddress);
    }

    /**
     * @notice Updates the public key for Selfrica.
     */
    function updatePubkey(uint256 pubkeyX, uint256 pubkeyY) external virtual onlyOwner {
        _pubkeyX = pubkeyX;
        _pubkeyY = pubkeyY;
        emit PubkeyUpdated(pubkeyX, pubkeyY);
    }

    /**
     * @notice Updates the name and date of birth OFAC root.
     */
    function updateNameAndDobOfacRoot(uint256 nameAndDobOfacRoot) external virtual onlyOwner {
        _nameAndDobOfacRoot = nameAndDobOfacRoot;
        emit NameAndDobOfacRootUpdated(nameAndDobOfacRoot);
    }

    /**
     * @notice Updates the name and year of birth OFAC root.
     */
    function updateNameAndYobOfacRoot(uint256 nameAndYobOfacRoot) external virtual onlyOwner {
        _nameAndYobOfacRoot = nameAndYobOfacRoot;
        emit NameAndYobOfacRootUpdated(nameAndYobOfacRoot);
    }
}
