// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IIdentityVerificationHubV2} from "../interfaces/IIdentityVerificationHubV2.sol";
import {ISelfVerificationRoot} from "../interfaces/ISelfVerificationRoot.sol";
import {CircuitConstantsV2} from "../constants/CircuitConstantsV2.sol";
import {AttestationId} from "../constants/AttestationId.sol";

/**
 * @title SelfVerificationRoot
 * @notice Abstract base contract to be integrated with self's verification infrastructure
 * @dev Provides base functionality for verifying and disclosing identity credentials
 * @author Self Team
 */
abstract contract SelfVerificationRoot is ISelfVerificationRoot {
    // ====================================================
    // Constants
    // ====================================================

    /// @notice Contract version identifier used in verification process
    /// @dev This version is included in the hub data for protocol compatibility
    uint8 constant CONTRACT_VERSION = 2;

    // ====================================================
    // Storage Variables
    // ====================================================

    /// @notice The scope value that proofs must match
    /// @dev Used to validate that submitted proofs match the expected scope
    uint256 internal _scope;

    /// @notice Reference to the identity verification hub V2 contract
    /// @dev Immutable reference used for bytes-based proof verification
    IIdentityVerificationHubV2 internal immutable _identityVerificationHubV2;

    // ====================================================
    // Circuit Constants
    // ====================================================

    // Make CircuitConstants available to inheriting contracts
    uint256 internal constant REVEALED_DATA_PACKED_INDEX = CircuitConstants.VC_AND_DISCLOSE_REVEALED_DATA_PACKED_INDEX;
    uint256 internal constant FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX =
        CircuitConstants.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX;
    uint256 internal constant NULLIFIER_INDEX = CircuitConstants.VC_AND_DISCLOSE_NULLIFIER_INDEX;
    uint256 internal constant ATTESTATION_ID_INDEX = CircuitConstants.VC_AND_DISCLOSE_ATTESTATION_ID_INDEX;
    uint256 internal constant MERKLE_ROOT_INDEX = CircuitConstants.VC_AND_DISCLOSE_MERKLE_ROOT_INDEX;
    uint256 internal constant CURRENT_DATE_INDEX = CircuitConstants.VC_AND_DISCLOSE_CURRENT_DATE_INDEX;
    uint256 internal constant PASSPORT_NO_SMT_ROOT_INDEX = CircuitConstants.VC_AND_DISCLOSE_PASSPORT_NO_SMT_ROOT_INDEX;
    uint256 internal constant NAME_DOB_SMT_ROOT_INDEX = CircuitConstants.VC_AND_DISCLOSE_NAME_DOB_SMT_ROOT_INDEX;
    uint256 internal constant NAME_YOB_SMT_ROOT_INDEX = CircuitConstants.VC_AND_DISCLOSE_NAME_YOB_SMT_ROOT_INDEX;
    uint256 internal constant SCOPE_INDEX = CircuitConstants.VC_AND_DISCLOSE_SCOPE_INDEX;
    uint256 internal constant USER_IDENTIFIER_INDEX = CircuitConstants.VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX;

    // ====================================================
    // Attestation ID
    // ====================================================

    bytes32 constant E_PASSPORT_ID = AttestationId.E_PASSPORT;

    // ====================================================
    // Errors
    // ====================================================

    /// @notice Error thrown when the data format is invalid
    /// @dev Triggered when the provided bytes data doesn't have the expected format
    error InvalidDataFormat();

    /// @notice Error thrown when onVerificationSuccess is called by an unauthorized address
    /// @dev Only the identity verification hub V2 contract can call onVerificationSuccess
    error UnauthorizedCaller();

    // ====================================================
    // Events
    // ====================================================

    /// @notice Emitted when the scope is updated
    /// @param newScope The new scope value that was set
    event ScopeUpdated(uint256 indexed newScope);

    // ====================================================
    // Events
    // ====================================================

    /// @notice Emitted when the verification configuration is updated
    event VerificationConfigUpdated(ISelfVerificationRoot.VerificationConfig indexed verificationConfig);

    /// @notice Emitted when the verification is successful
    event VerificationSuccess(uint256[3] revealedDataPacked, uint256 indexed userIdentifier, uint256 indexed nullifier);

    /// @notice Emitted when the scope is updated
    event ScopeUpdated(uint256 indexed newScope);

    /// @notice Emitted when a new attestation ID is added
    event AttestationIdAdded(uint256 indexed attestationId);

    /// @notice Emitted when an attestation ID is removed
    event AttestationIdRemoved(uint256 indexed attestationId);

    /**
     * @notice Initializes the SelfVerificationRoot contract
     * @dev Sets up the immutable reference to the hub contract and initial scope
     * @param identityVerificationHubV2Address The address of the Identity Verification Hub V2
     * @param scopeValue The expected proof scope for user registration
     */
    constructor(address identityVerificationHubV2Address, uint256 scopeValue) {
        _identityVerificationHubV2 = IIdentityVerificationHubV2(identityVerificationHubV2Address);
        _scope = scopeValue;
    }

    /**
     * @notice Returns the current scope value
     * @dev Public view function to access the current scope setting
     * @return The scope value that proofs must match
     */
    function scope() public view returns (uint256) {
        return _scope;
    }

    /**
     * @notice Updates the scope value
     * @dev Protected internal function to change the expected scope for proofs
     * @param newScope The new scope value to set
     */
    function _setScope(uint256 newScope) internal {
        _scope = newScope;
        emit ScopeUpdated(newScope);
    }

    /**
     * @notice Verifies a self-proof using the bytes-based interface
     * @dev Parses relayer data format and validates against contract settings before calling hub V2
     * @param proofPayload Packed data from relayer in format: | 32 bytes attestationId | proof data |
     * @param userContextData User-defined data in format: | 32 bytes destChainId | 32 bytes userIdentifier | data |
     * @custom:data-format proofPayload = | 32 bytes attestationId | proofData |
     * @custom:data-format userContextData = | 32 bytes destChainId | 32 bytes userIdentifier | data |
     * @custom:data-format hubData = | 1 bytes contract version | 31 bytes buffer | 32 bytes scope | 32 bytes attestationId | proofData |
     */
    function verifySelfProof(bytes calldata proofPayload, bytes calldata userContextData) public {
        // Minimum expected length for proofData: 32 bytes attestationId + proof data
        if (proofPayload.length < 32) {
            revert InvalidDataFormat();
        }

        // Minimum userDefinedData length: 32 (destChainId) + 32 (userIdentifier) + 0 (userDefinedData) = 64 bytes
        if (userContextData.length < 64) {
            revert InvalidDataFormat();
        }

        bytes32 attestationId;
        assembly {
            // Load attestationId from the beginning of proofData (first 32 bytes)
            attestationId := calldataload(proofPayload.offset)
        }

        bytes32 destinationChainId = bytes32(userContextData[0:32]);
        bytes32 userIdentifier = bytes32(userContextData[32:64]);
        bytes memory userDefinedData = userContextData[64:];

        bytes32 configId = getConfigId(destinationChainId, userIdentifier, userDefinedData);

        // Hub data should be | 1 byte contractVersion | 31 bytes buffer | 32 bytes scope | 32 bytes attestationId | proof data
        bytes memory baseVerificationInput = abi.encodePacked(
            // 1 byte contractVersion
            CONTRACT_VERSION,
            // 31 bytes buffer (all zeros)
            bytes31(0),
            // 32 bytes scope
            _scope,
            // 32 bytes attestationId
            attestationId,
            // proof data (starts after 32 bytes attestationId)
            proofPayload[32:]
        );

        // Call hub V2 verification
        _identityVerificationHubV2.verify(baseVerificationInput, bytes.concat(configId, userContextData));
    }

    /**
     * @notice Callback function called upon successful verification by the hub contract
     * @dev Only callable by the identity verification hub V2 contract for security
     * @param output The verification output data containing disclosed identity information
     * @param userData The user-defined data passed through the verification process
     * @custom:security Only the authorized hub contract can call this function
     * @custom:flow This function decodes the output and calls the customizable verification hook
     */
    function onVerificationSuccess(bytes memory output, bytes memory userData) public {
        // Only allow the identity verification hub V2 to call this function
        if (msg.sender != address(_identityVerificationHubV2)) {
            revert UnauthorizedCaller();
        }

        ISelfVerificationRoot.GenericDiscloseOutputV2 memory genericDiscloseOutput = abi.decode(
            output,
            (ISelfVerificationRoot.GenericDiscloseOutputV2)
        );

        // Call the customizable verification hook
        customVerificationHook(genericDiscloseOutput, userData);
    }

    /**
     * @notice Generates a configId for the user
     * @dev This function should be overridden by the implementing contract to provide custom configId logic
     * @param destinationChainId The destination chain ID
     * @param userIdentifier The user identifier
     * @param userDefinedData The user defined data
     * @return The configId
     */
    function getConfigId(
        bytes32 destinationChainId,
        bytes32 userIdentifier,
        bytes memory userDefinedData
    ) public view virtual returns (bytes32) {
        // Default implementation reverts; must be overridden in derived contract
        revert("SelfVerificationRoot: getConfigId must be overridden");
    }

    /**
     * @notice Custom verification hook that can be overridden by implementing contracts
     * @dev This function is called after successful verification and hub address validation
     * @param output The verification output data from the hub containing disclosed identity information
     * @param userData The user-defined data passed through the verification process
     * @custom:override Override this function in derived contracts to add custom verification logic
     * @custom:security This function is only called after proper authentication by the hub contract
     */
    function customVerificationHook(
        ISelfVerificationRoot.GenericDiscloseOutputV2 memory output,
        bytes memory userData
    ) internal virtual {
        // Default implementation is empty - override in derived contracts to add custom logic
    }
}
