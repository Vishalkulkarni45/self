// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title IIdentityRegistrySelfricaV1
 * @notice Interface for the Identity Registry Selfrica v1.
 * @dev This interface exposes only the external functions accessible by regular callers,
 *      i.e. functions that are not owner-restricted.
 */
interface IIdentityRegistrySelfricaV1 {
    /**
     * @notice Retrieves the address of the registered identity verification hub.
     * @return The address of the hub.
     */
    function hub() external view returns (address);

    /**
     * @notice Retrieves the public keys for Selfrica.
     * @return The public keys for Selfrica.
     */
    function getPubkeys() external view returns (uint256, uint256);

    /**
     * @notice Retrieves the current name and date of birth OFAC root.
     * @return The current name and date of birth OFAC root value.
     */
    function getNameAndDobOfacRoot() external view returns (uint256);

    /**
     * @notice Retrieves the current name and year of birth OFAC root.
     * @return The current name and year of birth OFAC root value.
     */
    function getNameAndYobOfacRoot() external view returns (uint256);

    /**
     * @notice Checks if the provided OFAC roots match the stored OFAC roots.
     * @param nameAndDobRoot The name and date of birth OFAC root to verify.
     * @param nameAndYobRoot The name and year of birth OFAC root to verify.
     * @return True if all provided roots match the stored values, false otherwise.
     */
    function checkOfacRoots(uint256 nameAndDobRoot, uint256 nameAndYobRoot) external view returns (bool);
}
