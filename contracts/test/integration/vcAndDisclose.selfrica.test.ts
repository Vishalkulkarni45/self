import { expect } from "chai";
import { deploySystemFixtures } from "../utils/deployment";
import { DeployedActors } from "../utils/types";
import { ethers } from "hardhat";
import { ATTESTATION_ID } from "../utils/constants";
import { LeanIMT } from "@openpassport/zk-kit-lean-imt";
import { poseidon2 } from "poseidon-lite";
import { generateCommitment } from "../../../common/src/utils/passports/passport";
import { generateRandomFieldElement, getStartOfDayTimestamp, splitHexFromBack } from "../utils/utils";
import { getPackedForbiddenCountries } from "../../../common/src/utils/contracts/forbiddenCountries";
import { countries } from "../../../common/src/constants/countries";
import type { SelfricaCircuitInput } from "../../../common/src/utils/selfrica/types";

describe("VC and Disclose", () => {
  let deployedActors: DeployedActors;
  let snapshotId: string;
  let baseVcAndDiscloseProofInput: any;
  let vcAndDiscloseProof: any;
  let registerSecret: any;
  let imt: any;
  let commitment: any;
  let nullifier: any;

  let forbiddenCountriesList: string[];
  let invalidForbiddenCountriesList: string[];
  let forbiddenCountriesListPacked: string[];
  let invalidForbiddenCountriesListPacked: string[];

  before(async () => {
    deployedActors = await deploySystemFixtures();
    registerSecret = generateRandomFieldElement();
    nullifier = generateRandomFieldElement();
    commitment = generateCommitment(registerSecret, ATTESTATION_ID.E_PASSPORT, deployedActors.mockPassport);

    await deployedActors.registry
      .connect(deployedActors.owner)
      .devAddIdentityCommitment(ATTESTATION_ID.E_PASSPORT, nullifier, commitment);

    const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
    imt = new LeanIMT<bigint>(hashFunction);
    await imt.insert(BigInt(commitment));

    invalidForbiddenCountriesList = ["AAA", "ABC", "CBA", "CBA"];
    // const invalidWholePacked = reverseBytes(Formatter.bytesToHexString(new Uint8Array(formatCountriesList(invalidForbiddenCountriesList))));
    // invalidForbiddenCountriesListPacked = splitHexFromBack(invalidWholePacked);
    invalidForbiddenCountriesListPacked = getPackedForbiddenCountries(invalidForbiddenCountriesList);

    //   baseVcAndDiscloseProof = await generateVcAndDiscloseProof(
    //     registerSecret,
    //     BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
    //     deployedActors.mockPassport,
    //     "test-scope",
    //     new Array(88).fill("1"),
    //     "1",
    //     imt,
    //     "20",
    //     undefined,
    //     undefined,
    //     undefined,
    //     undefined,
    //     forbiddenCountriesList,
    //     (await deployedActors.user1.getAddress()).slice(2),
    //   );
    //   snapshotId = await ethers.provider.send("evm_snapshot", []);
    // });

    baseVcAndDiscloseProofInput = beforeEach(async () => {
      vcAndDiscloseProof = structuredClone(baseVcAndDiscloseProof);
    });

    afterEach(async () => {
      await ethers.provider.send("evm_revert", [snapshotId]);
      snapshotId = await ethers.provider.send("evm_snapshot", []);
    });
  });
});
