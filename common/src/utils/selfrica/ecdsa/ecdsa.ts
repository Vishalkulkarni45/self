import { poseidon2 } from "poseidon-lite";
import { getECDSAMessageHash, modInv, modulus } from "./utils.js";
import { addPoint, Base8, mulPointEscalar, Point, subOrder } from "@zk-kit/baby-jubjub";
import { Signature } from "../types.js";

//TODO: zk-kit/baby-jubjub uses affine which involses Fr.div which makes process slower , try to implement the function using PointProjective

export function signECDSA(key: bigint, msg: number[]): Signature {
    key = modulus(key, subOrder);
    const msgHash = getECDSAMessageHash(msg);
    // Deterministically generate the nonce k and reduce it modulo the subgroup order
    const k = modulus(poseidon2([msgHash, key]), subOrder);

    const R = mulPointEscalar(Base8, k);

    const kInv = modInv(k, subOrder);

    // Compute s = k_inv * (msg_hash + r * key) mod n
    const s = modulus(
        kInv * (msgHash + R[0] * key),
        subOrder
    );

    return { R, s };
}

export function verifyECDSA(msg: number[], sig: Signature, pk: Point<bigint>): boolean {
    const msgHash = getECDSAMessageHash(msg);

    const sInv = modInv(sig.s, subOrder);

    // u1 = msg_hash * s_inv mod n
    const u1 = modulus((msgHash * sInv), subOrder);
    // u2 = r * s_inv mod n
    const u2 = modulus(sig.R[0] * sInv, subOrder);

    // R = u1*G + u2*pk

    const u1G = mulPointEscalar(Base8, u1);
    const u2Pk = mulPointEscalar(pk, u2);
    let R = addPoint(u1G, u2Pk);

    return R[0] == sig.R[0]

}

export function verifyEffECDSA(s: bigint, T: Point<bigint>, U: Point<bigint>, pk: Point<bigint>): boolean {
    // Check if s*T + U == pk
    const sT = mulPointEscalar(T, s);
    const calPk = addPoint(sT, U);

    const xvalid = calPk[0] == pk[0]
    const yvalid = calPk[1] == pk[1]
    return xvalid && yvalid == true
}
