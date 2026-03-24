/** 1 TRX = 1e6 SUN */
export const SUN = 1_000_000;

/** keccak256("transfer(address,uint256)").slice(0, 4) — TRC20 same as ERC-20 */
export const SEL_TRANSFER = "a9059cbb";

/** keccak256("transferFrom(address,address,uint256)").slice(0, 4) */
export const SEL_TRANSFER_FROM = "23b872dd";
