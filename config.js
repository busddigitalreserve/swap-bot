module.exports = {
  RPC_URL: process.env.RPC_URL,
  PRIVATE_KEYS: [
    process.env.PK1, process.env.PK2, process.env.PK3,
    process.env.PK4, process.env.PK5, process.env.PK6,
    process.env.PK7, process.env.PK8, process.env.PK9,
  ],
  TOKEN: {
    address: "0x6e50c5531b9193133a8dc6147c839ffbc86fe878",
    decimals: 18,
  },
  USDT: {
    address: "0x55d398326f99059ff775485246999027b3197955",
    decimals: 18,
  },
  ROUTER: {
    address: "0x10ED43C718714eb63d5aA57B78B54704E256024E",
  },
  AMOUNTS: [0.75, 1.25, 2.0, 1.0, 1.5, 0.5, 1.75, 1.0, 2.0, 0.8, 1.4, 1.9, 0.6, 1.3, 0.9]
};