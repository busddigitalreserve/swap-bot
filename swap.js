const { ethers } = require("ethers");
const config = require("./config");
const ABI = require("./routerABI.json");

const provider = new ethers.JsonRpcProvider(config.RPC_URL);
const router = new ethers.Contract(config.ROUTER.address, ABI, provider);

async function performSwap(privateKey, direction, amountIn) {
  const wallet = new ethers.Wallet(privateKey, provider);
  const signer = wallet.connect(provider);

  const tokenIn = direction === "buy" ? config.USDT : config.TOKEN;
  const tokenOut = direction === "buy" ? config.TOKEN : config.USDT;

  const tokenInContract = new ethers.Contract(tokenIn.address, [
    "function approve(address spender, uint amount) public returns(bool)",
    "function allowance(address owner, address spender) public view returns(uint)",
  ], signer);

  const amount = ethers.parseUnits(amountIn.toString(), tokenIn.decimals);

  const allowance = await tokenInContract.allowance(wallet.address, config.ROUTER.address);
  if (allowance < amount) {
    const tx = await tokenInContract.approve(config.ROUTER.address, ethers.MaxUint256);
    await tx.wait();
  }

  const path = [tokenIn.address, tokenOut.address];
  const deadline = Math.floor(Date.now() / 1000) + 600;

  try {
    const tx = await router.connect(signer).swapExactTokensForTokensSupportingFeeOnTransferTokens(
      amount, 0, path, wallet.address, deadline, { gasLimit: 300000 }
    );
    await tx.wait();
    console.log(`✅ [${wallet.address}] ${direction} ${amountIn} swap başarılı.`);
  } catch (err) {
    console.log(`❌ [${wallet.address}] HATA: ${err.message}`);
  }
}

module.exports = performSwap;