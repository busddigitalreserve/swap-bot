require("dotenv").config();
const config = require("./config");
const swap = require("./swap");

let index = 0;
let amountIndex = 0;

async function loopSwaps() {
  const key = config.PRIVATE_KEYS[index % config.PRIVATE_KEYS.length];
  const amount = config.AMOUNTS[amountIndex % config.AMOUNTS.length];
  const direction = (index % 2 === 0) ? "buy" : "sell";

  await swap(key, direction, amount);

  index++;
  amountIndex++;

  const delay = 1000 * 60 * 11; // her 11 dakikada bir işlem
  setTimeout(loopSwaps, delay);
}

loopSwaps();
