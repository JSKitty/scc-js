import { BigNumber } from "big-integer";

export type TransactionOutput = {
  value: BigNumber;
  script: number[];
};
