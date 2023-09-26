import { BigNumber } from "big-integer";

export default interface TransactionOutput {
  value: BigNumber;
  script: number[];
}
