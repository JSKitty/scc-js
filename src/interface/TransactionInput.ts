export type TransactionInput = {
  outpoint: { hash: string; index: number };
  script: number[];
  sequence: number;
};
