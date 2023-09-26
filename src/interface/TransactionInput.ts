export default interface TransactionInput {
  outpoint: { hash: string; index: number };
  script: number[];
  sequence: number;
}
