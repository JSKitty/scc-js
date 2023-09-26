import * as util from "./util";

export default class bitjs {
  public compressed = true;
  public static pub = (network: "MainNet" | "TestNet" = "MainNet") =>
    util.PUBKEY_ADDRESS[network].toString(16);

  public static script = (network: "MainNet" | "TestNet" = "MainNet") =>
    util.SCRIPT_ADDRESS[network].toString(16);

  public static priv = (network: "MainNet" | "TestNet" = "MainNet") =>
    util.SECRET_KEY[network].toString(16);

  public static numToBytes: (num: number, bytes: number) => Buffer = (
    num: number,
    bytes: number,
  ) => {
    if (typeof bytes === "undefined") bytes = 8;
    if (bytes == 0) {
      return Buffer.from([]);
    } else if (num == -1) {
      return Buffer.from("ffffffffffffffff", "hex");
    } else {
      return Buffer.from([
        num % 256,
        ...bitjs.numToBytes(Math.floor(num / 256), bytes - 1),
      ]);
    }
  };

  public static numToByteArray: (num: number) => Buffer = (num: number) => {
    if (num <= 256) {
      return Buffer.from([num]);
    } else {
      return Buffer.from([
        num % 256,
        ...bitjs.numToByteArray(Math.floor(num / 256)),
      ]);
    }
  };

  public static numToVarInt = (num: number) => {
    if (num < 253) {
      return Buffer.from([num]);
    } else if (num < 65536) {
      return Buffer.from([253, ...bitjs.numToBytes(num, 2)]);
    } else if (num < 4294967296) {
      return Buffer.from([254, ...bitjs.numToBytes(num, 4)]);
    } else {
      return Buffer.from([255, ...bitjs.numToBytes(num, 8)]);
    }
  };

  public static bytesToNum: (bytes: string) => number = (bytes: string) => {
    if (bytes.length == 0) return 0;
    else return bytes.charCodeAt(0) + 256 * bitjs.bytesToNum(bytes.slice(1));
  };
}
