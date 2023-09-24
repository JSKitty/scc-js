/* eslint-disable @typescript-eslint/no-explicit-any */
import { equal, notEqual } from "assert";
import * as SCC from "./index";

function verifyPubkeyWithCatch(
  strPubkey = "",
  network: "MainNet" | "TestNet" = "MainNet",
) {
  try {
    return SCC.wallet.verifyPubkey(strPubkey, network);
  } catch (e) {
    return (e as any).message ? (e as any).message : "";
  }
}

describe("Wallet Tests", () => {
  describe("MainNet", async () => {
    const cWallet: {
      pubkey: string | Uint8Array;
      privkey: string;
    } = await SCC.wallet.generateWallet("MainNet");
    let cSig: Buffer;
    let fSigVerif = false;

    it(`Generated a wallet - ${cWallet.pubkey}`, async () => {
      equal(!!cWallet.privkey, true);
      equal(!!cWallet.pubkey, true);
    });

    it("Can derive a Pubkey from WIF Privkey", async () => {
      const strPubkey = SCC.wallet.pubFromPriv(cWallet.privkey);
      equal(!!strPubkey, true);
    });

    it("Can create a signature", async () => {
      cSig = await SCC.signer.sign("test", cWallet.privkey);
      equal(!!cSig, true);
    });

    it("Can verify the signature", async () => {
      fSigVerif = SCC.signer.verify("test", cWallet.pubkey, cSig);
      equal(fSigVerif, true);
    });

    it("Can verify the address of our wallet", async () => {
      const pubkey = verifyPubkeyWithCatch(
        Buffer.from(cWallet.pubkey).toString(),
      );
      equal(pubkey, true);
    });

    it("Can verifyPubkey() regression & integrity", async () => {
      const arrTestAddresses = [
        "sYbmHt8EP8YacjFGahjhqXT8GNeSiTjbRs", // VALID
        "sYbmHt8EP8YacjFGahjhqXT8GNeSiTjbRs", // VALID
        "sYbmHt8EP8YacjFGahjhqXT8GNeSiTjbRs", // VALID
        "sAbmHt8EP8YacjFGahjhqXT8GNeSiTjbRs", // BAD
        "sBbmHt8EP8YacjFGahjhqXT8GNeSiTjbRs", // BAD
        "sY mHt8EP8YacjFGahjhqXT8GNeSiTjbRs", // BAD
        "sYbmHt", // BAD
        "i55j", // BAD
        "sYbmHt8EP8YacjFGahjhqXT8GNeSiTjbR!", // BAD
        "sYbmHt8EP8YacjFGahjhqXT8GNeSiTjbRiz", // BAD
        "sYbmHt8EP8YacjFGahjhqXT8GNeSiTjbRizz", // BAD
        "sYbmHt8EP8YacjFGahjhqXT8GNeSiTjbRz", // BAD
      ];
      const expected = [
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
      ];
      for (let i = 0; i < arrTestAddresses.length; i++) {
        const verified = verifyPubkeyWithCatch(arrTestAddresses[i], "MainNet");
        if (expected[i]) {
          equal(verified, true);
        } else {
          notEqual(verified, true);
        }
      }
    });
  });
  describe("TestNet", async () => {
    const cWallet: {
      pubkey: string | Uint8Array;
      privkey: string;
    } = await SCC.wallet.generateWallet("TestNet");
    let cSig: Buffer;
    let fSigVerif = false;

    it(`Generated a wallet - ${cWallet.pubkey}`, async () => {
      equal(!!cWallet.privkey, true);
      equal(!!cWallet.pubkey, true);
    });

    it("Can derive a Pubkey from WIF Privkey", async () => {
      const strPubkey = SCC.wallet.pubFromPriv(cWallet.privkey);
      equal(!!strPubkey, true);
    });

    it("Can create a signature", async () => {
      cSig = await SCC.signer.sign("test", cWallet.privkey);
      equal(!!cSig, true);
    });

    it("Can verify the signature", async () => {
      fSigVerif = SCC.signer.verify(
        "test",
        cWallet.pubkey,
        cSig,
        undefined,
        "TestNet",
      );
      equal(fSigVerif, true);
    });

    it("Can verify the address of our wallet", async () => {
      const pubkey = verifyPubkeyWithCatch(
        Buffer.from(cWallet.pubkey).toString(),
        "TestNet",
      );
      equal(pubkey, true);
    });

    it("Can verifyPubkey() regression & integrity", async () => {
      const arrTestAddresses = [
        "yegegVFuHLoo9NcptpXJoQcKy6PgBw1FF3", // VALID
        "yegegVFuHLoo9NcptpXJoQcKy6PgBw1FF3", // VALID
        "yegegVFuHLoo9NcptpXJoQcKy6PgBw1FF3", // VALID
        "yAgegVFuHLoo9NcptpXJoQcKy6PgBw1FF3", // BAD
        "yBgegVFuHLoo9NcptpXJoQcKy6PgBw1FF3", // BAD
        "y gegVFuHLoo9NcptpXJoQcKy6PgBw1FF3", // BAD
        "yegeg", // BAD
        "i55j", // BAD
        "yegegVFuHLoo9NcptpXJoQcKy6PgBw1FF!", // BAD
        "yegegVFuHLoo9NcptpXJoQcKy6PgBw1Riz", // BAD
        "yegegVFuHLoo9NcptpXJoQcKy6PgBwRizz", // BAD
        "yegegVFuHLoo9NcptpXJoQcKy6PgBwjbRz", // BAD
      ];
      const expected = [
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
      ];
      for (let i = 0; i < arrTestAddresses.length; i++) {
        const verified = verifyPubkeyWithCatch(arrTestAddresses[i], "TestNet");
        if (expected[i]) {
          equal(verified, true);
        } else {
          notEqual(verified, true);
        }
      }
    });
  });
});
