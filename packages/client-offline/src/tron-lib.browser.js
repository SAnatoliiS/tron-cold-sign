var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// lib/errors.js
var require_errors = __commonJS({
  "lib/errors.js"(exports, module) {
    "use strict";
    var CliError = class extends Error {
      /**
       * @param {string} message
       * @param {number} [exitCode=1]
       */
      constructor(message, exitCode = 1) {
        super(message);
        this.name = "CliError";
        this.exitCode = exitCode;
      }
    };
    module.exports = { CliError };
  }
});

// lib/tron/constants.js
var require_constants = __commonJS({
  "lib/tron/constants.js"(exports, module) {
    "use strict";
    var TRON_DERIVATION_PATH = "m/44'/195'/0'/0/0";
    var TRON_ADDRESS_VERSION_BYTE = 65;
    var ALLOWED_ENTROPY_BITS = /* @__PURE__ */ new Set([128, 160, 192, 224, 256]);
    var TRON_PATH_RE = /^m\/44'\/195'\/\d+'\/\d+\/\d+$/;
    module.exports = {
      TRON_DERIVATION_PATH,
      TRON_ADDRESS_VERSION_BYTE,
      ALLOWED_ENTROPY_BITS,
      TRON_PATH_RE
    };
  }
});

// node_modules/@noble/secp256k1/index.js
var secp256k1_exports = {};
__export(secp256k1_exports, {
  Point: () => Point,
  Signature: () => Signature,
  etc: () => etc,
  getPublicKey: () => getPublicKey,
  getSharedSecret: () => getSharedSecret,
  hash: () => hash,
  hashes: () => hashes,
  keygen: () => keygen,
  recoverPublicKey: () => recoverPublicKey,
  recoverPublicKeyAsync: () => recoverPublicKeyAsync,
  schnorr: () => schnorr,
  sign: () => sign,
  signAsync: () => signAsync,
  utils: () => utils,
  verify: () => verify,
  verifyAsync: () => verifyAsync
});
var secp256k1_CURVE, P, N, Gx, Gy, _b, L, L2, lengths, captureTrace, err, isBig, isStr, isBytes, abytes, u8n, padh, bytesToHex, C, _ch, hexToBytes, cr, subtle, concatBytes, randomBytes, big, arange, M, modN, invert, callHash, hash, apoint, koblitz, FpIsValid, FpIsValidNot0, FnIsValidNot0, isEven, u8of, getPrefix, lift_x, Point, G, I, doubleScalarMulUns, bytesToNumBE, sliceBytesNumBE, B256, numTo32b, secretKeyToScalar, highS, getPublicKey, isValidSecretKey, isValidPublicKey, assertRecoveryBit, assertSigFormat, assertSigLength, Signature, bits2int, bits2int_modN, SIG_COMPACT, SIG_RECOVERED, SIG_DER, ALL_SIG, defaultSignOpts, _sha, hashes, prepMsg, NULL, byte0, byte1, _maxDrbgIters, _drbgErr, hmacDrbg, hmacDrbgAsync, _sign, _verify, setDefaults, sign, signAsync, verify, verifyAsync, _recover, recoverPublicKey, recoverPublicKeyAsync, getSharedSecret, randomSecretKey, createKeygen, keygen, etc, utils, getTag, T_AUX, T_NONCE, T_CHALLENGE, taggedHash, taggedHashAsync, extpubSchnorr, bytesModN, challenge, challengeAsync, pubSchnorr, keygenSchnorr, prepSigSchnorr, extractK, createSigSchnorr, E_INVSIG, signSchnorr, signSchnorrAsync, callSyncAsyncFn, _verifSchnorr, verifySchnorr, verifySchnorrAsync, schnorr, W, scalarBits, pwindows, pwindowSize, precompute, Gpows, ctneg, wNAF;
var init_secp256k1 = __esm({
  "node_modules/@noble/secp256k1/index.js"() {
    secp256k1_CURVE = {
      p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
      n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
      h: 1n,
      a: 0n,
      b: 7n,
      Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
      Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
    };
    ({ p: P, n: N, Gx, Gy, b: _b } = secp256k1_CURVE);
    L = 32;
    L2 = 64;
    lengths = {
      publicKey: L + 1,
      publicKeyUncompressed: L2 + 1,
      signature: L2,
      seed: L + L / 2
    };
    captureTrace = (...args) => {
      if ("captureStackTrace" in Error && typeof Error.captureStackTrace === "function") {
        Error.captureStackTrace(...args);
      }
    };
    err = (message = "") => {
      const e = new Error(message);
      captureTrace(e, err);
      throw e;
    };
    isBig = (n) => typeof n === "bigint";
    isStr = (s) => typeof s === "string";
    isBytes = (a) => a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
    abytes = (value, length, title = "") => {
      const bytes2 = isBytes(value);
      const len = value?.length;
      const needsLen = length !== void 0;
      if (!bytes2 || needsLen && len !== length) {
        const prefix = title && `"${title}" `;
        const ofLen = needsLen ? ` of length ${length}` : "";
        const got = bytes2 ? `length=${len}` : `type=${typeof value}`;
        err(prefix + "expected Uint8Array" + ofLen + ", got " + got);
      }
      return value;
    };
    u8n = (len) => new Uint8Array(len);
    padh = (n, pad) => n.toString(16).padStart(pad, "0");
    bytesToHex = (b) => Array.from(abytes(b)).map((e) => padh(e, 2)).join("");
    C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
    _ch = (ch) => {
      if (ch >= C._0 && ch <= C._9)
        return ch - C._0;
      if (ch >= C.A && ch <= C.F)
        return ch - (C.A - 10);
      if (ch >= C.a && ch <= C.f)
        return ch - (C.a - 10);
      return;
    };
    hexToBytes = (hex2) => {
      const e = "hex invalid";
      if (!isStr(hex2))
        return err(e);
      const hl = hex2.length;
      const al = hl / 2;
      if (hl % 2)
        return err(e);
      const array = u8n(al);
      for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = _ch(hex2.charCodeAt(hi));
        const n2 = _ch(hex2.charCodeAt(hi + 1));
        if (n1 === void 0 || n2 === void 0)
          return err(e);
        array[ai] = n1 * 16 + n2;
      }
      return array;
    };
    cr = () => globalThis?.crypto;
    subtle = () => cr()?.subtle ?? err("crypto.subtle must be defined, consider polyfill");
    concatBytes = (...arrs) => {
      const r = u8n(arrs.reduce((sum, a) => sum + abytes(a).length, 0));
      let pad = 0;
      arrs.forEach((a) => {
        r.set(a, pad);
        pad += a.length;
      });
      return r;
    };
    randomBytes = (len = L) => {
      const c = cr();
      return c.getRandomValues(u8n(len));
    };
    big = BigInt;
    arange = (n, min, max, msg = "bad number: out of range") => isBig(n) && min <= n && n < max ? n : err(msg);
    M = (a, b = P) => {
      const r = a % b;
      return r >= 0n ? r : b + r;
    };
    modN = (a) => M(a, N);
    invert = (num, md) => {
      if (num === 0n || md <= 0n)
        err("no inverse n=" + num + " mod=" + md);
      let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
      while (a !== 0n) {
        const q = b / a, r = b % a;
        const m = x - u * q, n = y - v * q;
        b = a, a = r, x = u, y = v, u = m, v = n;
      }
      return b === 1n ? M(x, md) : err("no inverse");
    };
    callHash = (name) => {
      const fn = hashes[name];
      if (typeof fn !== "function")
        err("hashes." + name + " not set");
      return fn;
    };
    hash = (msg) => callHash("sha256")(msg);
    apoint = (p) => p instanceof Point ? p : err("Point expected");
    koblitz = (x) => M(M(x * x) * x + _b);
    FpIsValid = (n) => arange(n, 0n, P);
    FpIsValidNot0 = (n) => arange(n, 1n, P);
    FnIsValidNot0 = (n) => arange(n, 1n, N);
    isEven = (y) => (y & 1n) === 0n;
    u8of = (n) => Uint8Array.of(n);
    getPrefix = (y) => u8of(isEven(y) ? 2 : 3);
    lift_x = (x) => {
      const c = koblitz(FpIsValidNot0(x));
      let r = 1n;
      for (let num = c, e = (P + 1n) / 4n; e > 0n; e >>= 1n) {
        if (e & 1n)
          r = r * num % P;
        num = num * num % P;
      }
      return M(r * r) === c ? r : err("sqrt invalid");
    };
    Point = class _Point {
      static BASE;
      static ZERO;
      X;
      Y;
      Z;
      constructor(X, Y, Z) {
        this.X = FpIsValid(X);
        this.Y = FpIsValidNot0(Y);
        this.Z = FpIsValid(Z);
        Object.freeze(this);
      }
      static CURVE() {
        return secp256k1_CURVE;
      }
      /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
      static fromAffine(ap) {
        const { x, y } = ap;
        return x === 0n && y === 0n ? I : new _Point(x, y, 1n);
      }
      /** Convert Uint8Array or hex string to Point. */
      static fromBytes(bytes2) {
        abytes(bytes2);
        const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths;
        let p = void 0;
        const length = bytes2.length;
        const head = bytes2[0];
        const tail = bytes2.subarray(1);
        const x = sliceBytesNumBE(tail, 0, L);
        if (length === comp && (head === 2 || head === 3)) {
          let y = lift_x(x);
          const evenY = isEven(y);
          const evenH = isEven(big(head));
          if (evenH !== evenY)
            y = M(-y);
          p = new _Point(x, y, 1n);
        }
        if (length === uncomp && head === 4)
          p = new _Point(x, sliceBytesNumBE(tail, L, L2), 1n);
        return p ? p.assertValidity() : err("bad point: not on curve");
      }
      static fromHex(hex2) {
        return _Point.fromBytes(hexToBytes(hex2));
      }
      get x() {
        return this.toAffine().x;
      }
      get y() {
        return this.toAffine().y;
      }
      /** Equality check: compare points P&Q. */
      equals(other) {
        const { X: X1, Y: Y1, Z: Z1 } = this;
        const { X: X2, Y: Y2, Z: Z2 } = apoint(other);
        const X1Z2 = M(X1 * Z2);
        const X2Z1 = M(X2 * Z1);
        const Y1Z2 = M(Y1 * Z2);
        const Y2Z1 = M(Y2 * Z1);
        return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
      }
      is0() {
        return this.equals(I);
      }
      /** Flip point over y coordinate. */
      negate() {
        return new _Point(this.X, M(-this.Y), this.Z);
      }
      /** Point doubling: P+P, complete formula. */
      double() {
        return this.add(this);
      }
      /**
       * Point addition: P+Q, complete, exception-free formula
       * (Renes-Costello-Batina, algo 1 of [2015/1060](https://eprint.iacr.org/2015/1060)).
       * Cost: `12M + 0S + 3*a + 3*b3 + 23add`.
       */
      // prettier-ignore
      add(other) {
        const { X: X1, Y: Y1, Z: Z1 } = this;
        const { X: X2, Y: Y2, Z: Z2 } = apoint(other);
        const a = 0n;
        const b = _b;
        let X3 = 0n, Y3 = 0n, Z3 = 0n;
        const b3 = M(b * 3n);
        let t0 = M(X1 * X2), t1 = M(Y1 * Y2), t2 = M(Z1 * Z2), t3 = M(X1 + Y1);
        let t4 = M(X2 + Y2);
        t3 = M(t3 * t4);
        t4 = M(t0 + t1);
        t3 = M(t3 - t4);
        t4 = M(X1 + Z1);
        let t5 = M(X2 + Z2);
        t4 = M(t4 * t5);
        t5 = M(t0 + t2);
        t4 = M(t4 - t5);
        t5 = M(Y1 + Z1);
        X3 = M(Y2 + Z2);
        t5 = M(t5 * X3);
        X3 = M(t1 + t2);
        t5 = M(t5 - X3);
        Z3 = M(a * t4);
        X3 = M(b3 * t2);
        Z3 = M(X3 + Z3);
        X3 = M(t1 - Z3);
        Z3 = M(t1 + Z3);
        Y3 = M(X3 * Z3);
        t1 = M(t0 + t0);
        t1 = M(t1 + t0);
        t2 = M(a * t2);
        t4 = M(b3 * t4);
        t1 = M(t1 + t2);
        t2 = M(t0 - t2);
        t2 = M(a * t2);
        t4 = M(t4 + t2);
        t0 = M(t1 * t4);
        Y3 = M(Y3 + t0);
        t0 = M(t5 * t4);
        X3 = M(t3 * X3);
        X3 = M(X3 - t0);
        t0 = M(t3 * t1);
        Z3 = M(t5 * Z3);
        Z3 = M(Z3 + t0);
        return new _Point(X3, Y3, Z3);
      }
      subtract(other) {
        return this.add(apoint(other).negate());
      }
      /**
       * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
       * Uses {@link wNAF} for base point.
       * Uses fake point to mitigate side-channel leakage.
       * @param n scalar by which point is multiplied
       * @param safe safe mode guards against timing attacks; unsafe mode is faster
       */
      multiply(n, safe = true) {
        if (!safe && n === 0n)
          return I;
        FnIsValidNot0(n);
        if (n === 1n)
          return this;
        if (this.equals(G))
          return wNAF(n).p;
        let p = I;
        let f = G;
        for (let d = this; n > 0n; d = d.double(), n >>= 1n) {
          if (n & 1n)
            p = p.add(d);
          else if (safe)
            f = f.add(d);
        }
        return p;
      }
      multiplyUnsafe(scalar) {
        return this.multiply(scalar, false);
      }
      /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
      toAffine() {
        const { X: x, Y: y, Z: z } = this;
        if (this.equals(I))
          return { x: 0n, y: 0n };
        if (z === 1n)
          return { x, y };
        const iz = invert(z, P);
        if (M(z * iz) !== 1n)
          err("inverse invalid");
        return { x: M(x * iz), y: M(y * iz) };
      }
      /** Checks if the point is valid and on-curve. */
      assertValidity() {
        const { x, y } = this.toAffine();
        FpIsValidNot0(x);
        FpIsValidNot0(y);
        return M(y * y) === koblitz(x) ? this : err("bad point: not on curve");
      }
      /** Converts point to 33/65-byte Uint8Array. */
      toBytes(isCompressed = true) {
        const { x, y } = this.assertValidity().toAffine();
        const x32b = numTo32b(x);
        if (isCompressed)
          return concatBytes(getPrefix(y), x32b);
        return concatBytes(u8of(4), x32b, numTo32b(y));
      }
      toHex(isCompressed) {
        return bytesToHex(this.toBytes(isCompressed));
      }
    };
    G = new Point(Gx, Gy, 1n);
    I = new Point(0n, 1n, 0n);
    Point.BASE = G;
    Point.ZERO = I;
    doubleScalarMulUns = (R, u1, u2) => {
      return G.multiply(u1, false).add(R.multiply(u2, false)).assertValidity();
    };
    bytesToNumBE = (b) => big("0x" + (bytesToHex(b) || "0"));
    sliceBytesNumBE = (b, from, to) => bytesToNumBE(b.subarray(from, to));
    B256 = 2n ** 256n;
    numTo32b = (num) => hexToBytes(padh(arange(num, 0n, B256), L2));
    secretKeyToScalar = (secretKey) => {
      const num = bytesToNumBE(abytes(secretKey, L, "secret key"));
      return arange(num, 1n, N, "invalid secret key: outside of range");
    };
    highS = (n) => n > N >> 1n;
    getPublicKey = (privKey, isCompressed = true) => {
      return G.multiply(secretKeyToScalar(privKey)).toBytes(isCompressed);
    };
    isValidSecretKey = (secretKey) => {
      try {
        return !!secretKeyToScalar(secretKey);
      } catch (error) {
        return false;
      }
    };
    isValidPublicKey = (publicKey, isCompressed) => {
      const { publicKey: comp, publicKeyUncompressed } = lengths;
      try {
        const l = publicKey.length;
        if (isCompressed === true && l !== comp)
          return false;
        if (isCompressed === false && l !== publicKeyUncompressed)
          return false;
        return !!Point.fromBytes(publicKey);
      } catch (error) {
        return false;
      }
    };
    assertRecoveryBit = (recovery) => {
      if (![0, 1, 2, 3].includes(recovery))
        err("recovery id must be valid and present");
    };
    assertSigFormat = (format) => {
      if (format != null && !ALL_SIG.includes(format))
        err(`Signature format must be one of: ${ALL_SIG.join(", ")}`);
      if (format === SIG_DER)
        err('Signature format "der" is not supported: switch to noble-curves');
    };
    assertSigLength = (sig, format = SIG_COMPACT) => {
      assertSigFormat(format);
      const SL = lengths.signature;
      const RL = SL + 1;
      let msg = `Signature format "${format}" expects Uint8Array with length `;
      if (format === SIG_COMPACT && sig.length !== SL)
        err(msg + SL);
      if (format === SIG_RECOVERED && sig.length !== RL)
        err(msg + RL);
    };
    Signature = class _Signature {
      r;
      s;
      recovery;
      constructor(r, s, recovery) {
        this.r = FnIsValidNot0(r);
        this.s = FnIsValidNot0(s);
        if (recovery != null)
          this.recovery = recovery;
        Object.freeze(this);
      }
      static fromBytes(b, format = SIG_COMPACT) {
        assertSigLength(b, format);
        let rec;
        if (format === SIG_RECOVERED) {
          rec = b[0];
          b = b.subarray(1);
        }
        const r = sliceBytesNumBE(b, 0, L);
        const s = sliceBytesNumBE(b, L, L2);
        return new _Signature(r, s, rec);
      }
      addRecoveryBit(bit) {
        return new _Signature(this.r, this.s, bit);
      }
      hasHighS() {
        return highS(this.s);
      }
      toBytes(format = SIG_COMPACT) {
        const { r, s, recovery } = this;
        const res = concatBytes(numTo32b(r), numTo32b(s));
        if (format === SIG_RECOVERED) {
          assertRecoveryBit(recovery);
          return concatBytes(Uint8Array.of(recovery), res);
        }
        return res;
      }
    };
    bits2int = (bytes2) => {
      const delta = bytes2.length * 8 - 256;
      if (delta > 1024)
        err("msg invalid");
      const num = bytesToNumBE(bytes2);
      return delta > 0 ? num >> big(delta) : num;
    };
    bits2int_modN = (bytes2) => modN(bits2int(abytes(bytes2)));
    SIG_COMPACT = "compact";
    SIG_RECOVERED = "recovered";
    SIG_DER = "der";
    ALL_SIG = [SIG_COMPACT, SIG_RECOVERED, SIG_DER];
    defaultSignOpts = {
      lowS: true,
      prehash: true,
      format: SIG_COMPACT,
      extraEntropy: false
    };
    _sha = "SHA-256";
    hashes = {
      hmacSha256Async: async (key, message) => {
        const s = subtle();
        const name = "HMAC";
        const k = await s.importKey("raw", key, { name, hash: { name: _sha } }, false, ["sign"]);
        return u8n(await s.sign(name, k, message));
      },
      hmacSha256: void 0,
      sha256Async: async (msg) => u8n(await subtle().digest(_sha, msg)),
      sha256: void 0
    };
    prepMsg = (msg, opts, async_) => {
      abytes(msg, void 0, "message");
      if (!opts.prehash)
        return msg;
      return async_ ? hashes.sha256Async(msg) : callHash("sha256")(msg);
    };
    NULL = u8n(0);
    byte0 = u8of(0);
    byte1 = u8of(1);
    _maxDrbgIters = 1e3;
    _drbgErr = "drbg: tried max amount of iterations";
    hmacDrbg = (seed, pred) => {
      let v = u8n(L);
      let k = u8n(L);
      let i = 0;
      const reset = () => {
        v.fill(1);
        k.fill(0);
      };
      const h = (...b) => callHash("hmacSha256")(k, concatBytes(v, ...b));
      const reseed = (seed2 = NULL) => {
        k = h(byte0, seed2);
        v = h();
        if (seed2.length === 0)
          return;
        k = h(byte1, seed2);
        v = h();
      };
      const gen = () => {
        if (i++ >= _maxDrbgIters)
          err(_drbgErr);
        v = h();
        return v;
      };
      reset();
      reseed(seed);
      let res = void 0;
      while (!(res = pred(gen())))
        reseed();
      reset();
      return res;
    };
    hmacDrbgAsync = async (seed, pred) => {
      let v = u8n(L);
      let k = u8n(L);
      let i = 0;
      const reset = () => {
        v.fill(1);
        k.fill(0);
      };
      const h = (...b) => hashes.hmacSha256Async(k, concatBytes(v, ...b));
      const reseed = async (seed2 = NULL) => {
        k = await h(byte0, seed2);
        v = await h();
        if (seed2.length === 0)
          return;
        k = await h(byte1, seed2);
        v = await h();
      };
      const gen = async () => {
        if (i++ >= _maxDrbgIters)
          err(_drbgErr);
        v = await h();
        return v;
      };
      reset();
      await reseed(seed);
      let res = void 0;
      while (!(res = pred(await gen())))
        await reseed();
      reset();
      return res;
    };
    _sign = (messageHash, secretKey, opts, hmacDrbg2) => {
      let { lowS, extraEntropy } = opts;
      const int2octets = numTo32b;
      const h1i = bits2int_modN(messageHash);
      const h1o = int2octets(h1i);
      const d = secretKeyToScalar(secretKey);
      const seedArgs = [int2octets(d), h1o];
      if (extraEntropy != null && extraEntropy !== false) {
        const e = extraEntropy === true ? randomBytes(L) : extraEntropy;
        seedArgs.push(abytes(e, void 0, "extraEntropy"));
      }
      const seed = concatBytes(...seedArgs);
      const m = h1i;
      const k2sig = (kBytes) => {
        const k = bits2int(kBytes);
        if (!(1n <= k && k < N))
          return;
        const ik = invert(k, N);
        const q = G.multiply(k).toAffine();
        const r = modN(q.x);
        if (r === 0n)
          return;
        const s = modN(ik * modN(m + r * d));
        if (s === 0n)
          return;
        let recovery = (q.x === r ? 0 : 2) | Number(q.y & 1n);
        let normS = s;
        if (lowS && highS(s)) {
          normS = modN(-s);
          recovery ^= 1;
        }
        const sig = new Signature(r, normS, recovery);
        return sig.toBytes(opts.format);
      };
      return hmacDrbg2(seed, k2sig);
    };
    _verify = (sig, messageHash, publicKey, opts = {}) => {
      const { lowS, format } = opts;
      if (sig instanceof Signature)
        err("Signature must be in Uint8Array, use .toBytes()");
      assertSigLength(sig, format);
      abytes(publicKey, void 0, "publicKey");
      try {
        const { r, s } = Signature.fromBytes(sig, format);
        const h = bits2int_modN(messageHash);
        const P2 = Point.fromBytes(publicKey);
        if (lowS && highS(s))
          return false;
        const is = invert(s, N);
        const u1 = modN(h * is);
        const u2 = modN(r * is);
        const R = doubleScalarMulUns(P2, u1, u2).toAffine();
        const v = modN(R.x);
        return v === r;
      } catch (error) {
        return false;
      }
    };
    setDefaults = (opts) => {
      const res = {};
      Object.keys(defaultSignOpts).forEach((k) => {
        res[k] = opts[k] ?? defaultSignOpts[k];
      });
      return res;
    };
    sign = (message, secretKey, opts = {}) => {
      opts = setDefaults(opts);
      message = prepMsg(message, opts, false);
      return _sign(message, secretKey, opts, hmacDrbg);
    };
    signAsync = async (message, secretKey, opts = {}) => {
      opts = setDefaults(opts);
      message = await prepMsg(message, opts, true);
      return _sign(message, secretKey, opts, hmacDrbgAsync);
    };
    verify = (signature, message, publicKey, opts = {}) => {
      opts = setDefaults(opts);
      message = prepMsg(message, opts, false);
      return _verify(signature, message, publicKey, opts);
    };
    verifyAsync = async (sig, message, publicKey, opts = {}) => {
      opts = setDefaults(opts);
      message = await prepMsg(message, opts, true);
      return _verify(sig, message, publicKey, opts);
    };
    _recover = (signature, messageHash) => {
      const sig = Signature.fromBytes(signature, "recovered");
      const { r, s, recovery } = sig;
      assertRecoveryBit(recovery);
      const h = bits2int_modN(abytes(messageHash, L));
      const radj = recovery === 2 || recovery === 3 ? r + N : r;
      FpIsValidNot0(radj);
      const head = getPrefix(big(recovery));
      const Rb = concatBytes(head, numTo32b(radj));
      const R = Point.fromBytes(Rb);
      const ir = invert(radj, N);
      const u1 = modN(-h * ir);
      const u2 = modN(s * ir);
      const point = doubleScalarMulUns(R, u1, u2);
      return point.toBytes();
    };
    recoverPublicKey = (signature, message, opts = {}) => {
      message = prepMsg(message, setDefaults(opts), false);
      return _recover(signature, message);
    };
    recoverPublicKeyAsync = async (signature, message, opts = {}) => {
      message = await prepMsg(message, setDefaults(opts), true);
      return _recover(signature, message);
    };
    getSharedSecret = (secretKeyA, publicKeyB, isCompressed = true) => {
      return Point.fromBytes(publicKeyB).multiply(secretKeyToScalar(secretKeyA)).toBytes(isCompressed);
    };
    randomSecretKey = (seed = randomBytes(lengths.seed)) => {
      abytes(seed);
      if (seed.length < lengths.seed || seed.length > 1024)
        err("expected 40-1024b");
      const num = M(bytesToNumBE(seed), N - 1n);
      return numTo32b(num + 1n);
    };
    createKeygen = (getPublicKey2) => (seed) => {
      const secretKey = randomSecretKey(seed);
      return { secretKey, publicKey: getPublicKey2(secretKey) };
    };
    keygen = createKeygen(getPublicKey);
    etc = {
      hexToBytes,
      bytesToHex,
      concatBytes,
      bytesToNumberBE: bytesToNumBE,
      numberToBytesBE: numTo32b,
      mod: M,
      invert,
      // math utilities
      randomBytes,
      secretKeyToScalar,
      abytes
    };
    utils = {
      isValidSecretKey,
      isValidPublicKey,
      randomSecretKey
    };
    getTag = (tag) => Uint8Array.from("BIP0340/" + tag, (c) => c.charCodeAt(0));
    T_AUX = "aux";
    T_NONCE = "nonce";
    T_CHALLENGE = "challenge";
    taggedHash = (tag, ...messages) => {
      const fn = callHash("sha256");
      const tagH = fn(getTag(tag));
      return fn(concatBytes(tagH, tagH, ...messages));
    };
    taggedHashAsync = async (tag, ...messages) => {
      const fn = hashes.sha256Async;
      const tagH = await fn(getTag(tag));
      return await fn(concatBytes(tagH, tagH, ...messages));
    };
    extpubSchnorr = (priv) => {
      const d_ = secretKeyToScalar(priv);
      const p = G.multiply(d_);
      const { x, y } = p.assertValidity().toAffine();
      const d = isEven(y) ? d_ : modN(-d_);
      const px = numTo32b(x);
      return { d, px };
    };
    bytesModN = (bytes2) => modN(bytesToNumBE(bytes2));
    challenge = (...args) => bytesModN(taggedHash(T_CHALLENGE, ...args));
    challengeAsync = async (...args) => bytesModN(await taggedHashAsync(T_CHALLENGE, ...args));
    pubSchnorr = (secretKey) => {
      return extpubSchnorr(secretKey).px;
    };
    keygenSchnorr = createKeygen(pubSchnorr);
    prepSigSchnorr = (message, secretKey, auxRand) => {
      const { px, d } = extpubSchnorr(secretKey);
      return { m: abytes(message), px, d, a: abytes(auxRand, L) };
    };
    extractK = (rand) => {
      const k_ = bytesModN(rand);
      if (k_ === 0n)
        err("sign failed: k is zero");
      const { px, d } = extpubSchnorr(numTo32b(k_));
      return { rx: px, k: d };
    };
    createSigSchnorr = (k, px, e, d) => {
      return concatBytes(px, numTo32b(modN(k + e * d)));
    };
    E_INVSIG = "invalid signature produced";
    signSchnorr = (message, secretKey, auxRand = randomBytes(L)) => {
      const { m, px, d, a } = prepSigSchnorr(message, secretKey, auxRand);
      const aux = taggedHash(T_AUX, a);
      const t = numTo32b(d ^ bytesToNumBE(aux));
      const rand = taggedHash(T_NONCE, t, px, m);
      const { rx, k } = extractK(rand);
      const e = challenge(rx, px, m);
      const sig = createSigSchnorr(k, rx, e, d);
      if (!verifySchnorr(sig, m, px))
        err(E_INVSIG);
      return sig;
    };
    signSchnorrAsync = async (message, secretKey, auxRand = randomBytes(L)) => {
      const { m, px, d, a } = prepSigSchnorr(message, secretKey, auxRand);
      const aux = await taggedHashAsync(T_AUX, a);
      const t = numTo32b(d ^ bytesToNumBE(aux));
      const rand = await taggedHashAsync(T_NONCE, t, px, m);
      const { rx, k } = extractK(rand);
      const e = await challengeAsync(rx, px, m);
      const sig = createSigSchnorr(k, rx, e, d);
      if (!await verifySchnorrAsync(sig, m, px))
        err(E_INVSIG);
      return sig;
    };
    callSyncAsyncFn = (res, later) => {
      return res instanceof Promise ? res.then(later) : later(res);
    };
    _verifSchnorr = (signature, message, publicKey, challengeFn) => {
      const sig = abytes(signature, L2, "signature");
      const msg = abytes(message, void 0, "message");
      const pub = abytes(publicKey, L, "publicKey");
      try {
        const x = bytesToNumBE(pub);
        const y = lift_x(x);
        const y_ = isEven(y) ? y : M(-y);
        const P_ = new Point(x, y_, 1n).assertValidity();
        const px = numTo32b(P_.toAffine().x);
        const r = sliceBytesNumBE(sig, 0, L);
        arange(r, 1n, P);
        const s = sliceBytesNumBE(sig, L, L2);
        arange(s, 1n, N);
        const i = concatBytes(numTo32b(r), px, msg);
        return callSyncAsyncFn(challengeFn(i), (e) => {
          const { x: x2, y: y2 } = doubleScalarMulUns(P_, s, modN(-e)).toAffine();
          if (!isEven(y2) || x2 !== r)
            return false;
          return true;
        });
      } catch (error) {
        return false;
      }
    };
    verifySchnorr = (s, m, p) => _verifSchnorr(s, m, p, challenge);
    verifySchnorrAsync = async (s, m, p) => _verifSchnorr(s, m, p, challengeAsync);
    schnorr = {
      keygen: keygenSchnorr,
      getPublicKey: pubSchnorr,
      sign: signSchnorr,
      verify: verifySchnorr,
      signAsync: signSchnorrAsync,
      verifyAsync: verifySchnorrAsync
    };
    W = 8;
    scalarBits = 256;
    pwindows = Math.ceil(scalarBits / W) + 1;
    pwindowSize = 2 ** (W - 1);
    precompute = () => {
      const points = [];
      let p = G;
      let b = p;
      for (let w = 0; w < pwindows; w++) {
        b = p;
        points.push(b);
        for (let i = 1; i < pwindowSize; i++) {
          b = b.add(p);
          points.push(b);
        }
        p = b.double();
      }
      return points;
    };
    Gpows = void 0;
    ctneg = (cnd, p) => {
      const n = p.negate();
      return cnd ? n : p;
    };
    wNAF = (n) => {
      const comp = Gpows || (Gpows = precompute());
      let p = I;
      let f = G;
      const pow_2_w = 2 ** W;
      const maxNum = pow_2_w;
      const mask = big(pow_2_w - 1);
      const shiftBy = big(W);
      for (let w = 0; w < pwindows; w++) {
        let wbits = Number(n & mask);
        n >>= shiftBy;
        if (wbits > pwindowSize) {
          wbits -= maxNum;
          n += 1n;
        }
        const off = w * pwindowSize;
        const offF = off;
        const offP = off + Math.abs(wbits) - 1;
        const isEven2 = w % 2 !== 0;
        const isNeg = wbits < 0;
        if (wbits === 0) {
          f = f.add(ctneg(isEven2, comp[offF]));
        } else {
          p = p.add(ctneg(isNeg, comp[offP]));
        }
      }
      if (n !== 0n)
        err("invalid wnaf");
      return { p, f };
    };
  }
});

// node_modules/@noble/hashes/utils.js
function isBytes2(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n, title = "") {
  if (!Number.isSafeInteger(n) || n < 0) {
    const prefix = title && `"${title}" `;
    throw new Error(`${prefix}expected integer >= 0, got ${n}`);
  }
}
function abytes2(value, length, title = "") {
  const bytes2 = isBytes2(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes2 || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes2 ? `length=${len}` : `type=${typeof value}`;
    throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
  }
  return value;
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new Error("Hash must wrapped by utils.createHasher");
  anumber(h.outputLen);
  anumber(h.blockLen);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes2(out, void 0, "digestInto() output");
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error('"digestInto() output" expected to be of length >=' + min);
  }
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
function createHasher(hashCons, info = {}) {
  const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
var isLE, swap32IfBE, oidNist;
var init_utils = __esm({
  "node_modules/@noble/hashes/utils.js"() {
    isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
    swap32IfBE = isLE ? (u) => u : byteSwap32;
    oidNist = (suffix) => ({
      oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
    });
  }
});

// node_modules/@noble/hashes/hmac.js
var hmac_exports = {};
__export(hmac_exports, {
  _HMAC: () => _HMAC,
  hmac: () => hmac
});
var _HMAC, hmac;
var init_hmac = __esm({
  "node_modules/@noble/hashes/hmac.js"() {
    init_utils();
    _HMAC = class {
      oHash;
      iHash;
      blockLen;
      outputLen;
      finished = false;
      destroyed = false;
      constructor(hash2, key) {
        ahash(hash2);
        abytes2(key, void 0, "key");
        this.iHash = hash2.create();
        if (typeof this.iHash.update !== "function")
          throw new Error("Expected instance of class which extends utils.Hash");
        this.blockLen = this.iHash.blockLen;
        this.outputLen = this.iHash.outputLen;
        const blockLen = this.blockLen;
        const pad = new Uint8Array(blockLen);
        pad.set(key.length > blockLen ? hash2.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
          pad[i] ^= 54;
        this.iHash.update(pad);
        this.oHash = hash2.create();
        for (let i = 0; i < pad.length; i++)
          pad[i] ^= 54 ^ 92;
        this.oHash.update(pad);
        clean(pad);
      }
      update(buf) {
        aexists(this);
        this.iHash.update(buf);
        return this;
      }
      digestInto(out) {
        aexists(this);
        abytes2(out, this.outputLen, "output");
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
      }
      digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
      }
      _cloneInto(to) {
        to ||= Object.create(Object.getPrototypeOf(this), {});
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
      }
      clone() {
        return this._cloneInto();
      }
      destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
      }
    };
    hmac = (hash2, key, message) => new _HMAC(hash2, key).update(message).digest();
    hmac.create = (hash2, key) => new _HMAC(hash2, key);
  }
});

// node_modules/@noble/hashes/_md.js
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD, SHA256_IV, SHA224_IV, SHA384_IV, SHA512_IV;
var init_md = __esm({
  "node_modules/@noble/hashes/_md.js"() {
    init_utils();
    HashMD = class {
      blockLen;
      outputLen;
      padOffset;
      isLE;
      // For partial updates less than block size
      buffer;
      view;
      finished = false;
      length = 0;
      pos = 0;
      destroyed = false;
      constructor(blockLen, outputLen, padOffset, isLE2) {
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE2;
        this.buffer = new Uint8Array(blockLen);
        this.view = createView(this.buffer);
      }
      update(data) {
        aexists(this);
        abytes2(data);
        const { view, buffer, blockLen } = this;
        const len = data.length;
        for (let pos = 0; pos < len; ) {
          const take = Math.min(blockLen - this.pos, len - pos);
          if (take === blockLen) {
            const dataView = createView(data);
            for (; blockLen <= len - pos; pos += blockLen)
              this.process(dataView, pos);
            continue;
          }
          buffer.set(data.subarray(pos, pos + take), this.pos);
          this.pos += take;
          pos += take;
          if (this.pos === blockLen) {
            this.process(view, 0);
            this.pos = 0;
          }
        }
        this.length += data.length;
        this.roundClean();
        return this;
      }
      digestInto(out) {
        aexists(this);
        aoutput(out, this);
        this.finished = true;
        const { buffer, view, blockLen, isLE: isLE2 } = this;
        let { pos } = this;
        buffer[pos++] = 128;
        clean(this.buffer.subarray(pos));
        if (this.padOffset > blockLen - pos) {
          this.process(view, 0);
          pos = 0;
        }
        for (let i = pos; i < blockLen; i++)
          buffer[i] = 0;
        view.setBigUint64(blockLen - 8, BigInt(this.length * 8), isLE2);
        this.process(view, 0);
        const oview = createView(out);
        const len = this.outputLen;
        if (len % 4)
          throw new Error("_sha2: outputLen must be aligned to 32bit");
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
          throw new Error("_sha2: outputLen bigger than state");
        for (let i = 0; i < outLen; i++)
          oview.setUint32(4 * i, state[i], isLE2);
      }
      digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
      }
      _cloneInto(to) {
        to ||= new this.constructor();
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.destroyed = destroyed;
        to.finished = finished;
        to.length = length;
        to.pos = pos;
        if (length % blockLen)
          to.buffer.set(buffer);
        return to;
      }
      clone() {
        return this._cloneInto();
      }
    };
    SHA256_IV = /* @__PURE__ */ Uint32Array.from([
      1779033703,
      3144134277,
      1013904242,
      2773480762,
      1359893119,
      2600822924,
      528734635,
      1541459225
    ]);
    SHA224_IV = /* @__PURE__ */ Uint32Array.from([
      3238371032,
      914150663,
      812702999,
      4144912697,
      4290775857,
      1750603025,
      1694076839,
      3204075428
    ]);
    SHA384_IV = /* @__PURE__ */ Uint32Array.from([
      3418070365,
      3238371032,
      1654270250,
      914150663,
      2438529370,
      812702999,
      355462360,
      4144912697,
      1731405415,
      4290775857,
      2394180231,
      1750603025,
      3675008525,
      1694076839,
      1203062813,
      3204075428
    ]);
    SHA512_IV = /* @__PURE__ */ Uint32Array.from([
      1779033703,
      4089235720,
      3144134277,
      2227873595,
      1013904242,
      4271175723,
      2773480762,
      1595750129,
      1359893119,
      2917565137,
      2600822924,
      725511199,
      528734635,
      4215389547,
      1541459225,
      327033209
    ]);
  }
});

// node_modules/@noble/hashes/_u64.js
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
function add(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}
var U32_MASK64, _32n, shrSH, shrSL, rotrSH, rotrSL, rotrBH, rotrBL, rotlSH, rotlSL, rotlBH, rotlBL, add3L, add3H, add4L, add4H, add5L, add5H;
var init_u64 = __esm({
  "node_modules/@noble/hashes/_u64.js"() {
    U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
    _32n = /* @__PURE__ */ BigInt(32);
    shrSH = (h, _l, s) => h >>> s;
    shrSL = (h, l, s) => h << 32 - s | l >>> s;
    rotrSH = (h, l, s) => h >>> s | l << 32 - s;
    rotrSL = (h, l, s) => h << 32 - s | l >>> s;
    rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
    rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
    rotlSH = (h, l, s) => h << s | l >>> 32 - s;
    rotlSL = (h, l, s) => l << s | h >>> 32 - s;
    rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
    rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;
    add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
    add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
    add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
    add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
    add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
    add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
  }
});

// node_modules/@noble/hashes/sha2.js
var sha2_exports = {};
__export(sha2_exports, {
  _SHA224: () => _SHA224,
  _SHA256: () => _SHA256,
  _SHA384: () => _SHA384,
  _SHA512: () => _SHA512,
  _SHA512_224: () => _SHA512_224,
  _SHA512_256: () => _SHA512_256,
  sha224: () => sha224,
  sha256: () => sha256,
  sha384: () => sha384,
  sha512: () => sha512,
  sha512_224: () => sha512_224,
  sha512_256: () => sha512_256
});
var SHA256_K, SHA256_W, SHA2_32B, _SHA256, _SHA224, K512, SHA512_Kh, SHA512_Kl, SHA512_W_H, SHA512_W_L, SHA2_64B, _SHA512, _SHA384, T224_IV, T256_IV, _SHA512_224, _SHA512_256, sha256, sha224, sha512, sha384, sha512_256, sha512_224;
var init_sha2 = __esm({
  "node_modules/@noble/hashes/sha2.js"() {
    init_md();
    init_u64();
    init_utils();
    SHA256_K = /* @__PURE__ */ Uint32Array.from([
      1116352408,
      1899447441,
      3049323471,
      3921009573,
      961987163,
      1508970993,
      2453635748,
      2870763221,
      3624381080,
      310598401,
      607225278,
      1426881987,
      1925078388,
      2162078206,
      2614888103,
      3248222580,
      3835390401,
      4022224774,
      264347078,
      604807628,
      770255983,
      1249150122,
      1555081692,
      1996064986,
      2554220882,
      2821834349,
      2952996808,
      3210313671,
      3336571891,
      3584528711,
      113926993,
      338241895,
      666307205,
      773529912,
      1294757372,
      1396182291,
      1695183700,
      1986661051,
      2177026350,
      2456956037,
      2730485921,
      2820302411,
      3259730800,
      3345764771,
      3516065817,
      3600352804,
      4094571909,
      275423344,
      430227734,
      506948616,
      659060556,
      883997877,
      958139571,
      1322822218,
      1537002063,
      1747873779,
      1955562222,
      2024104815,
      2227730452,
      2361852424,
      2428436474,
      2756734187,
      3204031479,
      3329325298
    ]);
    SHA256_W = /* @__PURE__ */ new Uint32Array(64);
    SHA2_32B = class extends HashMD {
      constructor(outputLen) {
        super(64, outputLen, 8, false);
      }
      get() {
        const { A, B, C: C2, D, E, F, G: G2, H } = this;
        return [A, B, C2, D, E, F, G2, H];
      }
      // prettier-ignore
      set(A, B, C2, D, E, F, G2, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C2 | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G2 | 0;
        this.H = H | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
          SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
          const W15 = SHA256_W[i - 15];
          const W2 = SHA256_W[i - 2];
          const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
          const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
          SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
        }
        let { A, B, C: C2, D, E, F, G: G2, H } = this;
        for (let i = 0; i < 64; i++) {
          const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
          const T1 = H + sigma1 + Chi(E, F, G2) + SHA256_K[i] + SHA256_W[i] | 0;
          const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
          const T2 = sigma0 + Maj(A, B, C2) | 0;
          H = G2;
          G2 = F;
          F = E;
          E = D + T1 | 0;
          D = C2;
          C2 = B;
          B = A;
          A = T1 + T2 | 0;
        }
        A = A + this.A | 0;
        B = B + this.B | 0;
        C2 = C2 + this.C | 0;
        D = D + this.D | 0;
        E = E + this.E | 0;
        F = F + this.F | 0;
        G2 = G2 + this.G | 0;
        H = H + this.H | 0;
        this.set(A, B, C2, D, E, F, G2, H);
      }
      roundClean() {
        clean(SHA256_W);
      }
      destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        clean(this.buffer);
      }
    };
    _SHA256 = class extends SHA2_32B {
      // We cannot use array here since array allows indexing by variable
      // which means optimizer/compiler cannot use registers.
      A = SHA256_IV[0] | 0;
      B = SHA256_IV[1] | 0;
      C = SHA256_IV[2] | 0;
      D = SHA256_IV[3] | 0;
      E = SHA256_IV[4] | 0;
      F = SHA256_IV[5] | 0;
      G = SHA256_IV[6] | 0;
      H = SHA256_IV[7] | 0;
      constructor() {
        super(32);
      }
    };
    _SHA224 = class extends SHA2_32B {
      A = SHA224_IV[0] | 0;
      B = SHA224_IV[1] | 0;
      C = SHA224_IV[2] | 0;
      D = SHA224_IV[3] | 0;
      E = SHA224_IV[4] | 0;
      F = SHA224_IV[5] | 0;
      G = SHA224_IV[6] | 0;
      H = SHA224_IV[7] | 0;
      constructor() {
        super(28);
      }
    };
    K512 = /* @__PURE__ */ (() => split([
      "0x428a2f98d728ae22",
      "0x7137449123ef65cd",
      "0xb5c0fbcfec4d3b2f",
      "0xe9b5dba58189dbbc",
      "0x3956c25bf348b538",
      "0x59f111f1b605d019",
      "0x923f82a4af194f9b",
      "0xab1c5ed5da6d8118",
      "0xd807aa98a3030242",
      "0x12835b0145706fbe",
      "0x243185be4ee4b28c",
      "0x550c7dc3d5ffb4e2",
      "0x72be5d74f27b896f",
      "0x80deb1fe3b1696b1",
      "0x9bdc06a725c71235",
      "0xc19bf174cf692694",
      "0xe49b69c19ef14ad2",
      "0xefbe4786384f25e3",
      "0x0fc19dc68b8cd5b5",
      "0x240ca1cc77ac9c65",
      "0x2de92c6f592b0275",
      "0x4a7484aa6ea6e483",
      "0x5cb0a9dcbd41fbd4",
      "0x76f988da831153b5",
      "0x983e5152ee66dfab",
      "0xa831c66d2db43210",
      "0xb00327c898fb213f",
      "0xbf597fc7beef0ee4",
      "0xc6e00bf33da88fc2",
      "0xd5a79147930aa725",
      "0x06ca6351e003826f",
      "0x142929670a0e6e70",
      "0x27b70a8546d22ffc",
      "0x2e1b21385c26c926",
      "0x4d2c6dfc5ac42aed",
      "0x53380d139d95b3df",
      "0x650a73548baf63de",
      "0x766a0abb3c77b2a8",
      "0x81c2c92e47edaee6",
      "0x92722c851482353b",
      "0xa2bfe8a14cf10364",
      "0xa81a664bbc423001",
      "0xc24b8b70d0f89791",
      "0xc76c51a30654be30",
      "0xd192e819d6ef5218",
      "0xd69906245565a910",
      "0xf40e35855771202a",
      "0x106aa07032bbd1b8",
      "0x19a4c116b8d2d0c8",
      "0x1e376c085141ab53",
      "0x2748774cdf8eeb99",
      "0x34b0bcb5e19b48a8",
      "0x391c0cb3c5c95a63",
      "0x4ed8aa4ae3418acb",
      "0x5b9cca4f7763e373",
      "0x682e6ff3d6b2b8a3",
      "0x748f82ee5defb2fc",
      "0x78a5636f43172f60",
      "0x84c87814a1f0ab72",
      "0x8cc702081a6439ec",
      "0x90befffa23631e28",
      "0xa4506cebde82bde9",
      "0xbef9a3f7b2c67915",
      "0xc67178f2e372532b",
      "0xca273eceea26619c",
      "0xd186b8c721c0c207",
      "0xeada7dd6cde0eb1e",
      "0xf57d4f7fee6ed178",
      "0x06f067aa72176fba",
      "0x0a637dc5a2c898a6",
      "0x113f9804bef90dae",
      "0x1b710b35131c471b",
      "0x28db77f523047d84",
      "0x32caab7b40c72493",
      "0x3c9ebe0a15c9bebc",
      "0x431d67c49c100d4c",
      "0x4cc5d4becb3e42b6",
      "0x597f299cfc657e2a",
      "0x5fcb6fab3ad6faec",
      "0x6c44198c4a475817"
    ].map((n) => BigInt(n))))();
    SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
    SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
    SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
    SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
    SHA2_64B = class extends HashMD {
      constructor(outputLen) {
        super(128, outputLen, 16, false);
      }
      // prettier-ignore
      get() {
        const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
      }
      // prettier-ignore
      set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
        this.Ah = Ah | 0;
        this.Al = Al | 0;
        this.Bh = Bh | 0;
        this.Bl = Bl | 0;
        this.Ch = Ch | 0;
        this.Cl = Cl | 0;
        this.Dh = Dh | 0;
        this.Dl = Dl | 0;
        this.Eh = Eh | 0;
        this.El = El | 0;
        this.Fh = Fh | 0;
        this.Fl = Fl | 0;
        this.Gh = Gh | 0;
        this.Gl = Gl | 0;
        this.Hh = Hh | 0;
        this.Hl = Hl | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4) {
          SHA512_W_H[i] = view.getUint32(offset);
          SHA512_W_L[i] = view.getUint32(offset += 4);
        }
        for (let i = 16; i < 80; i++) {
          const W15h = SHA512_W_H[i - 15] | 0;
          const W15l = SHA512_W_L[i - 15] | 0;
          const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
          const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
          const W2h = SHA512_W_H[i - 2] | 0;
          const W2l = SHA512_W_L[i - 2] | 0;
          const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
          const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
          const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
          const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
          SHA512_W_H[i] = SUMh | 0;
          SHA512_W_L[i] = SUMl | 0;
        }
        let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        for (let i = 0; i < 80; i++) {
          const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
          const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
          const CHIh = Eh & Fh ^ ~Eh & Gh;
          const CHIl = El & Fl ^ ~El & Gl;
          const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
          const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
          const T1l = T1ll | 0;
          const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
          const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
          const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
          const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
          Hh = Gh | 0;
          Hl = Gl | 0;
          Gh = Fh | 0;
          Gl = Fl | 0;
          Fh = Eh | 0;
          Fl = El | 0;
          ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
          Dh = Ch | 0;
          Dl = Cl | 0;
          Ch = Bh | 0;
          Cl = Bl | 0;
          Bh = Ah | 0;
          Bl = Al | 0;
          const All = add3L(T1l, sigma0l, MAJl);
          Ah = add3H(All, T1h, sigma0h, MAJh);
          Al = All | 0;
        }
        ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
        ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
        ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
        ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
        ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
        ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
        ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
        ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
        this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
      }
      roundClean() {
        clean(SHA512_W_H, SHA512_W_L);
      }
      destroy() {
        clean(this.buffer);
        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      }
    };
    _SHA512 = class extends SHA2_64B {
      Ah = SHA512_IV[0] | 0;
      Al = SHA512_IV[1] | 0;
      Bh = SHA512_IV[2] | 0;
      Bl = SHA512_IV[3] | 0;
      Ch = SHA512_IV[4] | 0;
      Cl = SHA512_IV[5] | 0;
      Dh = SHA512_IV[6] | 0;
      Dl = SHA512_IV[7] | 0;
      Eh = SHA512_IV[8] | 0;
      El = SHA512_IV[9] | 0;
      Fh = SHA512_IV[10] | 0;
      Fl = SHA512_IV[11] | 0;
      Gh = SHA512_IV[12] | 0;
      Gl = SHA512_IV[13] | 0;
      Hh = SHA512_IV[14] | 0;
      Hl = SHA512_IV[15] | 0;
      constructor() {
        super(64);
      }
    };
    _SHA384 = class extends SHA2_64B {
      Ah = SHA384_IV[0] | 0;
      Al = SHA384_IV[1] | 0;
      Bh = SHA384_IV[2] | 0;
      Bl = SHA384_IV[3] | 0;
      Ch = SHA384_IV[4] | 0;
      Cl = SHA384_IV[5] | 0;
      Dh = SHA384_IV[6] | 0;
      Dl = SHA384_IV[7] | 0;
      Eh = SHA384_IV[8] | 0;
      El = SHA384_IV[9] | 0;
      Fh = SHA384_IV[10] | 0;
      Fl = SHA384_IV[11] | 0;
      Gh = SHA384_IV[12] | 0;
      Gl = SHA384_IV[13] | 0;
      Hh = SHA384_IV[14] | 0;
      Hl = SHA384_IV[15] | 0;
      constructor() {
        super(48);
      }
    };
    T224_IV = /* @__PURE__ */ Uint32Array.from([
      2352822216,
      424955298,
      1944164710,
      2312950998,
      502970286,
      855612546,
      1738396948,
      1479516111,
      258812777,
      2077511080,
      2011393907,
      79989058,
      1067287976,
      1780299464,
      286451373,
      2446758561
    ]);
    T256_IV = /* @__PURE__ */ Uint32Array.from([
      573645204,
      4230739756,
      2673172387,
      3360449730,
      596883563,
      1867755857,
      2520282905,
      1497426621,
      2519219938,
      2827943907,
      3193839141,
      1401305490,
      721525244,
      746961066,
      246885852,
      2177182882
    ]);
    _SHA512_224 = class extends SHA2_64B {
      Ah = T224_IV[0] | 0;
      Al = T224_IV[1] | 0;
      Bh = T224_IV[2] | 0;
      Bl = T224_IV[3] | 0;
      Ch = T224_IV[4] | 0;
      Cl = T224_IV[5] | 0;
      Dh = T224_IV[6] | 0;
      Dl = T224_IV[7] | 0;
      Eh = T224_IV[8] | 0;
      El = T224_IV[9] | 0;
      Fh = T224_IV[10] | 0;
      Fl = T224_IV[11] | 0;
      Gh = T224_IV[12] | 0;
      Gl = T224_IV[13] | 0;
      Hh = T224_IV[14] | 0;
      Hl = T224_IV[15] | 0;
      constructor() {
        super(28);
      }
    };
    _SHA512_256 = class extends SHA2_64B {
      Ah = T256_IV[0] | 0;
      Al = T256_IV[1] | 0;
      Bh = T256_IV[2] | 0;
      Bl = T256_IV[3] | 0;
      Ch = T256_IV[4] | 0;
      Cl = T256_IV[5] | 0;
      Dh = T256_IV[6] | 0;
      Dl = T256_IV[7] | 0;
      Eh = T256_IV[8] | 0;
      El = T256_IV[9] | 0;
      Fh = T256_IV[10] | 0;
      Fl = T256_IV[11] | 0;
      Gh = T256_IV[12] | 0;
      Gl = T256_IV[13] | 0;
      Hh = T256_IV[14] | 0;
      Hl = T256_IV[15] | 0;
      constructor() {
        super(32);
      }
    };
    sha256 = /* @__PURE__ */ createHasher(
      () => new _SHA256(),
      /* @__PURE__ */ oidNist(1)
    );
    sha224 = /* @__PURE__ */ createHasher(
      () => new _SHA224(),
      /* @__PURE__ */ oidNist(4)
    );
    sha512 = /* @__PURE__ */ createHasher(
      () => new _SHA512(),
      /* @__PURE__ */ oidNist(3)
    );
    sha384 = /* @__PURE__ */ createHasher(
      () => new _SHA384(),
      /* @__PURE__ */ oidNist(2)
    );
    sha512_256 = /* @__PURE__ */ createHasher(
      () => new _SHA512_256(),
      /* @__PURE__ */ oidNist(6)
    );
    sha512_224 = /* @__PURE__ */ createHasher(
      () => new _SHA512_224(),
      /* @__PURE__ */ oidNist(5)
    );
  }
});

// lib/crypto/ecc-noble.js
var require_ecc_noble = __commonJS({
  "lib/crypto/ecc-noble.js"(exports, module) {
    "use strict";
    var secp = (init_secp256k1(), __toCommonJS(secp256k1_exports));
    var { hmac: hmac2 } = (init_hmac(), __toCommonJS(hmac_exports));
    var { sha256: sha2562 } = (init_sha2(), __toCommonJS(sha2_exports));
    secp.hashes.hmacSha256 = (key, msg) => hmac2(sha2562, key, msg);
    secp.hashes.sha256 = sha2562;
    var { Point: Point2, etc: etc2, getPublicKey: getPublicKey2, sign: sign2, verify: verify2, utils: utils3 } = secp;
    var N2 = Point2.CURVE().n;
    function isPoint(p) {
      return utils3.isValidPublicKey(p);
    }
    function isPrivate(d) {
      return utils3.isValidSecretKey(d);
    }
    function pointFromScalar(d, compressed) {
      try {
        if (!isPrivate(d)) return null;
        return getPublicKey2(d, compressed !== false);
      } catch {
        return null;
      }
    }
    function pointAddScalar(p, tweak, compressed) {
      try {
        const point = Point2.fromBytes(p);
        const tweakScalar = etc2.mod(etc2.bytesToNumberBE(tweak), N2);
        let sum;
        if (tweakScalar === 0n) {
          sum = point;
        } else {
          sum = point.add(Point2.BASE.multiply(tweakScalar));
        }
        return sum.toBytes(compressed !== false);
      } catch {
        return null;
      }
    }
    function privateAdd(d, tweak) {
      let dScalar;
      try {
        dScalar = etc2.secretKeyToScalar(d);
      } catch {
        return null;
      }
      const t = etc2.mod(etc2.bytesToNumberBE(tweak), N2);
      const sum = etc2.mod(dScalar + t, N2);
      if (sum === 0n) return null;
      const out = etc2.numberToBytesBE(sum);
      if (!isPrivate(out)) return null;
      return out;
    }
    function eccSign(h, d, e) {
      const opts = { prehash: false };
      if (e !== void 0) opts.extraEntropy = e;
      return sign2(h, d, opts);
    }
    function eccVerify(h, q, signature, strict) {
      return verify2(signature, h, q, {
        prehash: false,
        lowS: strict !== false
      });
    }
    function pointCompress(p, compressed) {
      try {
        return Point2.fromBytes(p).toBytes(compressed !== false);
      } catch {
        return null;
      }
    }
    module.exports = {
      isPoint,
      isPrivate,
      pointFromScalar,
      pointAddScalar,
      privateAdd,
      sign: eccSign,
      verify: eccVerify,
      pointCompress
    };
  }
});

// node_modules/@scure/base/index.js
var base_exports = {};
__export(base_exports, {
  base16: () => base16,
  base32: () => base32,
  base32crockford: () => base32crockford,
  base32hex: () => base32hex,
  base32hexnopad: () => base32hexnopad,
  base32nopad: () => base32nopad,
  base58: () => base58,
  base58check: () => base58check,
  base58flickr: () => base58flickr,
  base58xmr: () => base58xmr,
  base58xrp: () => base58xrp,
  base64: () => base64,
  base64nopad: () => base64nopad,
  base64url: () => base64url,
  base64urlnopad: () => base64urlnopad,
  bech32: () => bech32,
  bech32m: () => bech32m,
  bytes: () => bytes,
  bytesToString: () => bytesToString,
  createBase58check: () => createBase58check,
  hex: () => hex,
  str: () => str,
  stringToBytes: () => stringToBytes,
  utf8: () => utf8,
  utils: () => utils2
});
function isBytes3(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function abytes3(b) {
  if (!isBytes3(b))
    throw new Error("Uint8Array expected");
}
function isArrayOf(isString, arr) {
  if (!Array.isArray(arr))
    return false;
  if (arr.length === 0)
    return true;
  if (isString) {
    return arr.every((item) => typeof item === "string");
  } else {
    return arr.every((item) => Number.isSafeInteger(item));
  }
}
function afn(input) {
  if (typeof input !== "function")
    throw new Error("function expected");
  return true;
}
function astr(label, input) {
  if (typeof input !== "string")
    throw new Error(`${label}: string expected`);
  return true;
}
function anumber2(n) {
  if (!Number.isSafeInteger(n))
    throw new Error(`invalid integer: ${n}`);
}
function aArr(input) {
  if (!Array.isArray(input))
    throw new Error("array expected");
}
function astrArr(label, input) {
  if (!isArrayOf(true, input))
    throw new Error(`${label}: array of strings expected`);
}
function anumArr(label, input) {
  if (!isArrayOf(false, input))
    throw new Error(`${label}: array of numbers expected`);
}
// @__NO_SIDE_EFFECTS__
function chain(...args) {
  const id = (a) => a;
  const wrap = (a, b) => (c) => a(b(c));
  const encode = args.map((x) => x.encode).reduceRight(wrap, id);
  const decode = args.map((x) => x.decode).reduce(wrap, id);
  return { encode, decode };
}
// @__NO_SIDE_EFFECTS__
function alphabet(letters) {
  const lettersA = typeof letters === "string" ? letters.split("") : letters;
  const len = lettersA.length;
  astrArr("alphabet", lettersA);
  const indexes = new Map(lettersA.map((l, i) => [l, i]));
  return {
    encode: (digits) => {
      aArr(digits);
      return digits.map((i) => {
        if (!Number.isSafeInteger(i) || i < 0 || i >= len)
          throw new Error(`alphabet.encode: digit index outside alphabet "${i}". Allowed: ${letters}`);
        return lettersA[i];
      });
    },
    decode: (input) => {
      aArr(input);
      return input.map((letter) => {
        astr("alphabet.decode", letter);
        const i = indexes.get(letter);
        if (i === void 0)
          throw new Error(`Unknown letter: "${letter}". Allowed: ${letters}`);
        return i;
      });
    }
  };
}
// @__NO_SIDE_EFFECTS__
function join(separator = "") {
  astr("join", separator);
  return {
    encode: (from) => {
      astrArr("join.decode", from);
      return from.join(separator);
    },
    decode: (to) => {
      astr("join.decode", to);
      return to.split(separator);
    }
  };
}
// @__NO_SIDE_EFFECTS__
function padding(bits, chr = "=") {
  anumber2(bits);
  astr("padding", chr);
  return {
    encode(data) {
      astrArr("padding.encode", data);
      while (data.length * bits % 8)
        data.push(chr);
      return data;
    },
    decode(input) {
      astrArr("padding.decode", input);
      let end = input.length;
      if (end * bits % 8)
        throw new Error("padding: invalid, string should have whole number of bytes");
      for (; end > 0 && input[end - 1] === chr; end--) {
        const last = end - 1;
        const byte = last * bits;
        if (byte % 8 === 0)
          throw new Error("padding: invalid, string has too much padding");
      }
      return input.slice(0, end);
    }
  };
}
// @__NO_SIDE_EFFECTS__
function normalize(fn) {
  afn(fn);
  return { encode: (from) => from, decode: (to) => fn(to) };
}
function convertRadix(data, from, to) {
  if (from < 2)
    throw new Error(`convertRadix: invalid from=${from}, base cannot be less than 2`);
  if (to < 2)
    throw new Error(`convertRadix: invalid to=${to}, base cannot be less than 2`);
  aArr(data);
  if (!data.length)
    return [];
  let pos = 0;
  const res = [];
  const digits = Array.from(data, (d) => {
    anumber2(d);
    if (d < 0 || d >= from)
      throw new Error(`invalid integer: ${d}`);
    return d;
  });
  const dlen = digits.length;
  while (true) {
    let carry = 0;
    let done = true;
    for (let i = pos; i < dlen; i++) {
      const digit = digits[i];
      const fromCarry = from * carry;
      const digitBase = fromCarry + digit;
      if (!Number.isSafeInteger(digitBase) || fromCarry / from !== carry || digitBase - digit !== fromCarry) {
        throw new Error("convertRadix: carry overflow");
      }
      const div = digitBase / to;
      carry = digitBase % to;
      const rounded = Math.floor(div);
      digits[i] = rounded;
      if (!Number.isSafeInteger(rounded) || rounded * to + carry !== digitBase)
        throw new Error("convertRadix: carry overflow");
      if (!done)
        continue;
      else if (!rounded)
        pos = i;
      else
        done = false;
    }
    res.push(carry);
    if (done)
      break;
  }
  for (let i = 0; i < data.length - 1 && data[i] === 0; i++)
    res.push(0);
  return res.reverse();
}
function convertRadix2(data, from, to, padding2) {
  aArr(data);
  if (from <= 0 || from > 32)
    throw new Error(`convertRadix2: wrong from=${from}`);
  if (to <= 0 || to > 32)
    throw new Error(`convertRadix2: wrong to=${to}`);
  if (/* @__PURE__ */ radix2carry(from, to) > 32) {
    throw new Error(`convertRadix2: carry overflow from=${from} to=${to} carryBits=${/* @__PURE__ */ radix2carry(from, to)}`);
  }
  let carry = 0;
  let pos = 0;
  const max = powers[from];
  const mask = powers[to] - 1;
  const res = [];
  for (const n of data) {
    anumber2(n);
    if (n >= max)
      throw new Error(`convertRadix2: invalid data word=${n} from=${from}`);
    carry = carry << from | n;
    if (pos + from > 32)
      throw new Error(`convertRadix2: carry overflow pos=${pos} from=${from}`);
    pos += from;
    for (; pos >= to; pos -= to)
      res.push((carry >> pos - to & mask) >>> 0);
    const pow = powers[pos];
    if (pow === void 0)
      throw new Error("invalid carry");
    carry &= pow - 1;
  }
  carry = carry << to - pos & mask;
  if (!padding2 && pos >= from)
    throw new Error("Excess padding");
  if (!padding2 && carry > 0)
    throw new Error(`Non-zero padding: ${carry}`);
  if (padding2 && pos > 0)
    res.push(carry >>> 0);
  return res;
}
// @__NO_SIDE_EFFECTS__
function radix(num) {
  anumber2(num);
  const _256 = 2 ** 8;
  return {
    encode: (bytes2) => {
      if (!isBytes3(bytes2))
        throw new Error("radix.encode input should be Uint8Array");
      return convertRadix(Array.from(bytes2), _256, num);
    },
    decode: (digits) => {
      anumArr("radix.decode", digits);
      return Uint8Array.from(convertRadix(digits, num, _256));
    }
  };
}
// @__NO_SIDE_EFFECTS__
function radix2(bits, revPadding = false) {
  anumber2(bits);
  if (bits <= 0 || bits > 32)
    throw new Error("radix2: bits should be in (0..32]");
  if (/* @__PURE__ */ radix2carry(8, bits) > 32 || /* @__PURE__ */ radix2carry(bits, 8) > 32)
    throw new Error("radix2: carry overflow");
  return {
    encode: (bytes2) => {
      if (!isBytes3(bytes2))
        throw new Error("radix2.encode input should be Uint8Array");
      return convertRadix2(Array.from(bytes2), 8, bits, !revPadding);
    },
    decode: (digits) => {
      anumArr("radix2.decode", digits);
      return Uint8Array.from(convertRadix2(digits, bits, 8, revPadding));
    }
  };
}
function unsafeWrapper(fn) {
  afn(fn);
  return function(...args) {
    try {
      return fn.apply(null, args);
    } catch (e) {
    }
  };
}
function checksum(len, fn) {
  anumber2(len);
  afn(fn);
  return {
    encode(data) {
      if (!isBytes3(data))
        throw new Error("checksum.encode: input should be Uint8Array");
      const sum = fn(data).slice(0, len);
      const res = new Uint8Array(data.length + len);
      res.set(data);
      res.set(sum, data.length);
      return res;
    },
    decode(data) {
      if (!isBytes3(data))
        throw new Error("checksum.decode: input should be Uint8Array");
      const payload = data.slice(0, -len);
      const oldChecksum = data.slice(-len);
      const newChecksum = fn(payload).slice(0, len);
      for (let i = 0; i < len; i++)
        if (newChecksum[i] !== oldChecksum[i])
          throw new Error("Invalid checksum");
      return payload;
    }
  };
}
function bech32Polymod(pre) {
  const b = pre >> 25;
  let chk = (pre & 33554431) << 5;
  for (let i = 0; i < POLYMOD_GENERATORS.length; i++) {
    if ((b >> i & 1) === 1)
      chk ^= POLYMOD_GENERATORS[i];
  }
  return chk;
}
function bechChecksum(prefix, words, encodingConst = 1) {
  const len = prefix.length;
  let chk = 1;
  for (let i = 0; i < len; i++) {
    const c = prefix.charCodeAt(i);
    if (c < 33 || c > 126)
      throw new Error(`Invalid prefix (${prefix})`);
    chk = bech32Polymod(chk) ^ c >> 5;
  }
  chk = bech32Polymod(chk);
  for (let i = 0; i < len; i++)
    chk = bech32Polymod(chk) ^ prefix.charCodeAt(i) & 31;
  for (let v of words)
    chk = bech32Polymod(chk) ^ v;
  for (let i = 0; i < 6; i++)
    chk = bech32Polymod(chk);
  chk ^= encodingConst;
  return BECH_ALPHABET.encode(convertRadix2([chk % powers[30]], 30, 5, false));
}
// @__NO_SIDE_EFFECTS__
function genBech32(encoding) {
  const ENCODING_CONST = encoding === "bech32" ? 1 : 734539939;
  const _words = /* @__PURE__ */ radix2(5);
  const fromWords = _words.decode;
  const toWords = _words.encode;
  const fromWordsUnsafe = unsafeWrapper(fromWords);
  function encode(prefix, words, limit = 90) {
    astr("bech32.encode prefix", prefix);
    if (isBytes3(words))
      words = Array.from(words);
    anumArr("bech32.encode", words);
    const plen = prefix.length;
    if (plen === 0)
      throw new TypeError(`Invalid prefix length ${plen}`);
    const actualLength = plen + 7 + words.length;
    if (limit !== false && actualLength > limit)
      throw new TypeError(`Length ${actualLength} exceeds limit ${limit}`);
    const lowered = prefix.toLowerCase();
    const sum = bechChecksum(lowered, words, ENCODING_CONST);
    return `${lowered}1${BECH_ALPHABET.encode(words)}${sum}`;
  }
  function decode(str2, limit = 90) {
    astr("bech32.decode input", str2);
    const slen = str2.length;
    if (slen < 8 || limit !== false && slen > limit)
      throw new TypeError(`invalid string length: ${slen} (${str2}). Expected (8..${limit})`);
    const lowered = str2.toLowerCase();
    if (str2 !== lowered && str2 !== str2.toUpperCase())
      throw new Error(`String must be lowercase or uppercase`);
    const sepIndex = lowered.lastIndexOf("1");
    if (sepIndex === 0 || sepIndex === -1)
      throw new Error(`Letter "1" must be present between prefix and data only`);
    const prefix = lowered.slice(0, sepIndex);
    const data = lowered.slice(sepIndex + 1);
    if (data.length < 6)
      throw new Error("Data must be at least 6 characters long");
    const words = BECH_ALPHABET.decode(data).slice(0, -6);
    const sum = bechChecksum(prefix, words, ENCODING_CONST);
    if (!data.endsWith(sum))
      throw new Error(`Invalid checksum in ${str2}: expected "${sum}"`);
    return { prefix, words };
  }
  const decodeUnsafe = unsafeWrapper(decode);
  function decodeToBytes(str2) {
    const { prefix, words } = decode(str2, false);
    return { prefix, words, bytes: fromWords(words) };
  }
  function encodeFromBytes(prefix, bytes2) {
    return encode(prefix, toWords(bytes2));
  }
  return {
    encode,
    decode,
    encodeFromBytes,
    decodeToBytes,
    decodeUnsafe,
    fromWords,
    fromWordsUnsafe,
    toWords
  };
}
var gcd, radix2carry, powers, utils2, base16, base32, base32nopad, base32hex, base32hexnopad, base32crockford, hasBase64Builtin, decodeBase64Builtin, base64, base64nopad, base64url, base64urlnopad, genBase58, base58, base58flickr, base58xrp, XMR_BLOCK_LEN, base58xmr, createBase58check, base58check, BECH_ALPHABET, POLYMOD_GENERATORS, bech32, bech32m, utf8, hasHexBuiltin, hexBuiltin, hex, CODERS, coderTypeError, bytesToString, str, stringToBytes, bytes;
var init_base = __esm({
  "node_modules/@scure/base/index.js"() {
    gcd = (a, b) => b === 0 ? a : gcd(b, a % b);
    radix2carry = /* @__NO_SIDE_EFFECTS__ */ (from, to) => from + (to - gcd(from, to));
    powers = /* @__PURE__ */ (() => {
      let res = [];
      for (let i = 0; i < 40; i++)
        res.push(2 ** i);
      return res;
    })();
    utils2 = {
      alphabet,
      chain,
      checksum,
      convertRadix,
      convertRadix2,
      radix,
      radix2,
      join,
      padding
    };
    base16 = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(4), /* @__PURE__ */ alphabet("0123456789ABCDEF"), /* @__PURE__ */ join(""));
    base32 = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(5), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), /* @__PURE__ */ padding(5), /* @__PURE__ */ join(""));
    base32nopad = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(5), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), /* @__PURE__ */ join(""));
    base32hex = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(5), /* @__PURE__ */ alphabet("0123456789ABCDEFGHIJKLMNOPQRSTUV"), /* @__PURE__ */ padding(5), /* @__PURE__ */ join(""));
    base32hexnopad = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(5), /* @__PURE__ */ alphabet("0123456789ABCDEFGHIJKLMNOPQRSTUV"), /* @__PURE__ */ join(""));
    base32crockford = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(5), /* @__PURE__ */ alphabet("0123456789ABCDEFGHJKMNPQRSTVWXYZ"), /* @__PURE__ */ join(""), /* @__PURE__ */ normalize((s) => s.toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1")));
    hasBase64Builtin = /* @__PURE__ */ (() => typeof Uint8Array.from([]).toBase64 === "function" && typeof Uint8Array.fromBase64 === "function")();
    decodeBase64Builtin = (s, isUrl) => {
      astr("base64", s);
      const re = isUrl ? /^[A-Za-z0-9=_-]+$/ : /^[A-Za-z0-9=+/]+$/;
      const alphabet2 = isUrl ? "base64url" : "base64";
      if (s.length > 0 && !re.test(s))
        throw new Error("invalid base64");
      return Uint8Array.fromBase64(s, { alphabet: alphabet2, lastChunkHandling: "strict" });
    };
    base64 = hasBase64Builtin ? {
      encode(b) {
        abytes3(b);
        return b.toBase64();
      },
      decode(s) {
        return decodeBase64Builtin(s, false);
      }
    } : /* @__PURE__ */ chain(/* @__PURE__ */ radix2(6), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), /* @__PURE__ */ padding(6), /* @__PURE__ */ join(""));
    base64nopad = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(6), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), /* @__PURE__ */ join(""));
    base64url = hasBase64Builtin ? {
      encode(b) {
        abytes3(b);
        return b.toBase64({ alphabet: "base64url" });
      },
      decode(s) {
        return decodeBase64Builtin(s, true);
      }
    } : /* @__PURE__ */ chain(/* @__PURE__ */ radix2(6), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), /* @__PURE__ */ padding(6), /* @__PURE__ */ join(""));
    base64urlnopad = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(6), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), /* @__PURE__ */ join(""));
    genBase58 = /* @__NO_SIDE_EFFECTS__ */ (abc) => /* @__PURE__ */ chain(/* @__PURE__ */ radix(58), /* @__PURE__ */ alphabet(abc), /* @__PURE__ */ join(""));
    base58 = /* @__PURE__ */ genBase58("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
    base58flickr = /* @__PURE__ */ genBase58("123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ");
    base58xrp = /* @__PURE__ */ genBase58("rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz");
    XMR_BLOCK_LEN = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    base58xmr = {
      encode(data) {
        let res = "";
        for (let i = 0; i < data.length; i += 8) {
          const block = data.subarray(i, i + 8);
          res += base58.encode(block).padStart(XMR_BLOCK_LEN[block.length], "1");
        }
        return res;
      },
      decode(str2) {
        let res = [];
        for (let i = 0; i < str2.length; i += 11) {
          const slice = str2.slice(i, i + 11);
          const blockLen = XMR_BLOCK_LEN.indexOf(slice.length);
          const block = base58.decode(slice);
          for (let j = 0; j < block.length - blockLen; j++) {
            if (block[j] !== 0)
              throw new Error("base58xmr: wrong padding");
          }
          res = res.concat(Array.from(block.slice(block.length - blockLen)));
        }
        return Uint8Array.from(res);
      }
    };
    createBase58check = (sha2562) => /* @__PURE__ */ chain(checksum(4, (data) => sha2562(sha2562(data))), base58);
    base58check = createBase58check;
    BECH_ALPHABET = /* @__PURE__ */ chain(/* @__PURE__ */ alphabet("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), /* @__PURE__ */ join(""));
    POLYMOD_GENERATORS = [996825010, 642813549, 513874426, 1027748829, 705979059];
    bech32 = /* @__PURE__ */ genBech32("bech32");
    bech32m = /* @__PURE__ */ genBech32("bech32m");
    utf8 = {
      encode: (data) => new TextDecoder().decode(data),
      decode: (str2) => new TextEncoder().encode(str2)
    };
    hasHexBuiltin = /* @__PURE__ */ (() => typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function")();
    hexBuiltin = {
      encode(data) {
        abytes3(data);
        return data.toHex();
      },
      decode(s) {
        astr("hex", s);
        return Uint8Array.fromHex(s);
      }
    };
    hex = hasHexBuiltin ? hexBuiltin : /* @__PURE__ */ chain(/* @__PURE__ */ radix2(4), /* @__PURE__ */ alphabet("0123456789abcdef"), /* @__PURE__ */ join(""), /* @__PURE__ */ normalize((s) => {
      if (typeof s !== "string" || s.length % 2 !== 0)
        throw new TypeError(`hex.decode: expected string, got ${typeof s} with length ${s.length}`);
      return s.toLowerCase();
    }));
    CODERS = {
      utf8,
      hex,
      base16,
      base32,
      base64,
      base64url,
      base58,
      base58xmr
    };
    coderTypeError = "Invalid encoding type. Available types: utf8, hex, base16, base32, base64, base64url, base58, base58xmr";
    bytesToString = (type, bytes2) => {
      if (typeof type !== "string" || !CODERS.hasOwnProperty(type))
        throw new TypeError(coderTypeError);
      if (!isBytes3(bytes2))
        throw new TypeError("bytesToString() expects Uint8Array");
      return CODERS[type].encode(bytes2);
    };
    str = bytesToString;
    stringToBytes = (type, str2) => {
      if (!CODERS.hasOwnProperty(type))
        throw new TypeError(coderTypeError);
      if (typeof str2 !== "string")
        throw new TypeError("stringToBytes() expects string");
      return CODERS[type].decode(str2);
    };
    bytes = stringToBytes;
  }
});

// node_modules/@noble/hashes/sha3.js
var sha3_exports = {};
__export(sha3_exports, {
  Keccak: () => Keccak,
  keccakP: () => keccakP,
  keccak_224: () => keccak_224,
  keccak_256: () => keccak_256,
  keccak_384: () => keccak_384,
  keccak_512: () => keccak_512,
  sha3_224: () => sha3_224,
  sha3_256: () => sha3_256,
  sha3_384: () => sha3_384,
  sha3_512: () => sha3_512,
  shake128: () => shake128,
  shake128_32: () => shake128_32,
  shake256: () => shake256,
  shake256_64: () => shake256_64
});
function keccakP(s, rounds = 24) {
  const B = new Uint32Array(5 * 2);
  for (let round = 24 - rounds; round < 24; round++) {
    for (let x = 0; x < 10; x++)
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0; x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0; y < 50; y += 10) {
      for (let x = 0; x < 10; x++)
        B[x] = s[y + x];
      for (let x = 0; x < 10; x++)
        s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  clean(B);
}
var _0n, _1n, _2n, _7n, _256n, _0x71n, SHA3_PI, SHA3_ROTL, _SHA3_IOTA, IOTAS, SHA3_IOTA_H, SHA3_IOTA_L, rotlH, rotlL, Keccak, genKeccak, sha3_224, sha3_256, sha3_384, sha3_512, keccak_224, keccak_256, keccak_384, keccak_512, genShake, shake128, shake256, shake128_32, shake256_64;
var init_sha3 = __esm({
  "node_modules/@noble/hashes/sha3.js"() {
    init_u64();
    init_utils();
    _0n = BigInt(0);
    _1n = BigInt(1);
    _2n = BigInt(2);
    _7n = BigInt(7);
    _256n = BigInt(256);
    _0x71n = BigInt(113);
    SHA3_PI = [];
    SHA3_ROTL = [];
    _SHA3_IOTA = [];
    for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
      [x, y] = [y, (2 * x + 3 * y) % 5];
      SHA3_PI.push(2 * (5 * y + x));
      SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
      let t = _0n;
      for (let j = 0; j < 7; j++) {
        R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
        if (R & _2n)
          t ^= _1n << (_1n << BigInt(j)) - _1n;
      }
      _SHA3_IOTA.push(t);
    }
    IOTAS = split(_SHA3_IOTA, true);
    SHA3_IOTA_H = IOTAS[0];
    SHA3_IOTA_L = IOTAS[1];
    rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
    rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
    Keccak = class _Keccak {
      state;
      pos = 0;
      posOut = 0;
      finished = false;
      state32;
      destroyed = false;
      blockLen;
      suffix;
      outputLen;
      enableXOF = false;
      rounds;
      // NOTE: we accept arguments in bytes instead of bits here.
      constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
        this.blockLen = blockLen;
        this.suffix = suffix;
        this.outputLen = outputLen;
        this.enableXOF = enableXOF;
        this.rounds = rounds;
        anumber(outputLen, "outputLen");
        if (!(0 < blockLen && blockLen < 200))
          throw new Error("only keccak-f1600 function is supported");
        this.state = new Uint8Array(200);
        this.state32 = u32(this.state);
      }
      clone() {
        return this._cloneInto();
      }
      keccak() {
        swap32IfBE(this.state32);
        keccakP(this.state32, this.rounds);
        swap32IfBE(this.state32);
        this.posOut = 0;
        this.pos = 0;
      }
      update(data) {
        aexists(this);
        abytes2(data);
        const { blockLen, state } = this;
        const len = data.length;
        for (let pos = 0; pos < len; ) {
          const take = Math.min(blockLen - this.pos, len - pos);
          for (let i = 0; i < take; i++)
            state[this.pos++] ^= data[pos++];
          if (this.pos === blockLen)
            this.keccak();
        }
        return this;
      }
      finish() {
        if (this.finished)
          return;
        this.finished = true;
        const { state, suffix, pos, blockLen } = this;
        state[pos] ^= suffix;
        if ((suffix & 128) !== 0 && pos === blockLen - 1)
          this.keccak();
        state[blockLen - 1] ^= 128;
        this.keccak();
      }
      writeInto(out) {
        aexists(this, false);
        abytes2(out);
        this.finish();
        const bufferOut = this.state;
        const { blockLen } = this;
        for (let pos = 0, len = out.length; pos < len; ) {
          if (this.posOut >= blockLen)
            this.keccak();
          const take = Math.min(blockLen - this.posOut, len - pos);
          out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
          this.posOut += take;
          pos += take;
        }
        return out;
      }
      xofInto(out) {
        if (!this.enableXOF)
          throw new Error("XOF is not possible for this instance");
        return this.writeInto(out);
      }
      xof(bytes2) {
        anumber(bytes2);
        return this.xofInto(new Uint8Array(bytes2));
      }
      digestInto(out) {
        aoutput(out, this);
        if (this.finished)
          throw new Error("digest() was already called");
        this.writeInto(out);
        this.destroy();
        return out;
      }
      digest() {
        return this.digestInto(new Uint8Array(this.outputLen));
      }
      destroy() {
        this.destroyed = true;
        clean(this.state);
      }
      _cloneInto(to) {
        const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
        to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
        to.state32.set(this.state32);
        to.pos = this.pos;
        to.posOut = this.posOut;
        to.finished = this.finished;
        to.rounds = rounds;
        to.suffix = suffix;
        to.outputLen = outputLen;
        to.enableXOF = enableXOF;
        to.destroyed = this.destroyed;
        return to;
      }
    };
    genKeccak = (suffix, blockLen, outputLen, info = {}) => createHasher(() => new Keccak(blockLen, suffix, outputLen), info);
    sha3_224 = /* @__PURE__ */ genKeccak(
      6,
      144,
      28,
      /* @__PURE__ */ oidNist(7)
    );
    sha3_256 = /* @__PURE__ */ genKeccak(
      6,
      136,
      32,
      /* @__PURE__ */ oidNist(8)
    );
    sha3_384 = /* @__PURE__ */ genKeccak(
      6,
      104,
      48,
      /* @__PURE__ */ oidNist(9)
    );
    sha3_512 = /* @__PURE__ */ genKeccak(
      6,
      72,
      64,
      /* @__PURE__ */ oidNist(10)
    );
    keccak_224 = /* @__PURE__ */ genKeccak(1, 144, 28);
    keccak_256 = /* @__PURE__ */ genKeccak(1, 136, 32);
    keccak_384 = /* @__PURE__ */ genKeccak(1, 104, 48);
    keccak_512 = /* @__PURE__ */ genKeccak(1, 72, 64);
    genShake = (suffix, blockLen, outputLen, info = {}) => createHasher((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === void 0 ? outputLen : opts.dkLen, true), info);
    shake128 = /* @__PURE__ */ genShake(31, 168, 16, /* @__PURE__ */ oidNist(11));
    shake256 = /* @__PURE__ */ genShake(31, 136, 32, /* @__PURE__ */ oidNist(12));
    shake128_32 = /* @__PURE__ */ genShake(31, 168, 32, /* @__PURE__ */ oidNist(11));
    shake256_64 = /* @__PURE__ */ genShake(31, 136, 64, /* @__PURE__ */ oidNist(12));
  }
});

// lib/tron/address.js
var require_address = __commonJS({
  "lib/tron/address.js"(exports, module) {
    "use strict";
    var ecc = require_ecc_noble();
    var { createBase58check: createBase58check2 } = (init_base(), __toCommonJS(base_exports));
    var { sha256: sha2562 } = (init_sha2(), __toCommonJS(sha2_exports));
    var { keccak_256: keccak_2562 } = (init_sha3(), __toCommonJS(sha3_exports));
    var { TRON_ADDRESS_VERSION_BYTE } = require_constants();
    var tronBase58Check = createBase58check2((data) => sha2562(data));
    function asBuffer(bytes2) {
      return Buffer.isBuffer(bytes2) ? bytes2 : Buffer.from(bytes2);
    }
    function publicKeyUncompressedToTronAddress(uncompressedPubKey) {
      const pub = asBuffer(uncompressedPubKey);
      if (pub.length !== 65) {
        throw new Error(`Expected 65-byte uncompressed key, got ${pub.length}`);
      }
      if (pub[0] !== 4) {
        throw new Error("Uncompressed key must start with 0x04");
      }
      const xy = pub.subarray(1, 65);
      const hash2 = Buffer.from(keccak_2562(xy));
      const payload = Buffer.concat([
        Buffer.from([TRON_ADDRESS_VERSION_BYTE]),
        hash2.subarray(-20)
      ]);
      return tronBase58Check.encode(payload);
    }
    function compressedPublicKeyToTronAddress(compressedPubKey) {
      const uncompressed = ecc.pointCompress(asBuffer(compressedPubKey), false);
      if (!uncompressed) {
        throw new Error("pointCompress: failed to decompress public key");
      }
      return publicKeyUncompressedToTronAddress(asBuffer(uncompressed));
    }
    function tronAddressBase58ToHex(base58Address) {
      const raw = Buffer.from(tronBase58Check.decode(base58Address));
      return `0x${raw.toString("hex")}`;
    }
    function decodeTronAddressBase58Checked(base58Address) {
      const s = String(base58Address).trim();
      let raw;
      try {
        raw = Buffer.from(tronBase58Check.decode(s));
      } catch {
        throw new Error("Invalid TRON address: bad Base58Check");
      }
      if (raw.length !== 21) {
        throw new Error(
          `Invalid TRON address: expected 21 bytes after decode, got ${raw.length}`
        );
      }
      if (raw[0] !== TRON_ADDRESS_VERSION_BYTE) {
        throw new Error(
          "Invalid TRON address: first byte must be 0x41 (mainnet)"
        );
      }
      return raw;
    }
    function encodeTronBase58CheckPayload(rawPayload) {
      return tronBase58Check.encode(rawPayload);
    }
    module.exports = {
      asBuffer,
      publicKeyUncompressedToTronAddress,
      compressedPublicKeyToTronAddress,
      tronAddressBase58ToHex,
      decodeTronAddressBase58Checked,
      encodeTronBase58CheckPayload
    };
  }
});

// node_modules/bip39/node_modules/@noble/hashes/crypto.js
var require_crypto = __commonJS({
  "node_modules/bip39/node_modules/@noble/hashes/crypto.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.crypto = void 0;
    exports.crypto = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0;
  }
});

// node_modules/bip39/node_modules/@noble/hashes/utils.js
var require_utils = __commonJS({
  "node_modules/bip39/node_modules/@noble/hashes/utils.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.wrapXOFConstructorWithOpts = exports.wrapConstructorWithOpts = exports.wrapConstructor = exports.Hash = exports.nextTick = exports.swap32IfBE = exports.byteSwapIfBE = exports.swap8IfBE = exports.isLE = void 0;
    exports.isBytes = isBytes4;
    exports.anumber = anumber3;
    exports.abytes = abytes4;
    exports.ahash = ahash2;
    exports.aexists = aexists2;
    exports.aoutput = aoutput2;
    exports.u8 = u8;
    exports.u32 = u322;
    exports.clean = clean2;
    exports.createView = createView2;
    exports.rotr = rotr2;
    exports.rotl = rotl;
    exports.byteSwap = byteSwap2;
    exports.byteSwap32 = byteSwap322;
    exports.bytesToHex = bytesToHex2;
    exports.hexToBytes = hexToBytes2;
    exports.asyncLoop = asyncLoop;
    exports.utf8ToBytes = utf8ToBytes;
    exports.bytesToUtf8 = bytesToUtf8;
    exports.toBytes = toBytes;
    exports.kdfInputToBytes = kdfInputToBytes;
    exports.concatBytes = concatBytes2;
    exports.checkOpts = checkOpts;
    exports.createHasher = createHasher2;
    exports.createOptHasher = createOptHasher;
    exports.createXOFer = createXOFer;
    exports.randomBytes = randomBytes2;
    var crypto_1 = require_crypto();
    function isBytes4(a) {
      return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
    }
    function anumber3(n) {
      if (!Number.isSafeInteger(n) || n < 0)
        throw new Error("positive integer expected, got " + n);
    }
    function abytes4(b, ...lengths2) {
      if (!isBytes4(b))
        throw new Error("Uint8Array expected");
      if (lengths2.length > 0 && !lengths2.includes(b.length))
        throw new Error("Uint8Array expected of length " + lengths2 + ", got length=" + b.length);
    }
    function ahash2(h) {
      if (typeof h !== "function" || typeof h.create !== "function")
        throw new Error("Hash should be wrapped by utils.createHasher");
      anumber3(h.outputLen);
      anumber3(h.blockLen);
    }
    function aexists2(instance, checkFinished = true) {
      if (instance.destroyed)
        throw new Error("Hash instance has been destroyed");
      if (checkFinished && instance.finished)
        throw new Error("Hash#digest() has already been called");
    }
    function aoutput2(out, instance) {
      abytes4(out);
      const min = instance.outputLen;
      if (out.length < min) {
        throw new Error("digestInto() expects output buffer of length at least " + min);
      }
    }
    function u8(arr) {
      return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
    }
    function u322(arr) {
      return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
    }
    function clean2(...arrays) {
      for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
      }
    }
    function createView2(arr) {
      return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    }
    function rotr2(word, shift) {
      return word << 32 - shift | word >>> shift;
    }
    function rotl(word, shift) {
      return word << shift | word >>> 32 - shift >>> 0;
    }
    exports.isLE = (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
    function byteSwap2(word) {
      return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
    }
    exports.swap8IfBE = exports.isLE ? (n) => n : (n) => byteSwap2(n);
    exports.byteSwapIfBE = exports.swap8IfBE;
    function byteSwap322(arr) {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = byteSwap2(arr[i]);
      }
      return arr;
    }
    exports.swap32IfBE = exports.isLE ? (u) => u : byteSwap322;
    var hasHexBuiltin2 = /* @__PURE__ */ (() => (
      // @ts-ignore
      typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
    ))();
    var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
    function bytesToHex2(bytes2) {
      abytes4(bytes2);
      if (hasHexBuiltin2)
        return bytes2.toHex();
      let hex2 = "";
      for (let i = 0; i < bytes2.length; i++) {
        hex2 += hexes[bytes2[i]];
      }
      return hex2;
    }
    var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
    function asciiToBase16(ch) {
      if (ch >= asciis._0 && ch <= asciis._9)
        return ch - asciis._0;
      if (ch >= asciis.A && ch <= asciis.F)
        return ch - (asciis.A - 10);
      if (ch >= asciis.a && ch <= asciis.f)
        return ch - (asciis.a - 10);
      return;
    }
    function hexToBytes2(hex2) {
      if (typeof hex2 !== "string")
        throw new Error("hex string expected, got " + typeof hex2);
      if (hasHexBuiltin2)
        return Uint8Array.fromHex(hex2);
      const hl = hex2.length;
      const al = hl / 2;
      if (hl % 2)
        throw new Error("hex string expected, got unpadded hex of length " + hl);
      const array = new Uint8Array(al);
      for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex2.charCodeAt(hi));
        const n2 = asciiToBase16(hex2.charCodeAt(hi + 1));
        if (n1 === void 0 || n2 === void 0) {
          const char = hex2[hi] + hex2[hi + 1];
          throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2;
      }
      return array;
    }
    var nextTick = async () => {
    };
    exports.nextTick = nextTick;
    async function asyncLoop(iters, tick, cb) {
      let ts = Date.now();
      for (let i = 0; i < iters; i++) {
        cb(i);
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick)
          continue;
        await (0, exports.nextTick)();
        ts += diff;
      }
    }
    function utf8ToBytes(str2) {
      if (typeof str2 !== "string")
        throw new Error("string expected");
      return new Uint8Array(new TextEncoder().encode(str2));
    }
    function bytesToUtf8(bytes2) {
      return new TextDecoder().decode(bytes2);
    }
    function toBytes(data) {
      if (typeof data === "string")
        data = utf8ToBytes(data);
      abytes4(data);
      return data;
    }
    function kdfInputToBytes(data) {
      if (typeof data === "string")
        data = utf8ToBytes(data);
      abytes4(data);
      return data;
    }
    function concatBytes2(...arrays) {
      let sum = 0;
      for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        abytes4(a);
        sum += a.length;
      }
      const res = new Uint8Array(sum);
      for (let i = 0, pad = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
      }
      return res;
    }
    function checkOpts(defaults, opts) {
      if (opts !== void 0 && {}.toString.call(opts) !== "[object Object]")
        throw new Error("options should be object or undefined");
      const merged = Object.assign(defaults, opts);
      return merged;
    }
    var Hash = class {
    };
    exports.Hash = Hash;
    function createHasher2(hashCons) {
      const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
      const tmp = hashCons();
      hashC.outputLen = tmp.outputLen;
      hashC.blockLen = tmp.blockLen;
      hashC.create = () => hashCons();
      return hashC;
    }
    function createOptHasher(hashCons) {
      const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
      const tmp = hashCons({});
      hashC.outputLen = tmp.outputLen;
      hashC.blockLen = tmp.blockLen;
      hashC.create = (opts) => hashCons(opts);
      return hashC;
    }
    function createXOFer(hashCons) {
      const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
      const tmp = hashCons({});
      hashC.outputLen = tmp.outputLen;
      hashC.blockLen = tmp.blockLen;
      hashC.create = (opts) => hashCons(opts);
      return hashC;
    }
    exports.wrapConstructor = createHasher2;
    exports.wrapConstructorWithOpts = createOptHasher;
    exports.wrapXOFConstructorWithOpts = createXOFer;
    function randomBytes2(bytesLength = 32) {
      if (crypto_1.crypto && typeof crypto_1.crypto.getRandomValues === "function") {
        return crypto_1.crypto.getRandomValues(new Uint8Array(bytesLength));
      }
      if (crypto_1.crypto && typeof crypto_1.crypto.randomBytes === "function") {
        return Uint8Array.from(crypto_1.crypto.randomBytes(bytesLength));
      }
      throw new Error("crypto.getRandomValues must be defined");
    }
  }
});

// node_modules/bip39/node_modules/@noble/hashes/_md.js
var require_md = __commonJS({
  "node_modules/bip39/node_modules/@noble/hashes/_md.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.SHA512_IV = exports.SHA384_IV = exports.SHA224_IV = exports.SHA256_IV = exports.HashMD = void 0;
    exports.setBigUint64 = setBigUint64;
    exports.Chi = Chi2;
    exports.Maj = Maj2;
    var utils_ts_1 = require_utils();
    function setBigUint64(view, byteOffset, value, isLE2) {
      if (typeof view.setBigUint64 === "function")
        return view.setBigUint64(byteOffset, value, isLE2);
      const _32n2 = BigInt(32);
      const _u32_max = BigInt(4294967295);
      const wh = Number(value >> _32n2 & _u32_max);
      const wl = Number(value & _u32_max);
      const h = isLE2 ? 4 : 0;
      const l = isLE2 ? 0 : 4;
      view.setUint32(byteOffset + h, wh, isLE2);
      view.setUint32(byteOffset + l, wl, isLE2);
    }
    function Chi2(a, b, c) {
      return a & b ^ ~a & c;
    }
    function Maj2(a, b, c) {
      return a & b ^ a & c ^ b & c;
    }
    var HashMD2 = class extends utils_ts_1.Hash {
      constructor(blockLen, outputLen, padOffset, isLE2) {
        super();
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE2;
        this.buffer = new Uint8Array(blockLen);
        this.view = (0, utils_ts_1.createView)(this.buffer);
      }
      update(data) {
        (0, utils_ts_1.aexists)(this);
        data = (0, utils_ts_1.toBytes)(data);
        (0, utils_ts_1.abytes)(data);
        const { view, buffer, blockLen } = this;
        const len = data.length;
        for (let pos = 0; pos < len; ) {
          const take = Math.min(blockLen - this.pos, len - pos);
          if (take === blockLen) {
            const dataView = (0, utils_ts_1.createView)(data);
            for (; blockLen <= len - pos; pos += blockLen)
              this.process(dataView, pos);
            continue;
          }
          buffer.set(data.subarray(pos, pos + take), this.pos);
          this.pos += take;
          pos += take;
          if (this.pos === blockLen) {
            this.process(view, 0);
            this.pos = 0;
          }
        }
        this.length += data.length;
        this.roundClean();
        return this;
      }
      digestInto(out) {
        (0, utils_ts_1.aexists)(this);
        (0, utils_ts_1.aoutput)(out, this);
        this.finished = true;
        const { buffer, view, blockLen, isLE: isLE2 } = this;
        let { pos } = this;
        buffer[pos++] = 128;
        (0, utils_ts_1.clean)(this.buffer.subarray(pos));
        if (this.padOffset > blockLen - pos) {
          this.process(view, 0);
          pos = 0;
        }
        for (let i = pos; i < blockLen; i++)
          buffer[i] = 0;
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
        this.process(view, 0);
        const oview = (0, utils_ts_1.createView)(out);
        const len = this.outputLen;
        if (len % 4)
          throw new Error("_sha2: outputLen should be aligned to 32bit");
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
          throw new Error("_sha2: outputLen bigger than state");
        for (let i = 0; i < outLen; i++)
          oview.setUint32(4 * i, state[i], isLE2);
      }
      digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
      }
      _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.destroyed = destroyed;
        to.finished = finished;
        to.length = length;
        to.pos = pos;
        if (length % blockLen)
          to.buffer.set(buffer);
        return to;
      }
      clone() {
        return this._cloneInto();
      }
    };
    exports.HashMD = HashMD2;
    exports.SHA256_IV = Uint32Array.from([
      1779033703,
      3144134277,
      1013904242,
      2773480762,
      1359893119,
      2600822924,
      528734635,
      1541459225
    ]);
    exports.SHA224_IV = Uint32Array.from([
      3238371032,
      914150663,
      812702999,
      4144912697,
      4290775857,
      1750603025,
      1694076839,
      3204075428
    ]);
    exports.SHA384_IV = Uint32Array.from([
      3418070365,
      3238371032,
      1654270250,
      914150663,
      2438529370,
      812702999,
      355462360,
      4144912697,
      1731405415,
      4290775857,
      2394180231,
      1750603025,
      3675008525,
      1694076839,
      1203062813,
      3204075428
    ]);
    exports.SHA512_IV = Uint32Array.from([
      1779033703,
      4089235720,
      3144134277,
      2227873595,
      1013904242,
      4271175723,
      2773480762,
      1595750129,
      1359893119,
      2917565137,
      2600822924,
      725511199,
      528734635,
      4215389547,
      1541459225,
      327033209
    ]);
  }
});

// node_modules/bip39/node_modules/@noble/hashes/_u64.js
var require_u64 = __commonJS({
  "node_modules/bip39/node_modules/@noble/hashes/_u64.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.toBig = exports.shrSL = exports.shrSH = exports.rotrSL = exports.rotrSH = exports.rotrBL = exports.rotrBH = exports.rotr32L = exports.rotr32H = exports.rotlSL = exports.rotlSH = exports.rotlBL = exports.rotlBH = exports.add5L = exports.add5H = exports.add4L = exports.add4H = exports.add3L = exports.add3H = void 0;
    exports.add = add2;
    exports.fromBig = fromBig2;
    exports.split = split2;
    var U32_MASK642 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
    var _32n2 = /* @__PURE__ */ BigInt(32);
    function fromBig2(n, le = false) {
      if (le)
        return { h: Number(n & U32_MASK642), l: Number(n >> _32n2 & U32_MASK642) };
      return { h: Number(n >> _32n2 & U32_MASK642) | 0, l: Number(n & U32_MASK642) | 0 };
    }
    function split2(lst, le = false) {
      const len = lst.length;
      let Ah = new Uint32Array(len);
      let Al = new Uint32Array(len);
      for (let i = 0; i < len; i++) {
        const { h, l } = fromBig2(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
      }
      return [Ah, Al];
    }
    var toBig = (h, l) => BigInt(h >>> 0) << _32n2 | BigInt(l >>> 0);
    exports.toBig = toBig;
    var shrSH2 = (h, _l, s) => h >>> s;
    exports.shrSH = shrSH2;
    var shrSL2 = (h, l, s) => h << 32 - s | l >>> s;
    exports.shrSL = shrSL2;
    var rotrSH2 = (h, l, s) => h >>> s | l << 32 - s;
    exports.rotrSH = rotrSH2;
    var rotrSL2 = (h, l, s) => h << 32 - s | l >>> s;
    exports.rotrSL = rotrSL2;
    var rotrBH2 = (h, l, s) => h << 64 - s | l >>> s - 32;
    exports.rotrBH = rotrBH2;
    var rotrBL2 = (h, l, s) => h >>> s - 32 | l << 64 - s;
    exports.rotrBL = rotrBL2;
    var rotr32H = (_h, l) => l;
    exports.rotr32H = rotr32H;
    var rotr32L = (h, _l) => h;
    exports.rotr32L = rotr32L;
    var rotlSH2 = (h, l, s) => h << s | l >>> 32 - s;
    exports.rotlSH = rotlSH2;
    var rotlSL2 = (h, l, s) => l << s | h >>> 32 - s;
    exports.rotlSL = rotlSL2;
    var rotlBH2 = (h, l, s) => l << s - 32 | h >>> 64 - s;
    exports.rotlBH = rotlBH2;
    var rotlBL2 = (h, l, s) => h << s - 32 | l >>> 64 - s;
    exports.rotlBL = rotlBL2;
    function add2(Ah, Al, Bh, Bl) {
      const l = (Al >>> 0) + (Bl >>> 0);
      return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
    }
    var add3L2 = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
    exports.add3L = add3L2;
    var add3H2 = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
    exports.add3H = add3H2;
    var add4L2 = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
    exports.add4L = add4L2;
    var add4H2 = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
    exports.add4H = add4H2;
    var add5L2 = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
    exports.add5L = add5L2;
    var add5H2 = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
    exports.add5H = add5H2;
    var u64 = {
      fromBig: fromBig2,
      split: split2,
      toBig,
      shrSH: shrSH2,
      shrSL: shrSL2,
      rotrSH: rotrSH2,
      rotrSL: rotrSL2,
      rotrBH: rotrBH2,
      rotrBL: rotrBL2,
      rotr32H,
      rotr32L,
      rotlSH: rotlSH2,
      rotlSL: rotlSL2,
      rotlBH: rotlBH2,
      rotlBL: rotlBL2,
      add: add2,
      add3L: add3L2,
      add3H: add3H2,
      add4L: add4L2,
      add4H: add4H2,
      add5H: add5H2,
      add5L: add5L2
    };
    exports.default = u64;
  }
});

// node_modules/bip39/node_modules/@noble/hashes/sha2.js
var require_sha2 = __commonJS({
  "node_modules/bip39/node_modules/@noble/hashes/sha2.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.sha512_224 = exports.sha512_256 = exports.sha384 = exports.sha512 = exports.sha224 = exports.sha256 = exports.SHA512_256 = exports.SHA512_224 = exports.SHA384 = exports.SHA512 = exports.SHA224 = exports.SHA256 = void 0;
    var _md_ts_1 = require_md();
    var u64 = require_u64();
    var utils_ts_1 = require_utils();
    var SHA256_K2 = /* @__PURE__ */ Uint32Array.from([
      1116352408,
      1899447441,
      3049323471,
      3921009573,
      961987163,
      1508970993,
      2453635748,
      2870763221,
      3624381080,
      310598401,
      607225278,
      1426881987,
      1925078388,
      2162078206,
      2614888103,
      3248222580,
      3835390401,
      4022224774,
      264347078,
      604807628,
      770255983,
      1249150122,
      1555081692,
      1996064986,
      2554220882,
      2821834349,
      2952996808,
      3210313671,
      3336571891,
      3584528711,
      113926993,
      338241895,
      666307205,
      773529912,
      1294757372,
      1396182291,
      1695183700,
      1986661051,
      2177026350,
      2456956037,
      2730485921,
      2820302411,
      3259730800,
      3345764771,
      3516065817,
      3600352804,
      4094571909,
      275423344,
      430227734,
      506948616,
      659060556,
      883997877,
      958139571,
      1322822218,
      1537002063,
      1747873779,
      1955562222,
      2024104815,
      2227730452,
      2361852424,
      2428436474,
      2756734187,
      3204031479,
      3329325298
    ]);
    var SHA256_W2 = /* @__PURE__ */ new Uint32Array(64);
    var SHA256 = class extends _md_ts_1.HashMD {
      constructor(outputLen = 32) {
        super(64, outputLen, 8, false);
        this.A = _md_ts_1.SHA256_IV[0] | 0;
        this.B = _md_ts_1.SHA256_IV[1] | 0;
        this.C = _md_ts_1.SHA256_IV[2] | 0;
        this.D = _md_ts_1.SHA256_IV[3] | 0;
        this.E = _md_ts_1.SHA256_IV[4] | 0;
        this.F = _md_ts_1.SHA256_IV[5] | 0;
        this.G = _md_ts_1.SHA256_IV[6] | 0;
        this.H = _md_ts_1.SHA256_IV[7] | 0;
      }
      get() {
        const { A, B, C: C2, D, E, F, G: G2, H } = this;
        return [A, B, C2, D, E, F, G2, H];
      }
      // prettier-ignore
      set(A, B, C2, D, E, F, G2, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C2 | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G2 | 0;
        this.H = H | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
          SHA256_W2[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
          const W15 = SHA256_W2[i - 15];
          const W2 = SHA256_W2[i - 2];
          const s0 = (0, utils_ts_1.rotr)(W15, 7) ^ (0, utils_ts_1.rotr)(W15, 18) ^ W15 >>> 3;
          const s1 = (0, utils_ts_1.rotr)(W2, 17) ^ (0, utils_ts_1.rotr)(W2, 19) ^ W2 >>> 10;
          SHA256_W2[i] = s1 + SHA256_W2[i - 7] + s0 + SHA256_W2[i - 16] | 0;
        }
        let { A, B, C: C2, D, E, F, G: G2, H } = this;
        for (let i = 0; i < 64; i++) {
          const sigma1 = (0, utils_ts_1.rotr)(E, 6) ^ (0, utils_ts_1.rotr)(E, 11) ^ (0, utils_ts_1.rotr)(E, 25);
          const T1 = H + sigma1 + (0, _md_ts_1.Chi)(E, F, G2) + SHA256_K2[i] + SHA256_W2[i] | 0;
          const sigma0 = (0, utils_ts_1.rotr)(A, 2) ^ (0, utils_ts_1.rotr)(A, 13) ^ (0, utils_ts_1.rotr)(A, 22);
          const T2 = sigma0 + (0, _md_ts_1.Maj)(A, B, C2) | 0;
          H = G2;
          G2 = F;
          F = E;
          E = D + T1 | 0;
          D = C2;
          C2 = B;
          B = A;
          A = T1 + T2 | 0;
        }
        A = A + this.A | 0;
        B = B + this.B | 0;
        C2 = C2 + this.C | 0;
        D = D + this.D | 0;
        E = E + this.E | 0;
        F = F + this.F | 0;
        G2 = G2 + this.G | 0;
        H = H + this.H | 0;
        this.set(A, B, C2, D, E, F, G2, H);
      }
      roundClean() {
        (0, utils_ts_1.clean)(SHA256_W2);
      }
      destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        (0, utils_ts_1.clean)(this.buffer);
      }
    };
    exports.SHA256 = SHA256;
    var SHA224 = class extends SHA256 {
      constructor() {
        super(28);
        this.A = _md_ts_1.SHA224_IV[0] | 0;
        this.B = _md_ts_1.SHA224_IV[1] | 0;
        this.C = _md_ts_1.SHA224_IV[2] | 0;
        this.D = _md_ts_1.SHA224_IV[3] | 0;
        this.E = _md_ts_1.SHA224_IV[4] | 0;
        this.F = _md_ts_1.SHA224_IV[5] | 0;
        this.G = _md_ts_1.SHA224_IV[6] | 0;
        this.H = _md_ts_1.SHA224_IV[7] | 0;
      }
    };
    exports.SHA224 = SHA224;
    var K5122 = /* @__PURE__ */ (() => u64.split([
      "0x428a2f98d728ae22",
      "0x7137449123ef65cd",
      "0xb5c0fbcfec4d3b2f",
      "0xe9b5dba58189dbbc",
      "0x3956c25bf348b538",
      "0x59f111f1b605d019",
      "0x923f82a4af194f9b",
      "0xab1c5ed5da6d8118",
      "0xd807aa98a3030242",
      "0x12835b0145706fbe",
      "0x243185be4ee4b28c",
      "0x550c7dc3d5ffb4e2",
      "0x72be5d74f27b896f",
      "0x80deb1fe3b1696b1",
      "0x9bdc06a725c71235",
      "0xc19bf174cf692694",
      "0xe49b69c19ef14ad2",
      "0xefbe4786384f25e3",
      "0x0fc19dc68b8cd5b5",
      "0x240ca1cc77ac9c65",
      "0x2de92c6f592b0275",
      "0x4a7484aa6ea6e483",
      "0x5cb0a9dcbd41fbd4",
      "0x76f988da831153b5",
      "0x983e5152ee66dfab",
      "0xa831c66d2db43210",
      "0xb00327c898fb213f",
      "0xbf597fc7beef0ee4",
      "0xc6e00bf33da88fc2",
      "0xd5a79147930aa725",
      "0x06ca6351e003826f",
      "0x142929670a0e6e70",
      "0x27b70a8546d22ffc",
      "0x2e1b21385c26c926",
      "0x4d2c6dfc5ac42aed",
      "0x53380d139d95b3df",
      "0x650a73548baf63de",
      "0x766a0abb3c77b2a8",
      "0x81c2c92e47edaee6",
      "0x92722c851482353b",
      "0xa2bfe8a14cf10364",
      "0xa81a664bbc423001",
      "0xc24b8b70d0f89791",
      "0xc76c51a30654be30",
      "0xd192e819d6ef5218",
      "0xd69906245565a910",
      "0xf40e35855771202a",
      "0x106aa07032bbd1b8",
      "0x19a4c116b8d2d0c8",
      "0x1e376c085141ab53",
      "0x2748774cdf8eeb99",
      "0x34b0bcb5e19b48a8",
      "0x391c0cb3c5c95a63",
      "0x4ed8aa4ae3418acb",
      "0x5b9cca4f7763e373",
      "0x682e6ff3d6b2b8a3",
      "0x748f82ee5defb2fc",
      "0x78a5636f43172f60",
      "0x84c87814a1f0ab72",
      "0x8cc702081a6439ec",
      "0x90befffa23631e28",
      "0xa4506cebde82bde9",
      "0xbef9a3f7b2c67915",
      "0xc67178f2e372532b",
      "0xca273eceea26619c",
      "0xd186b8c721c0c207",
      "0xeada7dd6cde0eb1e",
      "0xf57d4f7fee6ed178",
      "0x06f067aa72176fba",
      "0x0a637dc5a2c898a6",
      "0x113f9804bef90dae",
      "0x1b710b35131c471b",
      "0x28db77f523047d84",
      "0x32caab7b40c72493",
      "0x3c9ebe0a15c9bebc",
      "0x431d67c49c100d4c",
      "0x4cc5d4becb3e42b6",
      "0x597f299cfc657e2a",
      "0x5fcb6fab3ad6faec",
      "0x6c44198c4a475817"
    ].map((n) => BigInt(n))))();
    var SHA512_Kh2 = /* @__PURE__ */ (() => K5122[0])();
    var SHA512_Kl2 = /* @__PURE__ */ (() => K5122[1])();
    var SHA512_W_H2 = /* @__PURE__ */ new Uint32Array(80);
    var SHA512_W_L2 = /* @__PURE__ */ new Uint32Array(80);
    var SHA512 = class extends _md_ts_1.HashMD {
      constructor(outputLen = 64) {
        super(128, outputLen, 16, false);
        this.Ah = _md_ts_1.SHA512_IV[0] | 0;
        this.Al = _md_ts_1.SHA512_IV[1] | 0;
        this.Bh = _md_ts_1.SHA512_IV[2] | 0;
        this.Bl = _md_ts_1.SHA512_IV[3] | 0;
        this.Ch = _md_ts_1.SHA512_IV[4] | 0;
        this.Cl = _md_ts_1.SHA512_IV[5] | 0;
        this.Dh = _md_ts_1.SHA512_IV[6] | 0;
        this.Dl = _md_ts_1.SHA512_IV[7] | 0;
        this.Eh = _md_ts_1.SHA512_IV[8] | 0;
        this.El = _md_ts_1.SHA512_IV[9] | 0;
        this.Fh = _md_ts_1.SHA512_IV[10] | 0;
        this.Fl = _md_ts_1.SHA512_IV[11] | 0;
        this.Gh = _md_ts_1.SHA512_IV[12] | 0;
        this.Gl = _md_ts_1.SHA512_IV[13] | 0;
        this.Hh = _md_ts_1.SHA512_IV[14] | 0;
        this.Hl = _md_ts_1.SHA512_IV[15] | 0;
      }
      // prettier-ignore
      get() {
        const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
      }
      // prettier-ignore
      set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
        this.Ah = Ah | 0;
        this.Al = Al | 0;
        this.Bh = Bh | 0;
        this.Bl = Bl | 0;
        this.Ch = Ch | 0;
        this.Cl = Cl | 0;
        this.Dh = Dh | 0;
        this.Dl = Dl | 0;
        this.Eh = Eh | 0;
        this.El = El | 0;
        this.Fh = Fh | 0;
        this.Fl = Fl | 0;
        this.Gh = Gh | 0;
        this.Gl = Gl | 0;
        this.Hh = Hh | 0;
        this.Hl = Hl | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4) {
          SHA512_W_H2[i] = view.getUint32(offset);
          SHA512_W_L2[i] = view.getUint32(offset += 4);
        }
        for (let i = 16; i < 80; i++) {
          const W15h = SHA512_W_H2[i - 15] | 0;
          const W15l = SHA512_W_L2[i - 15] | 0;
          const s0h = u64.rotrSH(W15h, W15l, 1) ^ u64.rotrSH(W15h, W15l, 8) ^ u64.shrSH(W15h, W15l, 7);
          const s0l = u64.rotrSL(W15h, W15l, 1) ^ u64.rotrSL(W15h, W15l, 8) ^ u64.shrSL(W15h, W15l, 7);
          const W2h = SHA512_W_H2[i - 2] | 0;
          const W2l = SHA512_W_L2[i - 2] | 0;
          const s1h = u64.rotrSH(W2h, W2l, 19) ^ u64.rotrBH(W2h, W2l, 61) ^ u64.shrSH(W2h, W2l, 6);
          const s1l = u64.rotrSL(W2h, W2l, 19) ^ u64.rotrBL(W2h, W2l, 61) ^ u64.shrSL(W2h, W2l, 6);
          const SUMl = u64.add4L(s0l, s1l, SHA512_W_L2[i - 7], SHA512_W_L2[i - 16]);
          const SUMh = u64.add4H(SUMl, s0h, s1h, SHA512_W_H2[i - 7], SHA512_W_H2[i - 16]);
          SHA512_W_H2[i] = SUMh | 0;
          SHA512_W_L2[i] = SUMl | 0;
        }
        let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        for (let i = 0; i < 80; i++) {
          const sigma1h = u64.rotrSH(Eh, El, 14) ^ u64.rotrSH(Eh, El, 18) ^ u64.rotrBH(Eh, El, 41);
          const sigma1l = u64.rotrSL(Eh, El, 14) ^ u64.rotrSL(Eh, El, 18) ^ u64.rotrBL(Eh, El, 41);
          const CHIh = Eh & Fh ^ ~Eh & Gh;
          const CHIl = El & Fl ^ ~El & Gl;
          const T1ll = u64.add5L(Hl, sigma1l, CHIl, SHA512_Kl2[i], SHA512_W_L2[i]);
          const T1h = u64.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh2[i], SHA512_W_H2[i]);
          const T1l = T1ll | 0;
          const sigma0h = u64.rotrSH(Ah, Al, 28) ^ u64.rotrBH(Ah, Al, 34) ^ u64.rotrBH(Ah, Al, 39);
          const sigma0l = u64.rotrSL(Ah, Al, 28) ^ u64.rotrBL(Ah, Al, 34) ^ u64.rotrBL(Ah, Al, 39);
          const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
          const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
          Hh = Gh | 0;
          Hl = Gl | 0;
          Gh = Fh | 0;
          Gl = Fl | 0;
          Fh = Eh | 0;
          Fl = El | 0;
          ({ h: Eh, l: El } = u64.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
          Dh = Ch | 0;
          Dl = Cl | 0;
          Ch = Bh | 0;
          Cl = Bl | 0;
          Bh = Ah | 0;
          Bl = Al | 0;
          const All = u64.add3L(T1l, sigma0l, MAJl);
          Ah = u64.add3H(All, T1h, sigma0h, MAJh);
          Al = All | 0;
        }
        ({ h: Ah, l: Al } = u64.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
        ({ h: Bh, l: Bl } = u64.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
        ({ h: Ch, l: Cl } = u64.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
        ({ h: Dh, l: Dl } = u64.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
        ({ h: Eh, l: El } = u64.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
        ({ h: Fh, l: Fl } = u64.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
        ({ h: Gh, l: Gl } = u64.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
        ({ h: Hh, l: Hl } = u64.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
        this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
      }
      roundClean() {
        (0, utils_ts_1.clean)(SHA512_W_H2, SHA512_W_L2);
      }
      destroy() {
        (0, utils_ts_1.clean)(this.buffer);
        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      }
    };
    exports.SHA512 = SHA512;
    var SHA384 = class extends SHA512 {
      constructor() {
        super(48);
        this.Ah = _md_ts_1.SHA384_IV[0] | 0;
        this.Al = _md_ts_1.SHA384_IV[1] | 0;
        this.Bh = _md_ts_1.SHA384_IV[2] | 0;
        this.Bl = _md_ts_1.SHA384_IV[3] | 0;
        this.Ch = _md_ts_1.SHA384_IV[4] | 0;
        this.Cl = _md_ts_1.SHA384_IV[5] | 0;
        this.Dh = _md_ts_1.SHA384_IV[6] | 0;
        this.Dl = _md_ts_1.SHA384_IV[7] | 0;
        this.Eh = _md_ts_1.SHA384_IV[8] | 0;
        this.El = _md_ts_1.SHA384_IV[9] | 0;
        this.Fh = _md_ts_1.SHA384_IV[10] | 0;
        this.Fl = _md_ts_1.SHA384_IV[11] | 0;
        this.Gh = _md_ts_1.SHA384_IV[12] | 0;
        this.Gl = _md_ts_1.SHA384_IV[13] | 0;
        this.Hh = _md_ts_1.SHA384_IV[14] | 0;
        this.Hl = _md_ts_1.SHA384_IV[15] | 0;
      }
    };
    exports.SHA384 = SHA384;
    var T224_IV2 = /* @__PURE__ */ Uint32Array.from([
      2352822216,
      424955298,
      1944164710,
      2312950998,
      502970286,
      855612546,
      1738396948,
      1479516111,
      258812777,
      2077511080,
      2011393907,
      79989058,
      1067287976,
      1780299464,
      286451373,
      2446758561
    ]);
    var T256_IV2 = /* @__PURE__ */ Uint32Array.from([
      573645204,
      4230739756,
      2673172387,
      3360449730,
      596883563,
      1867755857,
      2520282905,
      1497426621,
      2519219938,
      2827943907,
      3193839141,
      1401305490,
      721525244,
      746961066,
      246885852,
      2177182882
    ]);
    var SHA512_224 = class extends SHA512 {
      constructor() {
        super(28);
        this.Ah = T224_IV2[0] | 0;
        this.Al = T224_IV2[1] | 0;
        this.Bh = T224_IV2[2] | 0;
        this.Bl = T224_IV2[3] | 0;
        this.Ch = T224_IV2[4] | 0;
        this.Cl = T224_IV2[5] | 0;
        this.Dh = T224_IV2[6] | 0;
        this.Dl = T224_IV2[7] | 0;
        this.Eh = T224_IV2[8] | 0;
        this.El = T224_IV2[9] | 0;
        this.Fh = T224_IV2[10] | 0;
        this.Fl = T224_IV2[11] | 0;
        this.Gh = T224_IV2[12] | 0;
        this.Gl = T224_IV2[13] | 0;
        this.Hh = T224_IV2[14] | 0;
        this.Hl = T224_IV2[15] | 0;
      }
    };
    exports.SHA512_224 = SHA512_224;
    var SHA512_256 = class extends SHA512 {
      constructor() {
        super(32);
        this.Ah = T256_IV2[0] | 0;
        this.Al = T256_IV2[1] | 0;
        this.Bh = T256_IV2[2] | 0;
        this.Bl = T256_IV2[3] | 0;
        this.Ch = T256_IV2[4] | 0;
        this.Cl = T256_IV2[5] | 0;
        this.Dh = T256_IV2[6] | 0;
        this.Dl = T256_IV2[7] | 0;
        this.Eh = T256_IV2[8] | 0;
        this.El = T256_IV2[9] | 0;
        this.Fh = T256_IV2[10] | 0;
        this.Fl = T256_IV2[11] | 0;
        this.Gh = T256_IV2[12] | 0;
        this.Gl = T256_IV2[13] | 0;
        this.Hh = T256_IV2[14] | 0;
        this.Hl = T256_IV2[15] | 0;
      }
    };
    exports.SHA512_256 = SHA512_256;
    exports.sha256 = (0, utils_ts_1.createHasher)(() => new SHA256());
    exports.sha224 = (0, utils_ts_1.createHasher)(() => new SHA224());
    exports.sha512 = (0, utils_ts_1.createHasher)(() => new SHA512());
    exports.sha384 = (0, utils_ts_1.createHasher)(() => new SHA384());
    exports.sha512_256 = (0, utils_ts_1.createHasher)(() => new SHA512_256());
    exports.sha512_224 = (0, utils_ts_1.createHasher)(() => new SHA512_224());
  }
});

// node_modules/bip39/node_modules/@noble/hashes/sha256.js
var require_sha256 = __commonJS({
  "node_modules/bip39/node_modules/@noble/hashes/sha256.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.sha224 = exports.SHA224 = exports.sha256 = exports.SHA256 = void 0;
    var sha2_ts_1 = require_sha2();
    exports.SHA256 = sha2_ts_1.SHA256;
    exports.sha256 = sha2_ts_1.sha256;
    exports.SHA224 = sha2_ts_1.SHA224;
    exports.sha224 = sha2_ts_1.sha224;
  }
});

// node_modules/bip39/node_modules/@noble/hashes/sha512.js
var require_sha512 = __commonJS({
  "node_modules/bip39/node_modules/@noble/hashes/sha512.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.sha512_256 = exports.SHA512_256 = exports.sha512_224 = exports.SHA512_224 = exports.sha384 = exports.SHA384 = exports.sha512 = exports.SHA512 = void 0;
    var sha2_ts_1 = require_sha2();
    exports.SHA512 = sha2_ts_1.SHA512;
    exports.sha512 = sha2_ts_1.sha512;
    exports.SHA384 = sha2_ts_1.SHA384;
    exports.sha384 = sha2_ts_1.sha384;
    exports.SHA512_224 = sha2_ts_1.SHA512_224;
    exports.sha512_224 = sha2_ts_1.sha512_224;
    exports.SHA512_256 = sha2_ts_1.SHA512_256;
    exports.sha512_256 = sha2_ts_1.sha512_256;
  }
});

// node_modules/bip39/node_modules/@noble/hashes/hmac.js
var require_hmac = __commonJS({
  "node_modules/bip39/node_modules/@noble/hashes/hmac.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.hmac = exports.HMAC = void 0;
    var utils_ts_1 = require_utils();
    var HMAC = class extends utils_ts_1.Hash {
      constructor(hash2, _key) {
        super();
        this.finished = false;
        this.destroyed = false;
        (0, utils_ts_1.ahash)(hash2);
        const key = (0, utils_ts_1.toBytes)(_key);
        this.iHash = hash2.create();
        if (typeof this.iHash.update !== "function")
          throw new Error("Expected instance of class which extends utils.Hash");
        this.blockLen = this.iHash.blockLen;
        this.outputLen = this.iHash.outputLen;
        const blockLen = this.blockLen;
        const pad = new Uint8Array(blockLen);
        pad.set(key.length > blockLen ? hash2.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
          pad[i] ^= 54;
        this.iHash.update(pad);
        this.oHash = hash2.create();
        for (let i = 0; i < pad.length; i++)
          pad[i] ^= 54 ^ 92;
        this.oHash.update(pad);
        (0, utils_ts_1.clean)(pad);
      }
      update(buf) {
        (0, utils_ts_1.aexists)(this);
        this.iHash.update(buf);
        return this;
      }
      digestInto(out) {
        (0, utils_ts_1.aexists)(this);
        (0, utils_ts_1.abytes)(out, this.outputLen);
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
      }
      digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
      }
      _cloneInto(to) {
        to || (to = Object.create(Object.getPrototypeOf(this), {}));
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
      }
      clone() {
        return this._cloneInto();
      }
      destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
      }
    };
    exports.HMAC = HMAC;
    var hmac2 = (hash2, key, message) => new HMAC(hash2, key).update(message).digest();
    exports.hmac = hmac2;
    exports.hmac.create = (hash2, key) => new HMAC(hash2, key);
  }
});

// node_modules/bip39/node_modules/@noble/hashes/pbkdf2.js
var require_pbkdf2 = __commonJS({
  "node_modules/bip39/node_modules/@noble/hashes/pbkdf2.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.pbkdf2 = pbkdf2;
    exports.pbkdf2Async = pbkdf2Async;
    var hmac_ts_1 = require_hmac();
    var utils_ts_1 = require_utils();
    function pbkdf2Init(hash2, _password, _salt, _opts) {
      (0, utils_ts_1.ahash)(hash2);
      const opts = (0, utils_ts_1.checkOpts)({ dkLen: 32, asyncTick: 10 }, _opts);
      const { c, dkLen, asyncTick } = opts;
      (0, utils_ts_1.anumber)(c);
      (0, utils_ts_1.anumber)(dkLen);
      (0, utils_ts_1.anumber)(asyncTick);
      if (c < 1)
        throw new Error("iterations (c) should be >= 1");
      const password = (0, utils_ts_1.kdfInputToBytes)(_password);
      const salt = (0, utils_ts_1.kdfInputToBytes)(_salt);
      const DK = new Uint8Array(dkLen);
      const PRF = hmac_ts_1.hmac.create(hash2, password);
      const PRFSalt = PRF._cloneInto().update(salt);
      return { c, dkLen, asyncTick, DK, PRF, PRFSalt };
    }
    function pbkdf2Output(PRF, PRFSalt, DK, prfW, u) {
      PRF.destroy();
      PRFSalt.destroy();
      if (prfW)
        prfW.destroy();
      (0, utils_ts_1.clean)(u);
      return DK;
    }
    function pbkdf2(hash2, password, salt, opts) {
      const { c, dkLen, DK, PRF, PRFSalt } = pbkdf2Init(hash2, password, salt, opts);
      let prfW;
      const arr = new Uint8Array(4);
      const view = (0, utils_ts_1.createView)(arr);
      const u = new Uint8Array(PRF.outputLen);
      for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
        const Ti = DK.subarray(pos, pos + PRF.outputLen);
        view.setInt32(0, ti, false);
        (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
        Ti.set(u.subarray(0, Ti.length));
        for (let ui = 1; ui < c; ui++) {
          PRF._cloneInto(prfW).update(u).digestInto(u);
          for (let i = 0; i < Ti.length; i++)
            Ti[i] ^= u[i];
        }
      }
      return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
    }
    async function pbkdf2Async(hash2, password, salt, opts) {
      const { c, dkLen, asyncTick, DK, PRF, PRFSalt } = pbkdf2Init(hash2, password, salt, opts);
      let prfW;
      const arr = new Uint8Array(4);
      const view = (0, utils_ts_1.createView)(arr);
      const u = new Uint8Array(PRF.outputLen);
      for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
        const Ti = DK.subarray(pos, pos + PRF.outputLen);
        view.setInt32(0, ti, false);
        (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
        Ti.set(u.subarray(0, Ti.length));
        await (0, utils_ts_1.asyncLoop)(c - 1, asyncTick, () => {
          PRF._cloneInto(prfW).update(u).digestInto(u);
          for (let i = 0; i < Ti.length; i++)
            Ti[i] ^= u[i];
        });
      }
      return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
    }
  }
});

// node_modules/bip39/src/wordlists/czech.json
var require_czech = __commonJS({
  "node_modules/bip39/src/wordlists/czech.json"(exports, module) {
    module.exports = [
      "abdikace",
      "abeceda",
      "adresa",
      "agrese",
      "akce",
      "aktovka",
      "alej",
      "alkohol",
      "amputace",
      "ananas",
      "andulka",
      "anekdota",
      "anketa",
      "antika",
      "anulovat",
      "archa",
      "arogance",
      "asfalt",
      "asistent",
      "aspirace",
      "astma",
      "astronom",
      "atlas",
      "atletika",
      "atol",
      "autobus",
      "azyl",
      "babka",
      "bachor",
      "bacil",
      "baculka",
      "badatel",
      "bageta",
      "bagr",
      "bahno",
      "bakterie",
      "balada",
      "baletka",
      "balkon",
      "balonek",
      "balvan",
      "balza",
      "bambus",
      "bankomat",
      "barbar",
      "baret",
      "barman",
      "baroko",
      "barva",
      "baterka",
      "batoh",
      "bavlna",
      "bazalka",
      "bazilika",
      "bazuka",
      "bedna",
      "beran",
      "beseda",
      "bestie",
      "beton",
      "bezinka",
      "bezmoc",
      "beztak",
      "bicykl",
      "bidlo",
      "biftek",
      "bikiny",
      "bilance",
      "biograf",
      "biolog",
      "bitva",
      "bizon",
      "blahobyt",
      "blatouch",
      "blecha",
      "bledule",
      "blesk",
      "blikat",
      "blizna",
      "blokovat",
      "bloudit",
      "blud",
      "bobek",
      "bobr",
      "bodlina",
      "bodnout",
      "bohatost",
      "bojkot",
      "bojovat",
      "bokorys",
      "bolest",
      "borec",
      "borovice",
      "bota",
      "boubel",
      "bouchat",
      "bouda",
      "boule",
      "bourat",
      "boxer",
      "bradavka",
      "brambora",
      "branka",
      "bratr",
      "brepta",
      "briketa",
      "brko",
      "brloh",
      "bronz",
      "broskev",
      "brunetka",
      "brusinka",
      "brzda",
      "brzy",
      "bublina",
      "bubnovat",
      "buchta",
      "buditel",
      "budka",
      "budova",
      "bufet",
      "bujarost",
      "bukvice",
      "buldok",
      "bulva",
      "bunda",
      "bunkr",
      "burza",
      "butik",
      "buvol",
      "buzola",
      "bydlet",
      "bylina",
      "bytovka",
      "bzukot",
      "capart",
      "carevna",
      "cedr",
      "cedule",
      "cejch",
      "cejn",
      "cela",
      "celer",
      "celkem",
      "celnice",
      "cenina",
      "cennost",
      "cenovka",
      "centrum",
      "cenzor",
      "cestopis",
      "cetka",
      "chalupa",
      "chapadlo",
      "charita",
      "chata",
      "chechtat",
      "chemie",
      "chichot",
      "chirurg",
      "chlad",
      "chleba",
      "chlubit",
      "chmel",
      "chmura",
      "chobot",
      "chochol",
      "chodba",
      "cholera",
      "chomout",
      "chopit",
      "choroba",
      "chov",
      "chrapot",
      "chrlit",
      "chrt",
      "chrup",
      "chtivost",
      "chudina",
      "chutnat",
      "chvat",
      "chvilka",
      "chvost",
      "chyba",
      "chystat",
      "chytit",
      "cibule",
      "cigareta",
      "cihelna",
      "cihla",
      "cinkot",
      "cirkus",
      "cisterna",
      "citace",
      "citrus",
      "cizinec",
      "cizost",
      "clona",
      "cokoliv",
      "couvat",
      "ctitel",
      "ctnost",
      "cudnost",
      "cuketa",
      "cukr",
      "cupot",
      "cvaknout",
      "cval",
      "cvik",
      "cvrkot",
      "cyklista",
      "daleko",
      "dareba",
      "datel",
      "datum",
      "dcera",
      "debata",
      "dechovka",
      "decibel",
      "deficit",
      "deflace",
      "dekl",
      "dekret",
      "demokrat",
      "deprese",
      "derby",
      "deska",
      "detektiv",
      "dikobraz",
      "diktovat",
      "dioda",
      "diplom",
      "disk",
      "displej",
      "divadlo",
      "divoch",
      "dlaha",
      "dlouho",
      "dluhopis",
      "dnes",
      "dobro",
      "dobytek",
      "docent",
      "dochutit",
      "dodnes",
      "dohled",
      "dohoda",
      "dohra",
      "dojem",
      "dojnice",
      "doklad",
      "dokola",
      "doktor",
      "dokument",
      "dolar",
      "doleva",
      "dolina",
      "doma",
      "dominant",
      "domluvit",
      "domov",
      "donutit",
      "dopad",
      "dopis",
      "doplnit",
      "doposud",
      "doprovod",
      "dopustit",
      "dorazit",
      "dorost",
      "dort",
      "dosah",
      "doslov",
      "dostatek",
      "dosud",
      "dosyta",
      "dotaz",
      "dotek",
      "dotknout",
      "doufat",
      "doutnat",
      "dovozce",
      "dozadu",
      "doznat",
      "dozorce",
      "drahota",
      "drak",
      "dramatik",
      "dravec",
      "draze",
      "drdol",
      "drobnost",
      "drogerie",
      "drozd",
      "drsnost",
      "drtit",
      "drzost",
      "duben",
      "duchovno",
      "dudek",
      "duha",
      "duhovka",
      "dusit",
      "dusno",
      "dutost",
      "dvojice",
      "dvorec",
      "dynamit",
      "ekolog",
      "ekonomie",
      "elektron",
      "elipsa",
      "email",
      "emise",
      "emoce",
      "empatie",
      "epizoda",
      "epocha",
      "epopej",
      "epos",
      "esej",
      "esence",
      "eskorta",
      "eskymo",
      "etiketa",
      "euforie",
      "evoluce",
      "exekuce",
      "exkurze",
      "expedice",
      "exploze",
      "export",
      "extrakt",
      "facka",
      "fajfka",
      "fakulta",
      "fanatik",
      "fantazie",
      "farmacie",
      "favorit",
      "fazole",
      "federace",
      "fejeton",
      "fenka",
      "fialka",
      "figurant",
      "filozof",
      "filtr",
      "finance",
      "finta",
      "fixace",
      "fjord",
      "flanel",
      "flirt",
      "flotila",
      "fond",
      "fosfor",
      "fotbal",
      "fotka",
      "foton",
      "frakce",
      "freska",
      "fronta",
      "fukar",
      "funkce",
      "fyzika",
      "galeje",
      "garant",
      "genetika",
      "geolog",
      "gilotina",
      "glazura",
      "glejt",
      "golem",
      "golfista",
      "gotika",
      "graf",
      "gramofon",
      "granule",
      "grep",
      "gril",
      "grog",
      "groteska",
      "guma",
      "hadice",
      "hadr",
      "hala",
      "halenka",
      "hanba",
      "hanopis",
      "harfa",
      "harpuna",
      "havran",
      "hebkost",
      "hejkal",
      "hejno",
      "hejtman",
      "hektar",
      "helma",
      "hematom",
      "herec",
      "herna",
      "heslo",
      "hezky",
      "historik",
      "hladovka",
      "hlasivky",
      "hlava",
      "hledat",
      "hlen",
      "hlodavec",
      "hloh",
      "hloupost",
      "hltat",
      "hlubina",
      "hluchota",
      "hmat",
      "hmota",
      "hmyz",
      "hnis",
      "hnojivo",
      "hnout",
      "hoblina",
      "hoboj",
      "hoch",
      "hodiny",
      "hodlat",
      "hodnota",
      "hodovat",
      "hojnost",
      "hokej",
      "holinka",
      "holka",
      "holub",
      "homole",
      "honitba",
      "honorace",
      "horal",
      "horda",
      "horizont",
      "horko",
      "horlivec",
      "hormon",
      "hornina",
      "horoskop",
      "horstvo",
      "hospoda",
      "hostina",
      "hotovost",
      "houba",
      "houf",
      "houpat",
      "houska",
      "hovor",
      "hradba",
      "hranice",
      "hravost",
      "hrazda",
      "hrbolek",
      "hrdina",
      "hrdlo",
      "hrdost",
      "hrnek",
      "hrobka",
      "hromada",
      "hrot",
      "hrouda",
      "hrozen",
      "hrstka",
      "hrubost",
      "hryzat",
      "hubenost",
      "hubnout",
      "hudba",
      "hukot",
      "humr",
      "husita",
      "hustota",
      "hvozd",
      "hybnost",
      "hydrant",
      "hygiena",
      "hymna",
      "hysterik",
      "idylka",
      "ihned",
      "ikona",
      "iluze",
      "imunita",
      "infekce",
      "inflace",
      "inkaso",
      "inovace",
      "inspekce",
      "internet",
      "invalida",
      "investor",
      "inzerce",
      "ironie",
      "jablko",
      "jachta",
      "jahoda",
      "jakmile",
      "jakost",
      "jalovec",
      "jantar",
      "jarmark",
      "jaro",
      "jasan",
      "jasno",
      "jatka",
      "javor",
      "jazyk",
      "jedinec",
      "jedle",
      "jednatel",
      "jehlan",
      "jekot",
      "jelen",
      "jelito",
      "jemnost",
      "jenom",
      "jepice",
      "jeseter",
      "jevit",
      "jezdec",
      "jezero",
      "jinak",
      "jindy",
      "jinoch",
      "jiskra",
      "jistota",
      "jitrnice",
      "jizva",
      "jmenovat",
      "jogurt",
      "jurta",
      "kabaret",
      "kabel",
      "kabinet",
      "kachna",
      "kadet",
      "kadidlo",
      "kahan",
      "kajak",
      "kajuta",
      "kakao",
      "kaktus",
      "kalamita",
      "kalhoty",
      "kalibr",
      "kalnost",
      "kamera",
      "kamkoliv",
      "kamna",
      "kanibal",
      "kanoe",
      "kantor",
      "kapalina",
      "kapela",
      "kapitola",
      "kapka",
      "kaple",
      "kapota",
      "kapr",
      "kapusta",
      "kapybara",
      "karamel",
      "karotka",
      "karton",
      "kasa",
      "katalog",
      "katedra",
      "kauce",
      "kauza",
      "kavalec",
      "kazajka",
      "kazeta",
      "kazivost",
      "kdekoliv",
      "kdesi",
      "kedluben",
      "kemp",
      "keramika",
      "kino",
      "klacek",
      "kladivo",
      "klam",
      "klapot",
      "klasika",
      "klaun",
      "klec",
      "klenba",
      "klepat",
      "klesnout",
      "klid",
      "klima",
      "klisna",
      "klobouk",
      "klokan",
      "klopa",
      "kloub",
      "klubovna",
      "klusat",
      "kluzkost",
      "kmen",
      "kmitat",
      "kmotr",
      "kniha",
      "knot",
      "koalice",
      "koberec",
      "kobka",
      "kobliha",
      "kobyla",
      "kocour",
      "kohout",
      "kojenec",
      "kokos",
      "koktejl",
      "kolaps",
      "koleda",
      "kolize",
      "kolo",
      "komando",
      "kometa",
      "komik",
      "komnata",
      "komora",
      "kompas",
      "komunita",
      "konat",
      "koncept",
      "kondice",
      "konec",
      "konfese",
      "kongres",
      "konina",
      "konkurs",
      "kontakt",
      "konzerva",
      "kopanec",
      "kopie",
      "kopnout",
      "koprovka",
      "korbel",
      "korektor",
      "kormidlo",
      "koroptev",
      "korpus",
      "koruna",
      "koryto",
      "korzet",
      "kosatec",
      "kostka",
      "kotel",
      "kotleta",
      "kotoul",
      "koukat",
      "koupelna",
      "kousek",
      "kouzlo",
      "kovboj",
      "koza",
      "kozoroh",
      "krabice",
      "krach",
      "krajina",
      "kralovat",
      "krasopis",
      "kravata",
      "kredit",
      "krejcar",
      "kresba",
      "kreveta",
      "kriket",
      "kritik",
      "krize",
      "krkavec",
      "krmelec",
      "krmivo",
      "krocan",
      "krok",
      "kronika",
      "kropit",
      "kroupa",
      "krovka",
      "krtek",
      "kruhadlo",
      "krupice",
      "krutost",
      "krvinka",
      "krychle",
      "krypta",
      "krystal",
      "kryt",
      "kudlanka",
      "kufr",
      "kujnost",
      "kukla",
      "kulajda",
      "kulich",
      "kulka",
      "kulomet",
      "kultura",
      "kuna",
      "kupodivu",
      "kurt",
      "kurzor",
      "kutil",
      "kvalita",
      "kvasinka",
      "kvestor",
      "kynolog",
      "kyselina",
      "kytara",
      "kytice",
      "kytka",
      "kytovec",
      "kyvadlo",
      "labrador",
      "lachtan",
      "ladnost",
      "laik",
      "lakomec",
      "lamela",
      "lampa",
      "lanovka",
      "lasice",
      "laso",
      "lastura",
      "latinka",
      "lavina",
      "lebka",
      "leckdy",
      "leden",
      "lednice",
      "ledovka",
      "ledvina",
      "legenda",
      "legie",
      "legrace",
      "lehce",
      "lehkost",
      "lehnout",
      "lektvar",
      "lenochod",
      "lentilka",
      "lepenka",
      "lepidlo",
      "letadlo",
      "letec",
      "letmo",
      "letokruh",
      "levhart",
      "levitace",
      "levobok",
      "libra",
      "lichotka",
      "lidojed",
      "lidskost",
      "lihovina",
      "lijavec",
      "lilek",
      "limetka",
      "linie",
      "linka",
      "linoleum",
      "listopad",
      "litina",
      "litovat",
      "lobista",
      "lodivod",
      "logika",
      "logoped",
      "lokalita",
      "loket",
      "lomcovat",
      "lopata",
      "lopuch",
      "lord",
      "losos",
      "lotr",
      "loudal",
      "louh",
      "louka",
      "louskat",
      "lovec",
      "lstivost",
      "lucerna",
      "lucifer",
      "lump",
      "lusk",
      "lustrace",
      "lvice",
      "lyra",
      "lyrika",
      "lysina",
      "madam",
      "madlo",
      "magistr",
      "mahagon",
      "majetek",
      "majitel",
      "majorita",
      "makak",
      "makovice",
      "makrela",
      "malba",
      "malina",
      "malovat",
      "malvice",
      "maminka",
      "mandle",
      "manko",
      "marnost",
      "masakr",
      "maskot",
      "masopust",
      "matice",
      "matrika",
      "maturita",
      "mazanec",
      "mazivo",
      "mazlit",
      "mazurka",
      "mdloba",
      "mechanik",
      "meditace",
      "medovina",
      "melasa",
      "meloun",
      "mentolka",
      "metla",
      "metoda",
      "metr",
      "mezera",
      "migrace",
      "mihnout",
      "mihule",
      "mikina",
      "mikrofon",
      "milenec",
      "milimetr",
      "milost",
      "mimika",
      "mincovna",
      "minibar",
      "minomet",
      "minulost",
      "miska",
      "mistr",
      "mixovat",
      "mladost",
      "mlha",
      "mlhovina",
      "mlok",
      "mlsat",
      "mluvit",
      "mnich",
      "mnohem",
      "mobil",
      "mocnost",
      "modelka",
      "modlitba",
      "mohyla",
      "mokro",
      "molekula",
      "momentka",
      "monarcha",
      "monokl",
      "monstrum",
      "montovat",
      "monzun",
      "mosaz",
      "moskyt",
      "most",
      "motivace",
      "motorka",
      "motyka",
      "moucha",
      "moudrost",
      "mozaika",
      "mozek",
      "mozol",
      "mramor",
      "mravenec",
      "mrkev",
      "mrtvola",
      "mrzet",
      "mrzutost",
      "mstitel",
      "mudrc",
      "muflon",
      "mulat",
      "mumie",
      "munice",
      "muset",
      "mutace",
      "muzeum",
      "muzikant",
      "myslivec",
      "mzda",
      "nabourat",
      "nachytat",
      "nadace",
      "nadbytek",
      "nadhoz",
      "nadobro",
      "nadpis",
      "nahlas",
      "nahnat",
      "nahodile",
      "nahradit",
      "naivita",
      "najednou",
      "najisto",
      "najmout",
      "naklonit",
      "nakonec",
      "nakrmit",
      "nalevo",
      "namazat",
      "namluvit",
      "nanometr",
      "naoko",
      "naopak",
      "naostro",
      "napadat",
      "napevno",
      "naplnit",
      "napnout",
      "naposled",
      "naprosto",
      "narodit",
      "naruby",
      "narychlo",
      "nasadit",
      "nasekat",
      "naslepo",
      "nastat",
      "natolik",
      "navenek",
      "navrch",
      "navzdory",
      "nazvat",
      "nebe",
      "nechat",
      "necky",
      "nedaleko",
      "nedbat",
      "neduh",
      "negace",
      "nehet",
      "nehoda",
      "nejen",
      "nejprve",
      "neklid",
      "nelibost",
      "nemilost",
      "nemoc",
      "neochota",
      "neonka",
      "nepokoj",
      "nerost",
      "nerv",
      "nesmysl",
      "nesoulad",
      "netvor",
      "neuron",
      "nevina",
      "nezvykle",
      "nicota",
      "nijak",
      "nikam",
      "nikdy",
      "nikl",
      "nikterak",
      "nitro",
      "nocleh",
      "nohavice",
      "nominace",
      "nora",
      "norek",
      "nositel",
      "nosnost",
      "nouze",
      "noviny",
      "novota",
      "nozdra",
      "nuda",
      "nudle",
      "nuget",
      "nutit",
      "nutnost",
      "nutrie",
      "nymfa",
      "obal",
      "obarvit",
      "obava",
      "obdiv",
      "obec",
      "obehnat",
      "obejmout",
      "obezita",
      "obhajoba",
      "obilnice",
      "objasnit",
      "objekt",
      "obklopit",
      "oblast",
      "oblek",
      "obliba",
      "obloha",
      "obluda",
      "obnos",
      "obohatit",
      "obojek",
      "obout",
      "obrazec",
      "obrna",
      "obruba",
      "obrys",
      "obsah",
      "obsluha",
      "obstarat",
      "obuv",
      "obvaz",
      "obvinit",
      "obvod",
      "obvykle",
      "obyvatel",
      "obzor",
      "ocas",
      "ocel",
      "ocenit",
      "ochladit",
      "ochota",
      "ochrana",
      "ocitnout",
      "odboj",
      "odbyt",
      "odchod",
      "odcizit",
      "odebrat",
      "odeslat",
      "odevzdat",
      "odezva",
      "odhadce",
      "odhodit",
      "odjet",
      "odjinud",
      "odkaz",
      "odkoupit",
      "odliv",
      "odluka",
      "odmlka",
      "odolnost",
      "odpad",
      "odpis",
      "odplout",
      "odpor",
      "odpustit",
      "odpykat",
      "odrazka",
      "odsoudit",
      "odstup",
      "odsun",
      "odtok",
      "odtud",
      "odvaha",
      "odveta",
      "odvolat",
      "odvracet",
      "odznak",
      "ofina",
      "ofsajd",
      "ohlas",
      "ohnisko",
      "ohrada",
      "ohrozit",
      "ohryzek",
      "okap",
      "okenice",
      "oklika",
      "okno",
      "okouzlit",
      "okovy",
      "okrasa",
      "okres",
      "okrsek",
      "okruh",
      "okupant",
      "okurka",
      "okusit",
      "olejnina",
      "olizovat",
      "omak",
      "omeleta",
      "omezit",
      "omladina",
      "omlouvat",
      "omluva",
      "omyl",
      "onehdy",
      "opakovat",
      "opasek",
      "operace",
      "opice",
      "opilost",
      "opisovat",
      "opora",
      "opozice",
      "opravdu",
      "oproti",
      "orbital",
      "orchestr",
      "orgie",
      "orlice",
      "orloj",
      "ortel",
      "osada",
      "oschnout",
      "osika",
      "osivo",
      "oslava",
      "oslepit",
      "oslnit",
      "oslovit",
      "osnova",
      "osoba",
      "osolit",
      "ospalec",
      "osten",
      "ostraha",
      "ostuda",
      "ostych",
      "osvojit",
      "oteplit",
      "otisk",
      "otop",
      "otrhat",
      "otrlost",
      "otrok",
      "otruby",
      "otvor",
      "ovanout",
      "ovar",
      "oves",
      "ovlivnit",
      "ovoce",
      "oxid",
      "ozdoba",
      "pachatel",
      "pacient",
      "padouch",
      "pahorek",
      "pakt",
      "palanda",
      "palec",
      "palivo",
      "paluba",
      "pamflet",
      "pamlsek",
      "panenka",
      "panika",
      "panna",
      "panovat",
      "panstvo",
      "pantofle",
      "paprika",
      "parketa",
      "parodie",
      "parta",
      "paruka",
      "paryba",
      "paseka",
      "pasivita",
      "pastelka",
      "patent",
      "patrona",
      "pavouk",
      "pazneht",
      "pazourek",
      "pecka",
      "pedagog",
      "pejsek",
      "peklo",
      "peloton",
      "penalta",
      "pendrek",
      "penze",
      "periskop",
      "pero",
      "pestrost",
      "petarda",
      "petice",
      "petrolej",
      "pevnina",
      "pexeso",
      "pianista",
      "piha",
      "pijavice",
      "pikle",
      "piknik",
      "pilina",
      "pilnost",
      "pilulka",
      "pinzeta",
      "pipeta",
      "pisatel",
      "pistole",
      "pitevna",
      "pivnice",
      "pivovar",
      "placenta",
      "plakat",
      "plamen",
      "planeta",
      "plastika",
      "platit",
      "plavidlo",
      "plaz",
      "plech",
      "plemeno",
      "plenta",
      "ples",
      "pletivo",
      "plevel",
      "plivat",
      "plnit",
      "plno",
      "plocha",
      "plodina",
      "plomba",
      "plout",
      "pluk",
      "plyn",
      "pobavit",
      "pobyt",
      "pochod",
      "pocit",
      "poctivec",
      "podat",
      "podcenit",
      "podepsat",
      "podhled",
      "podivit",
      "podklad",
      "podmanit",
      "podnik",
      "podoba",
      "podpora",
      "podraz",
      "podstata",
      "podvod",
      "podzim",
      "poezie",
      "pohanka",
      "pohnutka",
      "pohovor",
      "pohroma",
      "pohyb",
      "pointa",
      "pojistka",
      "pojmout",
      "pokazit",
      "pokles",
      "pokoj",
      "pokrok",
      "pokuta",
      "pokyn",
      "poledne",
      "polibek",
      "polknout",
      "poloha",
      "polynom",
      "pomalu",
      "pominout",
      "pomlka",
      "pomoc",
      "pomsta",
      "pomyslet",
      "ponechat",
      "ponorka",
      "ponurost",
      "popadat",
      "popel",
      "popisek",
      "poplach",
      "poprosit",
      "popsat",
      "popud",
      "poradce",
      "porce",
      "porod",
      "porucha",
      "poryv",
      "posadit",
      "posed",
      "posila",
      "poskok",
      "poslanec",
      "posoudit",
      "pospolu",
      "postava",
      "posudek",
      "posyp",
      "potah",
      "potkan",
      "potlesk",
      "potomek",
      "potrava",
      "potupa",
      "potvora",
      "poukaz",
      "pouto",
      "pouzdro",
      "povaha",
      "povidla",
      "povlak",
      "povoz",
      "povrch",
      "povstat",
      "povyk",
      "povzdech",
      "pozdrav",
      "pozemek",
      "poznatek",
      "pozor",
      "pozvat",
      "pracovat",
      "prahory",
      "praktika",
      "prales",
      "praotec",
      "praporek",
      "prase",
      "pravda",
      "princip",
      "prkno",
      "probudit",
      "procento",
      "prodej",
      "profese",
      "prohra",
      "projekt",
      "prolomit",
      "promile",
      "pronikat",
      "propad",
      "prorok",
      "prosba",
      "proton",
      "proutek",
      "provaz",
      "prskavka",
      "prsten",
      "prudkost",
      "prut",
      "prvek",
      "prvohory",
      "psanec",
      "psovod",
      "pstruh",
      "ptactvo",
      "puberta",
      "puch",
      "pudl",
      "pukavec",
      "puklina",
      "pukrle",
      "pult",
      "pumpa",
      "punc",
      "pupen",
      "pusa",
      "pusinka",
      "pustina",
      "putovat",
      "putyka",
      "pyramida",
      "pysk",
      "pytel",
      "racek",
      "rachot",
      "radiace",
      "radnice",
      "radon",
      "raft",
      "ragby",
      "raketa",
      "rakovina",
      "rameno",
      "rampouch",
      "rande",
      "rarach",
      "rarita",
      "rasovna",
      "rastr",
      "ratolest",
      "razance",
      "razidlo",
      "reagovat",
      "reakce",
      "recept",
      "redaktor",
      "referent",
      "reflex",
      "rejnok",
      "reklama",
      "rekord",
      "rekrut",
      "rektor",
      "reputace",
      "revize",
      "revma",
      "revolver",
      "rezerva",
      "riskovat",
      "riziko",
      "robotika",
      "rodokmen",
      "rohovka",
      "rokle",
      "rokoko",
      "romaneto",
      "ropovod",
      "ropucha",
      "rorejs",
      "rosol",
      "rostlina",
      "rotmistr",
      "rotoped",
      "rotunda",
      "roubenka",
      "roucho",
      "roup",
      "roura",
      "rovina",
      "rovnice",
      "rozbor",
      "rozchod",
      "rozdat",
      "rozeznat",
      "rozhodce",
      "rozinka",
      "rozjezd",
      "rozkaz",
      "rozloha",
      "rozmar",
      "rozpad",
      "rozruch",
      "rozsah",
      "roztok",
      "rozum",
      "rozvod",
      "rubrika",
      "ruchadlo",
      "rukavice",
      "rukopis",
      "ryba",
      "rybolov",
      "rychlost",
      "rydlo",
      "rypadlo",
      "rytina",
      "ryzost",
      "sadista",
      "sahat",
      "sako",
      "samec",
      "samizdat",
      "samota",
      "sanitka",
      "sardinka",
      "sasanka",
      "satelit",
      "sazba",
      "sazenice",
      "sbor",
      "schovat",
      "sebranka",
      "secese",
      "sedadlo",
      "sediment",
      "sedlo",
      "sehnat",
      "sejmout",
      "sekera",
      "sekta",
      "sekunda",
      "sekvoje",
      "semeno",
      "seno",
      "servis",
      "sesadit",
      "seshora",
      "seskok",
      "seslat",
      "sestra",
      "sesuv",
      "sesypat",
      "setba",
      "setina",
      "setkat",
      "setnout",
      "setrvat",
      "sever",
      "seznam",
      "shoda",
      "shrnout",
      "sifon",
      "silnice",
      "sirka",
      "sirotek",
      "sirup",
      "situace",
      "skafandr",
      "skalisko",
      "skanzen",
      "skaut",
      "skeptik",
      "skica",
      "skladba",
      "sklenice",
      "sklo",
      "skluz",
      "skoba",
      "skokan",
      "skoro",
      "skripta",
      "skrz",
      "skupina",
      "skvost",
      "skvrna",
      "slabika",
      "sladidlo",
      "slanina",
      "slast",
      "slavnost",
      "sledovat",
      "slepec",
      "sleva",
      "slezina",
      "slib",
      "slina",
      "sliznice",
      "slon",
      "sloupek",
      "slovo",
      "sluch",
      "sluha",
      "slunce",
      "slupka",
      "slza",
      "smaragd",
      "smetana",
      "smilstvo",
      "smlouva",
      "smog",
      "smrad",
      "smrk",
      "smrtka",
      "smutek",
      "smysl",
      "snad",
      "snaha",
      "snob",
      "sobota",
      "socha",
      "sodovka",
      "sokol",
      "sopka",
      "sotva",
      "souboj",
      "soucit",
      "soudce",
      "souhlas",
      "soulad",
      "soumrak",
      "souprava",
      "soused",
      "soutok",
      "souviset",
      "spalovna",
      "spasitel",
      "spis",
      "splav",
      "spodek",
      "spojenec",
      "spolu",
      "sponzor",
      "spornost",
      "spousta",
      "sprcha",
      "spustit",
      "sranda",
      "sraz",
      "srdce",
      "srna",
      "srnec",
      "srovnat",
      "srpen",
      "srst",
      "srub",
      "stanice",
      "starosta",
      "statika",
      "stavba",
      "stehno",
      "stezka",
      "stodola",
      "stolek",
      "stopa",
      "storno",
      "stoupat",
      "strach",
      "stres",
      "strhnout",
      "strom",
      "struna",
      "studna",
      "stupnice",
      "stvol",
      "styk",
      "subjekt",
      "subtropy",
      "suchar",
      "sudost",
      "sukno",
      "sundat",
      "sunout",
      "surikata",
      "surovina",
      "svah",
      "svalstvo",
      "svetr",
      "svatba",
      "svazek",
      "svisle",
      "svitek",
      "svoboda",
      "svodidlo",
      "svorka",
      "svrab",
      "sykavka",
      "sykot",
      "synek",
      "synovec",
      "sypat",
      "sypkost",
      "syrovost",
      "sysel",
      "sytost",
      "tabletka",
      "tabule",
      "tahoun",
      "tajemno",
      "tajfun",
      "tajga",
      "tajit",
      "tajnost",
      "taktika",
      "tamhle",
      "tampon",
      "tancovat",
      "tanec",
      "tanker",
      "tapeta",
      "tavenina",
      "tazatel",
      "technika",
      "tehdy",
      "tekutina",
      "telefon",
      "temnota",
      "tendence",
      "tenista",
      "tenor",
      "teplota",
      "tepna",
      "teprve",
      "terapie",
      "termoska",
      "textil",
      "ticho",
      "tiskopis",
      "titulek",
      "tkadlec",
      "tkanina",
      "tlapka",
      "tleskat",
      "tlukot",
      "tlupa",
      "tmel",
      "toaleta",
      "topinka",
      "topol",
      "torzo",
      "touha",
      "toulec",
      "tradice",
      "traktor",
      "tramp",
      "trasa",
      "traverza",
      "trefit",
      "trest",
      "trezor",
      "trhavina",
      "trhlina",
      "trochu",
      "trojice",
      "troska",
      "trouba",
      "trpce",
      "trpitel",
      "trpkost",
      "trubec",
      "truchlit",
      "truhlice",
      "trus",
      "trvat",
      "tudy",
      "tuhnout",
      "tuhost",
      "tundra",
      "turista",
      "turnaj",
      "tuzemsko",
      "tvaroh",
      "tvorba",
      "tvrdost",
      "tvrz",
      "tygr",
      "tykev",
      "ubohost",
      "uboze",
      "ubrat",
      "ubrousek",
      "ubrus",
      "ubytovna",
      "ucho",
      "uctivost",
      "udivit",
      "uhradit",
      "ujednat",
      "ujistit",
      "ujmout",
      "ukazatel",
      "uklidnit",
      "uklonit",
      "ukotvit",
      "ukrojit",
      "ulice",
      "ulita",
      "ulovit",
      "umyvadlo",
      "unavit",
      "uniforma",
      "uniknout",
      "upadnout",
      "uplatnit",
      "uplynout",
      "upoutat",
      "upravit",
      "uran",
      "urazit",
      "usednout",
      "usilovat",
      "usmrtit",
      "usnadnit",
      "usnout",
      "usoudit",
      "ustlat",
      "ustrnout",
      "utahovat",
      "utkat",
      "utlumit",
      "utonout",
      "utopenec",
      "utrousit",
      "uvalit",
      "uvolnit",
      "uvozovka",
      "uzdravit",
      "uzel",
      "uzenina",
      "uzlina",
      "uznat",
      "vagon",
      "valcha",
      "valoun",
      "vana",
      "vandal",
      "vanilka",
      "varan",
      "varhany",
      "varovat",
      "vcelku",
      "vchod",
      "vdova",
      "vedro",
      "vegetace",
      "vejce",
      "velbloud",
      "veletrh",
      "velitel",
      "velmoc",
      "velryba",
      "venkov",
      "veranda",
      "verze",
      "veselka",
      "veskrze",
      "vesnice",
      "vespodu",
      "vesta",
      "veterina",
      "veverka",
      "vibrace",
      "vichr",
      "videohra",
      "vidina",
      "vidle",
      "vila",
      "vinice",
      "viset",
      "vitalita",
      "vize",
      "vizitka",
      "vjezd",
      "vklad",
      "vkus",
      "vlajka",
      "vlak",
      "vlasec",
      "vlevo",
      "vlhkost",
      "vliv",
      "vlnovka",
      "vloupat",
      "vnucovat",
      "vnuk",
      "voda",
      "vodivost",
      "vodoznak",
      "vodstvo",
      "vojensky",
      "vojna",
      "vojsko",
      "volant",
      "volba",
      "volit",
      "volno",
      "voskovka",
      "vozidlo",
      "vozovna",
      "vpravo",
      "vrabec",
      "vracet",
      "vrah",
      "vrata",
      "vrba",
      "vrcholek",
      "vrhat",
      "vrstva",
      "vrtule",
      "vsadit",
      "vstoupit",
      "vstup",
      "vtip",
      "vybavit",
      "vybrat",
      "vychovat",
      "vydat",
      "vydra",
      "vyfotit",
      "vyhledat",
      "vyhnout",
      "vyhodit",
      "vyhradit",
      "vyhubit",
      "vyjasnit",
      "vyjet",
      "vyjmout",
      "vyklopit",
      "vykonat",
      "vylekat",
      "vymazat",
      "vymezit",
      "vymizet",
      "vymyslet",
      "vynechat",
      "vynikat",
      "vynutit",
      "vypadat",
      "vyplatit",
      "vypravit",
      "vypustit",
      "vyrazit",
      "vyrovnat",
      "vyrvat",
      "vyslovit",
      "vysoko",
      "vystavit",
      "vysunout",
      "vysypat",
      "vytasit",
      "vytesat",
      "vytratit",
      "vyvinout",
      "vyvolat",
      "vyvrhel",
      "vyzdobit",
      "vyznat",
      "vzadu",
      "vzbudit",
      "vzchopit",
      "vzdor",
      "vzduch",
      "vzdychat",
      "vzestup",
      "vzhledem",
      "vzkaz",
      "vzlykat",
      "vznik",
      "vzorek",
      "vzpoura",
      "vztah",
      "vztek",
      "xylofon",
      "zabrat",
      "zabydlet",
      "zachovat",
      "zadarmo",
      "zadusit",
      "zafoukat",
      "zahltit",
      "zahodit",
      "zahrada",
      "zahynout",
      "zajatec",
      "zajet",
      "zajistit",
      "zaklepat",
      "zakoupit",
      "zalepit",
      "zamezit",
      "zamotat",
      "zamyslet",
      "zanechat",
      "zanikat",
      "zaplatit",
      "zapojit",
      "zapsat",
      "zarazit",
      "zastavit",
      "zasunout",
      "zatajit",
      "zatemnit",
      "zatknout",
      "zaujmout",
      "zavalit",
      "zavelet",
      "zavinit",
      "zavolat",
      "zavrtat",
      "zazvonit",
      "zbavit",
      "zbrusu",
      "zbudovat",
      "zbytek",
      "zdaleka",
      "zdarma",
      "zdatnost",
      "zdivo",
      "zdobit",
      "zdroj",
      "zdvih",
      "zdymadlo",
      "zelenina",
      "zeman",
      "zemina",
      "zeptat",
      "zezadu",
      "zezdola",
      "zhatit",
      "zhltnout",
      "zhluboka",
      "zhotovit",
      "zhruba",
      "zima",
      "zimnice",
      "zjemnit",
      "zklamat",
      "zkoumat",
      "zkratka",
      "zkumavka",
      "zlato",
      "zlehka",
      "zloba",
      "zlom",
      "zlost",
      "zlozvyk",
      "zmapovat",
      "zmar",
      "zmatek",
      "zmije",
      "zmizet",
      "zmocnit",
      "zmodrat",
      "zmrzlina",
      "zmutovat",
      "znak",
      "znalost",
      "znamenat",
      "znovu",
      "zobrazit",
      "zotavit",
      "zoubek",
      "zoufale",
      "zplodit",
      "zpomalit",
      "zprava",
      "zprostit",
      "zprudka",
      "zprvu",
      "zrada",
      "zranit",
      "zrcadlo",
      "zrnitost",
      "zrno",
      "zrovna",
      "zrychlit",
      "zrzavost",
      "zticha",
      "ztratit",
      "zubovina",
      "zubr",
      "zvednout",
      "zvenku",
      "zvesela",
      "zvon",
      "zvrat",
      "zvukovod",
      "zvyk"
    ];
  }
});

// node_modules/bip39/src/wordlists/chinese_simplified.json
var require_chinese_simplified = __commonJS({
  "node_modules/bip39/src/wordlists/chinese_simplified.json"(exports, module) {
    module.exports = [
      "\u7684",
      "\u4E00",
      "\u662F",
      "\u5728",
      "\u4E0D",
      "\u4E86",
      "\u6709",
      "\u548C",
      "\u4EBA",
      "\u8FD9",
      "\u4E2D",
      "\u5927",
      "\u4E3A",
      "\u4E0A",
      "\u4E2A",
      "\u56FD",
      "\u6211",
      "\u4EE5",
      "\u8981",
      "\u4ED6",
      "\u65F6",
      "\u6765",
      "\u7528",
      "\u4EEC",
      "\u751F",
      "\u5230",
      "\u4F5C",
      "\u5730",
      "\u4E8E",
      "\u51FA",
      "\u5C31",
      "\u5206",
      "\u5BF9",
      "\u6210",
      "\u4F1A",
      "\u53EF",
      "\u4E3B",
      "\u53D1",
      "\u5E74",
      "\u52A8",
      "\u540C",
      "\u5DE5",
      "\u4E5F",
      "\u80FD",
      "\u4E0B",
      "\u8FC7",
      "\u5B50",
      "\u8BF4",
      "\u4EA7",
      "\u79CD",
      "\u9762",
      "\u800C",
      "\u65B9",
      "\u540E",
      "\u591A",
      "\u5B9A",
      "\u884C",
      "\u5B66",
      "\u6CD5",
      "\u6240",
      "\u6C11",
      "\u5F97",
      "\u7ECF",
      "\u5341",
      "\u4E09",
      "\u4E4B",
      "\u8FDB",
      "\u7740",
      "\u7B49",
      "\u90E8",
      "\u5EA6",
      "\u5BB6",
      "\u7535",
      "\u529B",
      "\u91CC",
      "\u5982",
      "\u6C34",
      "\u5316",
      "\u9AD8",
      "\u81EA",
      "\u4E8C",
      "\u7406",
      "\u8D77",
      "\u5C0F",
      "\u7269",
      "\u73B0",
      "\u5B9E",
      "\u52A0",
      "\u91CF",
      "\u90FD",
      "\u4E24",
      "\u4F53",
      "\u5236",
      "\u673A",
      "\u5F53",
      "\u4F7F",
      "\u70B9",
      "\u4ECE",
      "\u4E1A",
      "\u672C",
      "\u53BB",
      "\u628A",
      "\u6027",
      "\u597D",
      "\u5E94",
      "\u5F00",
      "\u5B83",
      "\u5408",
      "\u8FD8",
      "\u56E0",
      "\u7531",
      "\u5176",
      "\u4E9B",
      "\u7136",
      "\u524D",
      "\u5916",
      "\u5929",
      "\u653F",
      "\u56DB",
      "\u65E5",
      "\u90A3",
      "\u793E",
      "\u4E49",
      "\u4E8B",
      "\u5E73",
      "\u5F62",
      "\u76F8",
      "\u5168",
      "\u8868",
      "\u95F4",
      "\u6837",
      "\u4E0E",
      "\u5173",
      "\u5404",
      "\u91CD",
      "\u65B0",
      "\u7EBF",
      "\u5185",
      "\u6570",
      "\u6B63",
      "\u5FC3",
      "\u53CD",
      "\u4F60",
      "\u660E",
      "\u770B",
      "\u539F",
      "\u53C8",
      "\u4E48",
      "\u5229",
      "\u6BD4",
      "\u6216",
      "\u4F46",
      "\u8D28",
      "\u6C14",
      "\u7B2C",
      "\u5411",
      "\u9053",
      "\u547D",
      "\u6B64",
      "\u53D8",
      "\u6761",
      "\u53EA",
      "\u6CA1",
      "\u7ED3",
      "\u89E3",
      "\u95EE",
      "\u610F",
      "\u5EFA",
      "\u6708",
      "\u516C",
      "\u65E0",
      "\u7CFB",
      "\u519B",
      "\u5F88",
      "\u60C5",
      "\u8005",
      "\u6700",
      "\u7ACB",
      "\u4EE3",
      "\u60F3",
      "\u5DF2",
      "\u901A",
      "\u5E76",
      "\u63D0",
      "\u76F4",
      "\u9898",
      "\u515A",
      "\u7A0B",
      "\u5C55",
      "\u4E94",
      "\u679C",
      "\u6599",
      "\u8C61",
      "\u5458",
      "\u9769",
      "\u4F4D",
      "\u5165",
      "\u5E38",
      "\u6587",
      "\u603B",
      "\u6B21",
      "\u54C1",
      "\u5F0F",
      "\u6D3B",
      "\u8BBE",
      "\u53CA",
      "\u7BA1",
      "\u7279",
      "\u4EF6",
      "\u957F",
      "\u6C42",
      "\u8001",
      "\u5934",
      "\u57FA",
      "\u8D44",
      "\u8FB9",
      "\u6D41",
      "\u8DEF",
      "\u7EA7",
      "\u5C11",
      "\u56FE",
      "\u5C71",
      "\u7EDF",
      "\u63A5",
      "\u77E5",
      "\u8F83",
      "\u5C06",
      "\u7EC4",
      "\u89C1",
      "\u8BA1",
      "\u522B",
      "\u5979",
      "\u624B",
      "\u89D2",
      "\u671F",
      "\u6839",
      "\u8BBA",
      "\u8FD0",
      "\u519C",
      "\u6307",
      "\u51E0",
      "\u4E5D",
      "\u533A",
      "\u5F3A",
      "\u653E",
      "\u51B3",
      "\u897F",
      "\u88AB",
      "\u5E72",
      "\u505A",
      "\u5FC5",
      "\u6218",
      "\u5148",
      "\u56DE",
      "\u5219",
      "\u4EFB",
      "\u53D6",
      "\u636E",
      "\u5904",
      "\u961F",
      "\u5357",
      "\u7ED9",
      "\u8272",
      "\u5149",
      "\u95E8",
      "\u5373",
      "\u4FDD",
      "\u6CBB",
      "\u5317",
      "\u9020",
      "\u767E",
      "\u89C4",
      "\u70ED",
      "\u9886",
      "\u4E03",
      "\u6D77",
      "\u53E3",
      "\u4E1C",
      "\u5BFC",
      "\u5668",
      "\u538B",
      "\u5FD7",
      "\u4E16",
      "\u91D1",
      "\u589E",
      "\u4E89",
      "\u6D4E",
      "\u9636",
      "\u6CB9",
      "\u601D",
      "\u672F",
      "\u6781",
      "\u4EA4",
      "\u53D7",
      "\u8054",
      "\u4EC0",
      "\u8BA4",
      "\u516D",
      "\u5171",
      "\u6743",
      "\u6536",
      "\u8BC1",
      "\u6539",
      "\u6E05",
      "\u7F8E",
      "\u518D",
      "\u91C7",
      "\u8F6C",
      "\u66F4",
      "\u5355",
      "\u98CE",
      "\u5207",
      "\u6253",
      "\u767D",
      "\u6559",
      "\u901F",
      "\u82B1",
      "\u5E26",
      "\u5B89",
      "\u573A",
      "\u8EAB",
      "\u8F66",
      "\u4F8B",
      "\u771F",
      "\u52A1",
      "\u5177",
      "\u4E07",
      "\u6BCF",
      "\u76EE",
      "\u81F3",
      "\u8FBE",
      "\u8D70",
      "\u79EF",
      "\u793A",
      "\u8BAE",
      "\u58F0",
      "\u62A5",
      "\u6597",
      "\u5B8C",
      "\u7C7B",
      "\u516B",
      "\u79BB",
      "\u534E",
      "\u540D",
      "\u786E",
      "\u624D",
      "\u79D1",
      "\u5F20",
      "\u4FE1",
      "\u9A6C",
      "\u8282",
      "\u8BDD",
      "\u7C73",
      "\u6574",
      "\u7A7A",
      "\u5143",
      "\u51B5",
      "\u4ECA",
      "\u96C6",
      "\u6E29",
      "\u4F20",
      "\u571F",
      "\u8BB8",
      "\u6B65",
      "\u7FA4",
      "\u5E7F",
      "\u77F3",
      "\u8BB0",
      "\u9700",
      "\u6BB5",
      "\u7814",
      "\u754C",
      "\u62C9",
      "\u6797",
      "\u5F8B",
      "\u53EB",
      "\u4E14",
      "\u7A76",
      "\u89C2",
      "\u8D8A",
      "\u7EC7",
      "\u88C5",
      "\u5F71",
      "\u7B97",
      "\u4F4E",
      "\u6301",
      "\u97F3",
      "\u4F17",
      "\u4E66",
      "\u5E03",
      "\u590D",
      "\u5BB9",
      "\u513F",
      "\u987B",
      "\u9645",
      "\u5546",
      "\u975E",
      "\u9A8C",
      "\u8FDE",
      "\u65AD",
      "\u6DF1",
      "\u96BE",
      "\u8FD1",
      "\u77FF",
      "\u5343",
      "\u5468",
      "\u59D4",
      "\u7D20",
      "\u6280",
      "\u5907",
      "\u534A",
      "\u529E",
      "\u9752",
      "\u7701",
      "\u5217",
      "\u4E60",
      "\u54CD",
      "\u7EA6",
      "\u652F",
      "\u822C",
      "\u53F2",
      "\u611F",
      "\u52B3",
      "\u4FBF",
      "\u56E2",
      "\u5F80",
      "\u9178",
      "\u5386",
      "\u5E02",
      "\u514B",
      "\u4F55",
      "\u9664",
      "\u6D88",
      "\u6784",
      "\u5E9C",
      "\u79F0",
      "\u592A",
      "\u51C6",
      "\u7CBE",
      "\u503C",
      "\u53F7",
      "\u7387",
      "\u65CF",
      "\u7EF4",
      "\u5212",
      "\u9009",
      "\u6807",
      "\u5199",
      "\u5B58",
      "\u5019",
      "\u6BDB",
      "\u4EB2",
      "\u5FEB",
      "\u6548",
      "\u65AF",
      "\u9662",
      "\u67E5",
      "\u6C5F",
      "\u578B",
      "\u773C",
      "\u738B",
      "\u6309",
      "\u683C",
      "\u517B",
      "\u6613",
      "\u7F6E",
      "\u6D3E",
      "\u5C42",
      "\u7247",
      "\u59CB",
      "\u5374",
      "\u4E13",
      "\u72B6",
      "\u80B2",
      "\u5382",
      "\u4EAC",
      "\u8BC6",
      "\u9002",
      "\u5C5E",
      "\u5706",
      "\u5305",
      "\u706B",
      "\u4F4F",
      "\u8C03",
      "\u6EE1",
      "\u53BF",
      "\u5C40",
      "\u7167",
      "\u53C2",
      "\u7EA2",
      "\u7EC6",
      "\u5F15",
      "\u542C",
      "\u8BE5",
      "\u94C1",
      "\u4EF7",
      "\u4E25",
      "\u9996",
      "\u5E95",
      "\u6DB2",
      "\u5B98",
      "\u5FB7",
      "\u968F",
      "\u75C5",
      "\u82CF",
      "\u5931",
      "\u5C14",
      "\u6B7B",
      "\u8BB2",
      "\u914D",
      "\u5973",
      "\u9EC4",
      "\u63A8",
      "\u663E",
      "\u8C08",
      "\u7F6A",
      "\u795E",
      "\u827A",
      "\u5462",
      "\u5E2D",
      "\u542B",
      "\u4F01",
      "\u671B",
      "\u5BC6",
      "\u6279",
      "\u8425",
      "\u9879",
      "\u9632",
      "\u4E3E",
      "\u7403",
      "\u82F1",
      "\u6C27",
      "\u52BF",
      "\u544A",
      "\u674E",
      "\u53F0",
      "\u843D",
      "\u6728",
      "\u5E2E",
      "\u8F6E",
      "\u7834",
      "\u4E9A",
      "\u5E08",
      "\u56F4",
      "\u6CE8",
      "\u8FDC",
      "\u5B57",
      "\u6750",
      "\u6392",
      "\u4F9B",
      "\u6CB3",
      "\u6001",
      "\u5C01",
      "\u53E6",
      "\u65BD",
      "\u51CF",
      "\u6811",
      "\u6EB6",
      "\u600E",
      "\u6B62",
      "\u6848",
      "\u8A00",
      "\u58EB",
      "\u5747",
      "\u6B66",
      "\u56FA",
      "\u53F6",
      "\u9C7C",
      "\u6CE2",
      "\u89C6",
      "\u4EC5",
      "\u8D39",
      "\u7D27",
      "\u7231",
      "\u5DE6",
      "\u7AE0",
      "\u65E9",
      "\u671D",
      "\u5BB3",
      "\u7EED",
      "\u8F7B",
      "\u670D",
      "\u8BD5",
      "\u98DF",
      "\u5145",
      "\u5175",
      "\u6E90",
      "\u5224",
      "\u62A4",
      "\u53F8",
      "\u8DB3",
      "\u67D0",
      "\u7EC3",
      "\u5DEE",
      "\u81F4",
      "\u677F",
      "\u7530",
      "\u964D",
      "\u9ED1",
      "\u72AF",
      "\u8D1F",
      "\u51FB",
      "\u8303",
      "\u7EE7",
      "\u5174",
      "\u4F3C",
      "\u4F59",
      "\u575A",
      "\u66F2",
      "\u8F93",
      "\u4FEE",
      "\u6545",
      "\u57CE",
      "\u592B",
      "\u591F",
      "\u9001",
      "\u7B14",
      "\u8239",
      "\u5360",
      "\u53F3",
      "\u8D22",
      "\u5403",
      "\u5BCC",
      "\u6625",
      "\u804C",
      "\u89C9",
      "\u6C49",
      "\u753B",
      "\u529F",
      "\u5DF4",
      "\u8DDF",
      "\u867D",
      "\u6742",
      "\u98DE",
      "\u68C0",
      "\u5438",
      "\u52A9",
      "\u5347",
      "\u9633",
      "\u4E92",
      "\u521D",
      "\u521B",
      "\u6297",
      "\u8003",
      "\u6295",
      "\u574F",
      "\u7B56",
      "\u53E4",
      "\u5F84",
      "\u6362",
      "\u672A",
      "\u8DD1",
      "\u7559",
      "\u94A2",
      "\u66FE",
      "\u7AEF",
      "\u8D23",
      "\u7AD9",
      "\u7B80",
      "\u8FF0",
      "\u94B1",
      "\u526F",
      "\u5C3D",
      "\u5E1D",
      "\u5C04",
      "\u8349",
      "\u51B2",
      "\u627F",
      "\u72EC",
      "\u4EE4",
      "\u9650",
      "\u963F",
      "\u5BA3",
      "\u73AF",
      "\u53CC",
      "\u8BF7",
      "\u8D85",
      "\u5FAE",
      "\u8BA9",
      "\u63A7",
      "\u5DDE",
      "\u826F",
      "\u8F74",
      "\u627E",
      "\u5426",
      "\u7EAA",
      "\u76CA",
      "\u4F9D",
      "\u4F18",
      "\u9876",
      "\u7840",
      "\u8F7D",
      "\u5012",
      "\u623F",
      "\u7A81",
      "\u5750",
      "\u7C89",
      "\u654C",
      "\u7565",
      "\u5BA2",
      "\u8881",
      "\u51B7",
      "\u80DC",
      "\u7EDD",
      "\u6790",
      "\u5757",
      "\u5242",
      "\u6D4B",
      "\u4E1D",
      "\u534F",
      "\u8BC9",
      "\u5FF5",
      "\u9648",
      "\u4ECD",
      "\u7F57",
      "\u76D0",
      "\u53CB",
      "\u6D0B",
      "\u9519",
      "\u82E6",
      "\u591C",
      "\u5211",
      "\u79FB",
      "\u9891",
      "\u9010",
      "\u9760",
      "\u6DF7",
      "\u6BCD",
      "\u77ED",
      "\u76AE",
      "\u7EC8",
      "\u805A",
      "\u6C7D",
      "\u6751",
      "\u4E91",
      "\u54EA",
      "\u65E2",
      "\u8DDD",
      "\u536B",
      "\u505C",
      "\u70C8",
      "\u592E",
      "\u5BDF",
      "\u70E7",
      "\u8FC5",
      "\u5883",
      "\u82E5",
      "\u5370",
      "\u6D32",
      "\u523B",
      "\u62EC",
      "\u6FC0",
      "\u5B54",
      "\u641E",
      "\u751A",
      "\u5BA4",
      "\u5F85",
      "\u6838",
      "\u6821",
      "\u6563",
      "\u4FB5",
      "\u5427",
      "\u7532",
      "\u6E38",
      "\u4E45",
      "\u83DC",
      "\u5473",
      "\u65E7",
      "\u6A21",
      "\u6E56",
      "\u8D27",
      "\u635F",
      "\u9884",
      "\u963B",
      "\u6BEB",
      "\u666E",
      "\u7A33",
      "\u4E59",
      "\u5988",
      "\u690D",
      "\u606F",
      "\u6269",
      "\u94F6",
      "\u8BED",
      "\u6325",
      "\u9152",
      "\u5B88",
      "\u62FF",
      "\u5E8F",
      "\u7EB8",
      "\u533B",
      "\u7F3A",
      "\u96E8",
      "\u5417",
      "\u9488",
      "\u5218",
      "\u554A",
      "\u6025",
      "\u5531",
      "\u8BEF",
      "\u8BAD",
      "\u613F",
      "\u5BA1",
      "\u9644",
      "\u83B7",
      "\u8336",
      "\u9C9C",
      "\u7CAE",
      "\u65A4",
      "\u5B69",
      "\u8131",
      "\u786B",
      "\u80A5",
      "\u5584",
      "\u9F99",
      "\u6F14",
      "\u7236",
      "\u6E10",
      "\u8840",
      "\u6B22",
      "\u68B0",
      "\u638C",
      "\u6B4C",
      "\u6C99",
      "\u521A",
      "\u653B",
      "\u8C13",
      "\u76FE",
      "\u8BA8",
      "\u665A",
      "\u7C92",
      "\u4E71",
      "\u71C3",
      "\u77DB",
      "\u4E4E",
      "\u6740",
      "\u836F",
      "\u5B81",
      "\u9C81",
      "\u8D35",
      "\u949F",
      "\u7164",
      "\u8BFB",
      "\u73ED",
      "\u4F2F",
      "\u9999",
      "\u4ECB",
      "\u8FEB",
      "\u53E5",
      "\u4E30",
      "\u57F9",
      "\u63E1",
      "\u5170",
      "\u62C5",
      "\u5F26",
      "\u86CB",
      "\u6C89",
      "\u5047",
      "\u7A7F",
      "\u6267",
      "\u7B54",
      "\u4E50",
      "\u8C01",
      "\u987A",
      "\u70DF",
      "\u7F29",
      "\u5F81",
      "\u8138",
      "\u559C",
      "\u677E",
      "\u811A",
      "\u56F0",
      "\u5F02",
      "\u514D",
      "\u80CC",
      "\u661F",
      "\u798F",
      "\u4E70",
      "\u67D3",
      "\u4E95",
      "\u6982",
      "\u6162",
      "\u6015",
      "\u78C1",
      "\u500D",
      "\u7956",
      "\u7687",
      "\u4FC3",
      "\u9759",
      "\u8865",
      "\u8BC4",
      "\u7FFB",
      "\u8089",
      "\u8DF5",
      "\u5C3C",
      "\u8863",
      "\u5BBD",
      "\u626C",
      "\u68C9",
      "\u5E0C",
      "\u4F24",
      "\u64CD",
      "\u5782",
      "\u79CB",
      "\u5B9C",
      "\u6C22",
      "\u5957",
      "\u7763",
      "\u632F",
      "\u67B6",
      "\u4EAE",
      "\u672B",
      "\u5BAA",
      "\u5E86",
      "\u7F16",
      "\u725B",
      "\u89E6",
      "\u6620",
      "\u96F7",
      "\u9500",
      "\u8BD7",
      "\u5EA7",
      "\u5C45",
      "\u6293",
      "\u88C2",
      "\u80DE",
      "\u547C",
      "\u5A18",
      "\u666F",
      "\u5A01",
      "\u7EFF",
      "\u6676",
      "\u539A",
      "\u76DF",
      "\u8861",
      "\u9E21",
      "\u5B59",
      "\u5EF6",
      "\u5371",
      "\u80F6",
      "\u5C4B",
      "\u4E61",
      "\u4E34",
      "\u9646",
      "\u987E",
      "\u6389",
      "\u5440",
      "\u706F",
      "\u5C81",
      "\u63AA",
      "\u675F",
      "\u8010",
      "\u5267",
      "\u7389",
      "\u8D75",
      "\u8DF3",
      "\u54E5",
      "\u5B63",
      "\u8BFE",
      "\u51EF",
      "\u80E1",
      "\u989D",
      "\u6B3E",
      "\u7ECD",
      "\u5377",
      "\u9F50",
      "\u4F1F",
      "\u84B8",
      "\u6B96",
      "\u6C38",
      "\u5B97",
      "\u82D7",
      "\u5DDD",
      "\u7089",
      "\u5CA9",
      "\u5F31",
      "\u96F6",
      "\u6768",
      "\u594F",
      "\u6CBF",
      "\u9732",
      "\u6746",
      "\u63A2",
      "\u6ED1",
      "\u9547",
      "\u996D",
      "\u6D53",
      "\u822A",
      "\u6000",
      "\u8D76",
      "\u5E93",
      "\u593A",
      "\u4F0A",
      "\u7075",
      "\u7A0E",
      "\u9014",
      "\u706D",
      "\u8D5B",
      "\u5F52",
      "\u53EC",
      "\u9F13",
      "\u64AD",
      "\u76D8",
      "\u88C1",
      "\u9669",
      "\u5EB7",
      "\u552F",
      "\u5F55",
      "\u83CC",
      "\u7EAF",
      "\u501F",
      "\u7CD6",
      "\u76D6",
      "\u6A2A",
      "\u7B26",
      "\u79C1",
      "\u52AA",
      "\u5802",
      "\u57DF",
      "\u67AA",
      "\u6DA6",
      "\u5E45",
      "\u54C8",
      "\u7ADF",
      "\u719F",
      "\u866B",
      "\u6CFD",
      "\u8111",
      "\u58E4",
      "\u78B3",
      "\u6B27",
      "\u904D",
      "\u4FA7",
      "\u5BE8",
      "\u6562",
      "\u5F7B",
      "\u8651",
      "\u659C",
      "\u8584",
      "\u5EAD",
      "\u7EB3",
      "\u5F39",
      "\u9972",
      "\u4F38",
      "\u6298",
      "\u9EA6",
      "\u6E7F",
      "\u6697",
      "\u8377",
      "\u74E6",
      "\u585E",
      "\u5E8A",
      "\u7B51",
      "\u6076",
      "\u6237",
      "\u8BBF",
      "\u5854",
      "\u5947",
      "\u900F",
      "\u6881",
      "\u5200",
      "\u65CB",
      "\u8FF9",
      "\u5361",
      "\u6C2F",
      "\u9047",
      "\u4EFD",
      "\u6BD2",
      "\u6CE5",
      "\u9000",
      "\u6D17",
      "\u6446",
      "\u7070",
      "\u5F69",
      "\u5356",
      "\u8017",
      "\u590F",
      "\u62E9",
      "\u5FD9",
      "\u94DC",
      "\u732E",
      "\u786C",
      "\u4E88",
      "\u7E41",
      "\u5708",
      "\u96EA",
      "\u51FD",
      "\u4EA6",
      "\u62BD",
      "\u7BC7",
      "\u9635",
      "\u9634",
      "\u4E01",
      "\u5C3A",
      "\u8FFD",
      "\u5806",
      "\u96C4",
      "\u8FCE",
      "\u6CDB",
      "\u7238",
      "\u697C",
      "\u907F",
      "\u8C0B",
      "\u5428",
      "\u91CE",
      "\u732A",
      "\u65D7",
      "\u7D2F",
      "\u504F",
      "\u5178",
      "\u9986",
      "\u7D22",
      "\u79E6",
      "\u8102",
      "\u6F6E",
      "\u7237",
      "\u8C46",
      "\u5FFD",
      "\u6258",
      "\u60CA",
      "\u5851",
      "\u9057",
      "\u6108",
      "\u6731",
      "\u66FF",
      "\u7EA4",
      "\u7C97",
      "\u503E",
      "\u5C1A",
      "\u75DB",
      "\u695A",
      "\u8C22",
      "\u594B",
      "\u8D2D",
      "\u78E8",
      "\u541B",
      "\u6C60",
      "\u65C1",
      "\u788E",
      "\u9AA8",
      "\u76D1",
      "\u6355",
      "\u5F1F",
      "\u66B4",
      "\u5272",
      "\u8D2F",
      "\u6B8A",
      "\u91CA",
      "\u8BCD",
      "\u4EA1",
      "\u58C1",
      "\u987F",
      "\u5B9D",
      "\u5348",
      "\u5C18",
      "\u95FB",
      "\u63ED",
      "\u70AE",
      "\u6B8B",
      "\u51AC",
      "\u6865",
      "\u5987",
      "\u8B66",
      "\u7EFC",
      "\u62DB",
      "\u5434",
      "\u4ED8",
      "\u6D6E",
      "\u906D",
      "\u5F90",
      "\u60A8",
      "\u6447",
      "\u8C37",
      "\u8D5E",
      "\u7BB1",
      "\u9694",
      "\u8BA2",
      "\u7537",
      "\u5439",
      "\u56ED",
      "\u7EB7",
      "\u5510",
      "\u8D25",
      "\u5B8B",
      "\u73BB",
      "\u5DE8",
      "\u8015",
      "\u5766",
      "\u8363",
      "\u95ED",
      "\u6E7E",
      "\u952E",
      "\u51E1",
      "\u9A7B",
      "\u9505",
      "\u6551",
      "\u6069",
      "\u5265",
      "\u51DD",
      "\u78B1",
      "\u9F7F",
      "\u622A",
      "\u70BC",
      "\u9EBB",
      "\u7EBA",
      "\u7981",
      "\u5E9F",
      "\u76DB",
      "\u7248",
      "\u7F13",
      "\u51C0",
      "\u775B",
      "\u660C",
      "\u5A5A",
      "\u6D89",
      "\u7B52",
      "\u5634",
      "\u63D2",
      "\u5CB8",
      "\u6717",
      "\u5E84",
      "\u8857",
      "\u85CF",
      "\u59D1",
      "\u8D38",
      "\u8150",
      "\u5974",
      "\u5566",
      "\u60EF",
      "\u4E58",
      "\u4F19",
      "\u6062",
      "\u5300",
      "\u7EB1",
      "\u624E",
      "\u8FA9",
      "\u8033",
      "\u5F6A",
      "\u81E3",
      "\u4EBF",
      "\u7483",
      "\u62B5",
      "\u8109",
      "\u79C0",
      "\u8428",
      "\u4FC4",
      "\u7F51",
      "\u821E",
      "\u5E97",
      "\u55B7",
      "\u7EB5",
      "\u5BF8",
      "\u6C57",
      "\u6302",
      "\u6D2A",
      "\u8D3A",
      "\u95EA",
      "\u67EC",
      "\u7206",
      "\u70EF",
      "\u6D25",
      "\u7A3B",
      "\u5899",
      "\u8F6F",
      "\u52C7",
      "\u50CF",
      "\u6EDA",
      "\u5398",
      "\u8499",
      "\u82B3",
      "\u80AF",
      "\u5761",
      "\u67F1",
      "\u8361",
      "\u817F",
      "\u4EEA",
      "\u65C5",
      "\u5C3E",
      "\u8F67",
      "\u51B0",
      "\u8D21",
      "\u767B",
      "\u9ECE",
      "\u524A",
      "\u94BB",
      "\u52D2",
      "\u9003",
      "\u969C",
      "\u6C28",
      "\u90ED",
      "\u5CF0",
      "\u5E01",
      "\u6E2F",
      "\u4F0F",
      "\u8F68",
      "\u4EA9",
      "\u6BD5",
      "\u64E6",
      "\u83AB",
      "\u523A",
      "\u6D6A",
      "\u79D8",
      "\u63F4",
      "\u682A",
      "\u5065",
      "\u552E",
      "\u80A1",
      "\u5C9B",
      "\u7518",
      "\u6CE1",
      "\u7761",
      "\u7AE5",
      "\u94F8",
      "\u6C64",
      "\u9600",
      "\u4F11",
      "\u6C47",
      "\u820D",
      "\u7267",
      "\u7ED5",
      "\u70B8",
      "\u54F2",
      "\u78F7",
      "\u7EE9",
      "\u670B",
      "\u6DE1",
      "\u5C16",
      "\u542F",
      "\u9677",
      "\u67F4",
      "\u5448",
      "\u5F92",
      "\u989C",
      "\u6CEA",
      "\u7A0D",
      "\u5FD8",
      "\u6CF5",
      "\u84DD",
      "\u62D6",
      "\u6D1E",
      "\u6388",
      "\u955C",
      "\u8F9B",
      "\u58EE",
      "\u950B",
      "\u8D2B",
      "\u865A",
      "\u5F2F",
      "\u6469",
      "\u6CF0",
      "\u5E7C",
      "\u5EF7",
      "\u5C0A",
      "\u7A97",
      "\u7EB2",
      "\u5F04",
      "\u96B6",
      "\u7591",
      "\u6C0F",
      "\u5BAB",
      "\u59D0",
      "\u9707",
      "\u745E",
      "\u602A",
      "\u5C24",
      "\u7434",
      "\u5FAA",
      "\u63CF",
      "\u819C",
      "\u8FDD",
      "\u5939",
      "\u8170",
      "\u7F18",
      "\u73E0",
      "\u7A77",
      "\u68EE",
      "\u679D",
      "\u7AF9",
      "\u6C9F",
      "\u50AC",
      "\u7EF3",
      "\u5FC6",
      "\u90A6",
      "\u5269",
      "\u5E78",
      "\u6D46",
      "\u680F",
      "\u62E5",
      "\u7259",
      "\u8D2E",
      "\u793C",
      "\u6EE4",
      "\u94A0",
      "\u7EB9",
      "\u7F62",
      "\u62CD",
      "\u54B1",
      "\u558A",
      "\u8896",
      "\u57C3",
      "\u52E4",
      "\u7F5A",
      "\u7126",
      "\u6F5C",
      "\u4F0D",
      "\u58A8",
      "\u6B32",
      "\u7F1D",
      "\u59D3",
      "\u520A",
      "\u9971",
      "\u4EFF",
      "\u5956",
      "\u94DD",
      "\u9B3C",
      "\u4E3D",
      "\u8DE8",
      "\u9ED8",
      "\u6316",
      "\u94FE",
      "\u626B",
      "\u559D",
      "\u888B",
      "\u70AD",
      "\u6C61",
      "\u5E55",
      "\u8BF8",
      "\u5F27",
      "\u52B1",
      "\u6885",
      "\u5976",
      "\u6D01",
      "\u707E",
      "\u821F",
      "\u9274",
      "\u82EF",
      "\u8BBC",
      "\u62B1",
      "\u6BC1",
      "\u61C2",
      "\u5BD2",
      "\u667A",
      "\u57D4",
      "\u5BC4",
      "\u5C4A",
      "\u8DC3",
      "\u6E21",
      "\u6311",
      "\u4E39",
      "\u8270",
      "\u8D1D",
      "\u78B0",
      "\u62D4",
      "\u7239",
      "\u6234",
      "\u7801",
      "\u68A6",
      "\u82BD",
      "\u7194",
      "\u8D64",
      "\u6E14",
      "\u54ED",
      "\u656C",
      "\u9897",
      "\u5954",
      "\u94C5",
      "\u4EF2",
      "\u864E",
      "\u7A00",
      "\u59B9",
      "\u4E4F",
      "\u73CD",
      "\u7533",
      "\u684C",
      "\u9075",
      "\u5141",
      "\u9686",
      "\u87BA",
      "\u4ED3",
      "\u9B4F",
      "\u9510",
      "\u6653",
      "\u6C2E",
      "\u517C",
      "\u9690",
      "\u788D",
      "\u8D6B",
      "\u62E8",
      "\u5FE0",
      "\u8083",
      "\u7F38",
      "\u7275",
      "\u62A2",
      "\u535A",
      "\u5DE7",
      "\u58F3",
      "\u5144",
      "\u675C",
      "\u8BAF",
      "\u8BDA",
      "\u78A7",
      "\u7965",
      "\u67EF",
      "\u9875",
      "\u5DE1",
      "\u77E9",
      "\u60B2",
      "\u704C",
      "\u9F84",
      "\u4F26",
      "\u7968",
      "\u5BFB",
      "\u6842",
      "\u94FA",
      "\u5723",
      "\u6050",
      "\u6070",
      "\u90D1",
      "\u8DA3",
      "\u62AC",
      "\u8352",
      "\u817E",
      "\u8D34",
      "\u67D4",
      "\u6EF4",
      "\u731B",
      "\u9614",
      "\u8F86",
      "\u59BB",
      "\u586B",
      "\u64A4",
      "\u50A8",
      "\u7B7E",
      "\u95F9",
      "\u6270",
      "\u7D2B",
      "\u7802",
      "\u9012",
      "\u620F",
      "\u540A",
      "\u9676",
      "\u4F10",
      "\u5582",
      "\u7597",
      "\u74F6",
      "\u5A46",
      "\u629A",
      "\u81C2",
      "\u6478",
      "\u5FCD",
      "\u867E",
      "\u8721",
      "\u90BB",
      "\u80F8",
      "\u5DE9",
      "\u6324",
      "\u5076",
      "\u5F03",
      "\u69FD",
      "\u52B2",
      "\u4E73",
      "\u9093",
      "\u5409",
      "\u4EC1",
      "\u70C2",
      "\u7816",
      "\u79DF",
      "\u4E4C",
      "\u8230",
      "\u4F34",
      "\u74DC",
      "\u6D45",
      "\u4E19",
      "\u6682",
      "\u71E5",
      "\u6A61",
      "\u67F3",
      "\u8FF7",
      "\u6696",
      "\u724C",
      "\u79E7",
      "\u80C6",
      "\u8BE6",
      "\u7C27",
      "\u8E0F",
      "\u74F7",
      "\u8C31",
      "\u5446",
      "\u5BBE",
      "\u7CCA",
      "\u6D1B",
      "\u8F89",
      "\u6124",
      "\u7ADE",
      "\u9699",
      "\u6012",
      "\u7C98",
      "\u4E43",
      "\u7EEA",
      "\u80A9",
      "\u7C4D",
      "\u654F",
      "\u6D82",
      "\u7199",
      "\u7686",
      "\u4FA6",
      "\u60AC",
      "\u6398",
      "\u4EAB",
      "\u7EA0",
      "\u9192",
      "\u72C2",
      "\u9501",
      "\u6DC0",
      "\u6068",
      "\u7272",
      "\u9738",
      "\u722C",
      "\u8D4F",
      "\u9006",
      "\u73A9",
      "\u9675",
      "\u795D",
      "\u79D2",
      "\u6D59",
      "\u8C8C",
      "\u5F79",
      "\u5F7C",
      "\u6089",
      "\u9E2D",
      "\u8D8B",
      "\u51E4",
      "\u6668",
      "\u755C",
      "\u8F88",
      "\u79E9",
      "\u5375",
      "\u7F72",
      "\u68AF",
      "\u708E",
      "\u6EE9",
      "\u68CB",
      "\u9A71",
      "\u7B5B",
      "\u5CE1",
      "\u5192",
      "\u5565",
      "\u5BFF",
      "\u8BD1",
      "\u6D78",
      "\u6CC9",
      "\u5E3D",
      "\u8FDF",
      "\u7845",
      "\u7586",
      "\u8D37",
      "\u6F0F",
      "\u7A3F",
      "\u51A0",
      "\u5AE9",
      "\u80C1",
      "\u82AF",
      "\u7262",
      "\u53DB",
      "\u8680",
      "\u5965",
      "\u9E23",
      "\u5CAD",
      "\u7F8A",
      "\u51ED",
      "\u4E32",
      "\u5858",
      "\u7ED8",
      "\u9175",
      "\u878D",
      "\u76C6",
      "\u9521",
      "\u5E99",
      "\u7B79",
      "\u51BB",
      "\u8F85",
      "\u6444",
      "\u88AD",
      "\u7B4B",
      "\u62D2",
      "\u50DA",
      "\u65F1",
      "\u94BE",
      "\u9E1F",
      "\u6F06",
      "\u6C88",
      "\u7709",
      "\u758F",
      "\u6DFB",
      "\u68D2",
      "\u7A57",
      "\u785D",
      "\u97E9",
      "\u903C",
      "\u626D",
      "\u4FA8",
      "\u51C9",
      "\u633A",
      "\u7897",
      "\u683D",
      "\u7092",
      "\u676F",
      "\u60A3",
      "\u998F",
      "\u529D",
      "\u8C6A",
      "\u8FBD",
      "\u52C3",
      "\u9E3F",
      "\u65E6",
      "\u540F",
      "\u62DC",
      "\u72D7",
      "\u57CB",
      "\u8F8A",
      "\u63A9",
      "\u996E",
      "\u642C",
      "\u9A82",
      "\u8F9E",
      "\u52FE",
      "\u6263",
      "\u4F30",
      "\u848B",
      "\u7ED2",
      "\u96FE",
      "\u4E08",
      "\u6735",
      "\u59C6",
      "\u62DF",
      "\u5B87",
      "\u8F91",
      "\u9655",
      "\u96D5",
      "\u507F",
      "\u84C4",
      "\u5D07",
      "\u526A",
      "\u5021",
      "\u5385",
      "\u54AC",
      "\u9A76",
      "\u85AF",
      "\u5237",
      "\u65A5",
      "\u756A",
      "\u8D4B",
      "\u5949",
      "\u4F5B",
      "\u6D47",
      "\u6F2B",
      "\u66FC",
      "\u6247",
      "\u9499",
      "\u6843",
      "\u6276",
      "\u4ED4",
      "\u8FD4",
      "\u4FD7",
      "\u4E8F",
      "\u8154",
      "\u978B",
      "\u68F1",
      "\u8986",
      "\u6846",
      "\u6084",
      "\u53D4",
      "\u649E",
      "\u9A97",
      "\u52D8",
      "\u65FA",
      "\u6CB8",
      "\u5B64",
      "\u5410",
      "\u5B5F",
      "\u6E20",
      "\u5C48",
      "\u75BE",
      "\u5999",
      "\u60DC",
      "\u4EF0",
      "\u72E0",
      "\u80C0",
      "\u8C10",
      "\u629B",
      "\u9709",
      "\u6851",
      "\u5C97",
      "\u561B",
      "\u8870",
      "\u76D7",
      "\u6E17",
      "\u810F",
      "\u8D56",
      "\u6D8C",
      "\u751C",
      "\u66F9",
      "\u9605",
      "\u808C",
      "\u54E9",
      "\u5389",
      "\u70C3",
      "\u7EAC",
      "\u6BC5",
      "\u6628",
      "\u4F2A",
      "\u75C7",
      "\u716E",
      "\u53F9",
      "\u9489",
      "\u642D",
      "\u830E",
      "\u7B3C",
      "\u9177",
      "\u5077",
      "\u5F13",
      "\u9525",
      "\u6052",
      "\u6770",
      "\u5751",
      "\u9F3B",
      "\u7FFC",
      "\u7EB6",
      "\u53D9",
      "\u72F1",
      "\u902E",
      "\u7F50",
      "\u7EDC",
      "\u68DA",
      "\u6291",
      "\u81A8",
      "\u852C",
      "\u5BFA",
      "\u9AA4",
      "\u7A46",
      "\u51B6",
      "\u67AF",
      "\u518C",
      "\u5C38",
      "\u51F8",
      "\u7EC5",
      "\u576F",
      "\u727A",
      "\u7130",
      "\u8F70",
      "\u6B23",
      "\u664B",
      "\u7626",
      "\u5FA1",
      "\u952D",
      "\u9526",
      "\u4E27",
      "\u65EC",
      "\u953B",
      "\u5784",
      "\u641C",
      "\u6251",
      "\u9080",
      "\u4EAD",
      "\u916F",
      "\u8FC8",
      "\u8212",
      "\u8106",
      "\u9176",
      "\u95F2",
      "\u5FE7",
      "\u915A",
      "\u987D",
      "\u7FBD",
      "\u6DA8",
      "\u5378",
      "\u4ED7",
      "\u966A",
      "\u8F9F",
      "\u60E9",
      "\u676D",
      "\u59DA",
      "\u809A",
      "\u6349",
      "\u98D8",
      "\u6F02",
      "\u6606",
      "\u6B3A",
      "\u543E",
      "\u90CE",
      "\u70F7",
      "\u6C41",
      "\u5475",
      "\u9970",
      "\u8427",
      "\u96C5",
      "\u90AE",
      "\u8FC1",
      "\u71D5",
      "\u6492",
      "\u59FB",
      "\u8D74",
      "\u5BB4",
      "\u70E6",
      "\u503A",
      "\u5E10",
      "\u6591",
      "\u94C3",
      "\u65E8",
      "\u9187",
      "\u8463",
      "\u997C",
      "\u96CF",
      "\u59FF",
      "\u62CC",
      "\u5085",
      "\u8179",
      "\u59A5",
      "\u63C9",
      "\u8D24",
      "\u62C6",
      "\u6B6A",
      "\u8461",
      "\u80FA",
      "\u4E22",
      "\u6D69",
      "\u5FBD",
      "\u6602",
      "\u57AB",
      "\u6321",
      "\u89C8",
      "\u8D2A",
      "\u6170",
      "\u7F34",
      "\u6C6A",
      "\u614C",
      "\u51AF",
      "\u8BFA",
      "\u59DC",
      "\u8C0A",
      "\u51F6",
      "\u52A3",
      "\u8BEC",
      "\u8000",
      "\u660F",
      "\u8EBA",
      "\u76C8",
      "\u9A91",
      "\u4E54",
      "\u6EAA",
      "\u4E1B",
      "\u5362",
      "\u62B9",
      "\u95F7",
      "\u54A8",
      "\u522E",
      "\u9A7E",
      "\u7F06",
      "\u609F",
      "\u6458",
      "\u94D2",
      "\u63B7",
      "\u9887",
      "\u5E7B",
      "\u67C4",
      "\u60E0",
      "\u60E8",
      "\u4F73",
      "\u4EC7",
      "\u814A",
      "\u7A9D",
      "\u6DA4",
      "\u5251",
      "\u77A7",
      "\u5821",
      "\u6CFC",
      "\u8471",
      "\u7F69",
      "\u970D",
      "\u635E",
      "\u80CE",
      "\u82CD",
      "\u6EE8",
      "\u4FE9",
      "\u6345",
      "\u6E58",
      "\u780D",
      "\u971E",
      "\u90B5",
      "\u8404",
      "\u75AF",
      "\u6DEE",
      "\u9042",
      "\u718A",
      "\u7CAA",
      "\u70D8",
      "\u5BBF",
      "\u6863",
      "\u6208",
      "\u9A73",
      "\u5AC2",
      "\u88D5",
      "\u5F99",
      "\u7BAD",
      "\u6350",
      "\u80A0",
      "\u6491",
      "\u6652",
      "\u8FA8",
      "\u6BBF",
      "\u83B2",
      "\u644A",
      "\u6405",
      "\u9171",
      "\u5C4F",
      "\u75AB",
      "\u54C0",
      "\u8521",
      "\u5835",
      "\u6CAB",
      "\u76B1",
      "\u7545",
      "\u53E0",
      "\u9601",
      "\u83B1",
      "\u6572",
      "\u8F96",
      "\u94A9",
      "\u75D5",
      "\u575D",
      "\u5DF7",
      "\u997F",
      "\u7978",
      "\u4E18",
      "\u7384",
      "\u6E9C",
      "\u66F0",
      "\u903B",
      "\u5F6D",
      "\u5C1D",
      "\u537F",
      "\u59A8",
      "\u8247",
      "\u541E",
      "\u97E6",
      "\u6028",
      "\u77EE",
      "\u6B47"
    ];
  }
});

// node_modules/bip39/src/wordlists/chinese_traditional.json
var require_chinese_traditional = __commonJS({
  "node_modules/bip39/src/wordlists/chinese_traditional.json"(exports, module) {
    module.exports = [
      "\u7684",
      "\u4E00",
      "\u662F",
      "\u5728",
      "\u4E0D",
      "\u4E86",
      "\u6709",
      "\u548C",
      "\u4EBA",
      "\u9019",
      "\u4E2D",
      "\u5927",
      "\u70BA",
      "\u4E0A",
      "\u500B",
      "\u570B",
      "\u6211",
      "\u4EE5",
      "\u8981",
      "\u4ED6",
      "\u6642",
      "\u4F86",
      "\u7528",
      "\u5011",
      "\u751F",
      "\u5230",
      "\u4F5C",
      "\u5730",
      "\u65BC",
      "\u51FA",
      "\u5C31",
      "\u5206",
      "\u5C0D",
      "\u6210",
      "\u6703",
      "\u53EF",
      "\u4E3B",
      "\u767C",
      "\u5E74",
      "\u52D5",
      "\u540C",
      "\u5DE5",
      "\u4E5F",
      "\u80FD",
      "\u4E0B",
      "\u904E",
      "\u5B50",
      "\u8AAA",
      "\u7522",
      "\u7A2E",
      "\u9762",
      "\u800C",
      "\u65B9",
      "\u5F8C",
      "\u591A",
      "\u5B9A",
      "\u884C",
      "\u5B78",
      "\u6CD5",
      "\u6240",
      "\u6C11",
      "\u5F97",
      "\u7D93",
      "\u5341",
      "\u4E09",
      "\u4E4B",
      "\u9032",
      "\u8457",
      "\u7B49",
      "\u90E8",
      "\u5EA6",
      "\u5BB6",
      "\u96FB",
      "\u529B",
      "\u88E1",
      "\u5982",
      "\u6C34",
      "\u5316",
      "\u9AD8",
      "\u81EA",
      "\u4E8C",
      "\u7406",
      "\u8D77",
      "\u5C0F",
      "\u7269",
      "\u73FE",
      "\u5BE6",
      "\u52A0",
      "\u91CF",
      "\u90FD",
      "\u5169",
      "\u9AD4",
      "\u5236",
      "\u6A5F",
      "\u7576",
      "\u4F7F",
      "\u9EDE",
      "\u5F9E",
      "\u696D",
      "\u672C",
      "\u53BB",
      "\u628A",
      "\u6027",
      "\u597D",
      "\u61C9",
      "\u958B",
      "\u5B83",
      "\u5408",
      "\u9084",
      "\u56E0",
      "\u7531",
      "\u5176",
      "\u4E9B",
      "\u7136",
      "\u524D",
      "\u5916",
      "\u5929",
      "\u653F",
      "\u56DB",
      "\u65E5",
      "\u90A3",
      "\u793E",
      "\u7FA9",
      "\u4E8B",
      "\u5E73",
      "\u5F62",
      "\u76F8",
      "\u5168",
      "\u8868",
      "\u9593",
      "\u6A23",
      "\u8207",
      "\u95DC",
      "\u5404",
      "\u91CD",
      "\u65B0",
      "\u7DDA",
      "\u5167",
      "\u6578",
      "\u6B63",
      "\u5FC3",
      "\u53CD",
      "\u4F60",
      "\u660E",
      "\u770B",
      "\u539F",
      "\u53C8",
      "\u9EBC",
      "\u5229",
      "\u6BD4",
      "\u6216",
      "\u4F46",
      "\u8CEA",
      "\u6C23",
      "\u7B2C",
      "\u5411",
      "\u9053",
      "\u547D",
      "\u6B64",
      "\u8B8A",
      "\u689D",
      "\u53EA",
      "\u6C92",
      "\u7D50",
      "\u89E3",
      "\u554F",
      "\u610F",
      "\u5EFA",
      "\u6708",
      "\u516C",
      "\u7121",
      "\u7CFB",
      "\u8ECD",
      "\u5F88",
      "\u60C5",
      "\u8005",
      "\u6700",
      "\u7ACB",
      "\u4EE3",
      "\u60F3",
      "\u5DF2",
      "\u901A",
      "\u4E26",
      "\u63D0",
      "\u76F4",
      "\u984C",
      "\u9EE8",
      "\u7A0B",
      "\u5C55",
      "\u4E94",
      "\u679C",
      "\u6599",
      "\u8C61",
      "\u54E1",
      "\u9769",
      "\u4F4D",
      "\u5165",
      "\u5E38",
      "\u6587",
      "\u7E3D",
      "\u6B21",
      "\u54C1",
      "\u5F0F",
      "\u6D3B",
      "\u8A2D",
      "\u53CA",
      "\u7BA1",
      "\u7279",
      "\u4EF6",
      "\u9577",
      "\u6C42",
      "\u8001",
      "\u982D",
      "\u57FA",
      "\u8CC7",
      "\u908A",
      "\u6D41",
      "\u8DEF",
      "\u7D1A",
      "\u5C11",
      "\u5716",
      "\u5C71",
      "\u7D71",
      "\u63A5",
      "\u77E5",
      "\u8F03",
      "\u5C07",
      "\u7D44",
      "\u898B",
      "\u8A08",
      "\u5225",
      "\u5979",
      "\u624B",
      "\u89D2",
      "\u671F",
      "\u6839",
      "\u8AD6",
      "\u904B",
      "\u8FB2",
      "\u6307",
      "\u5E7E",
      "\u4E5D",
      "\u5340",
      "\u5F37",
      "\u653E",
      "\u6C7A",
      "\u897F",
      "\u88AB",
      "\u5E79",
      "\u505A",
      "\u5FC5",
      "\u6230",
      "\u5148",
      "\u56DE",
      "\u5247",
      "\u4EFB",
      "\u53D6",
      "\u64DA",
      "\u8655",
      "\u968A",
      "\u5357",
      "\u7D66",
      "\u8272",
      "\u5149",
      "\u9580",
      "\u5373",
      "\u4FDD",
      "\u6CBB",
      "\u5317",
      "\u9020",
      "\u767E",
      "\u898F",
      "\u71B1",
      "\u9818",
      "\u4E03",
      "\u6D77",
      "\u53E3",
      "\u6771",
      "\u5C0E",
      "\u5668",
      "\u58D3",
      "\u5FD7",
      "\u4E16",
      "\u91D1",
      "\u589E",
      "\u722D",
      "\u6FDF",
      "\u968E",
      "\u6CB9",
      "\u601D",
      "\u8853",
      "\u6975",
      "\u4EA4",
      "\u53D7",
      "\u806F",
      "\u4EC0",
      "\u8A8D",
      "\u516D",
      "\u5171",
      "\u6B0A",
      "\u6536",
      "\u8B49",
      "\u6539",
      "\u6E05",
      "\u7F8E",
      "\u518D",
      "\u63A1",
      "\u8F49",
      "\u66F4",
      "\u55AE",
      "\u98A8",
      "\u5207",
      "\u6253",
      "\u767D",
      "\u6559",
      "\u901F",
      "\u82B1",
      "\u5E36",
      "\u5B89",
      "\u5834",
      "\u8EAB",
      "\u8ECA",
      "\u4F8B",
      "\u771F",
      "\u52D9",
      "\u5177",
      "\u842C",
      "\u6BCF",
      "\u76EE",
      "\u81F3",
      "\u9054",
      "\u8D70",
      "\u7A4D",
      "\u793A",
      "\u8B70",
      "\u8072",
      "\u5831",
      "\u9B25",
      "\u5B8C",
      "\u985E",
      "\u516B",
      "\u96E2",
      "\u83EF",
      "\u540D",
      "\u78BA",
      "\u624D",
      "\u79D1",
      "\u5F35",
      "\u4FE1",
      "\u99AC",
      "\u7BC0",
      "\u8A71",
      "\u7C73",
      "\u6574",
      "\u7A7A",
      "\u5143",
      "\u6CC1",
      "\u4ECA",
      "\u96C6",
      "\u6EAB",
      "\u50B3",
      "\u571F",
      "\u8A31",
      "\u6B65",
      "\u7FA4",
      "\u5EE3",
      "\u77F3",
      "\u8A18",
      "\u9700",
      "\u6BB5",
      "\u7814",
      "\u754C",
      "\u62C9",
      "\u6797",
      "\u5F8B",
      "\u53EB",
      "\u4E14",
      "\u7A76",
      "\u89C0",
      "\u8D8A",
      "\u7E54",
      "\u88DD",
      "\u5F71",
      "\u7B97",
      "\u4F4E",
      "\u6301",
      "\u97F3",
      "\u773E",
      "\u66F8",
      "\u5E03",
      "\u590D",
      "\u5BB9",
      "\u5152",
      "\u9808",
      "\u969B",
      "\u5546",
      "\u975E",
      "\u9A57",
      "\u9023",
      "\u65B7",
      "\u6DF1",
      "\u96E3",
      "\u8FD1",
      "\u7926",
      "\u5343",
      "\u9031",
      "\u59D4",
      "\u7D20",
      "\u6280",
      "\u5099",
      "\u534A",
      "\u8FA6",
      "\u9752",
      "\u7701",
      "\u5217",
      "\u7FD2",
      "\u97FF",
      "\u7D04",
      "\u652F",
      "\u822C",
      "\u53F2",
      "\u611F",
      "\u52DE",
      "\u4FBF",
      "\u5718",
      "\u5F80",
      "\u9178",
      "\u6B77",
      "\u5E02",
      "\u514B",
      "\u4F55",
      "\u9664",
      "\u6D88",
      "\u69CB",
      "\u5E9C",
      "\u7A31",
      "\u592A",
      "\u6E96",
      "\u7CBE",
      "\u503C",
      "\u865F",
      "\u7387",
      "\u65CF",
      "\u7DAD",
      "\u5283",
      "\u9078",
      "\u6A19",
      "\u5BEB",
      "\u5B58",
      "\u5019",
      "\u6BDB",
      "\u89AA",
      "\u5FEB",
      "\u6548",
      "\u65AF",
      "\u9662",
      "\u67E5",
      "\u6C5F",
      "\u578B",
      "\u773C",
      "\u738B",
      "\u6309",
      "\u683C",
      "\u990A",
      "\u6613",
      "\u7F6E",
      "\u6D3E",
      "\u5C64",
      "\u7247",
      "\u59CB",
      "\u537B",
      "\u5C08",
      "\u72C0",
      "\u80B2",
      "\u5EE0",
      "\u4EAC",
      "\u8B58",
      "\u9069",
      "\u5C6C",
      "\u5713",
      "\u5305",
      "\u706B",
      "\u4F4F",
      "\u8ABF",
      "\u6EFF",
      "\u7E23",
      "\u5C40",
      "\u7167",
      "\u53C3",
      "\u7D05",
      "\u7D30",
      "\u5F15",
      "\u807D",
      "\u8A72",
      "\u9435",
      "\u50F9",
      "\u56B4",
      "\u9996",
      "\u5E95",
      "\u6DB2",
      "\u5B98",
      "\u5FB7",
      "\u96A8",
      "\u75C5",
      "\u8607",
      "\u5931",
      "\u723E",
      "\u6B7B",
      "\u8B1B",
      "\u914D",
      "\u5973",
      "\u9EC3",
      "\u63A8",
      "\u986F",
      "\u8AC7",
      "\u7F6A",
      "\u795E",
      "\u85DD",
      "\u5462",
      "\u5E2D",
      "\u542B",
      "\u4F01",
      "\u671B",
      "\u5BC6",
      "\u6279",
      "\u71DF",
      "\u9805",
      "\u9632",
      "\u8209",
      "\u7403",
      "\u82F1",
      "\u6C27",
      "\u52E2",
      "\u544A",
      "\u674E",
      "\u53F0",
      "\u843D",
      "\u6728",
      "\u5E6B",
      "\u8F2A",
      "\u7834",
      "\u4E9E",
      "\u5E2B",
      "\u570D",
      "\u6CE8",
      "\u9060",
      "\u5B57",
      "\u6750",
      "\u6392",
      "\u4F9B",
      "\u6CB3",
      "\u614B",
      "\u5C01",
      "\u53E6",
      "\u65BD",
      "\u6E1B",
      "\u6A39",
      "\u6EB6",
      "\u600E",
      "\u6B62",
      "\u6848",
      "\u8A00",
      "\u58EB",
      "\u5747",
      "\u6B66",
      "\u56FA",
      "\u8449",
      "\u9B5A",
      "\u6CE2",
      "\u8996",
      "\u50C5",
      "\u8CBB",
      "\u7DCA",
      "\u611B",
      "\u5DE6",
      "\u7AE0",
      "\u65E9",
      "\u671D",
      "\u5BB3",
      "\u7E8C",
      "\u8F15",
      "\u670D",
      "\u8A66",
      "\u98DF",
      "\u5145",
      "\u5175",
      "\u6E90",
      "\u5224",
      "\u8B77",
      "\u53F8",
      "\u8DB3",
      "\u67D0",
      "\u7DF4",
      "\u5DEE",
      "\u81F4",
      "\u677F",
      "\u7530",
      "\u964D",
      "\u9ED1",
      "\u72AF",
      "\u8CA0",
      "\u64CA",
      "\u8303",
      "\u7E7C",
      "\u8208",
      "\u4F3C",
      "\u9918",
      "\u5805",
      "\u66F2",
      "\u8F38",
      "\u4FEE",
      "\u6545",
      "\u57CE",
      "\u592B",
      "\u5920",
      "\u9001",
      "\u7B46",
      "\u8239",
      "\u4F54",
      "\u53F3",
      "\u8CA1",
      "\u5403",
      "\u5BCC",
      "\u6625",
      "\u8077",
      "\u89BA",
      "\u6F22",
      "\u756B",
      "\u529F",
      "\u5DF4",
      "\u8DDF",
      "\u96D6",
      "\u96DC",
      "\u98DB",
      "\u6AA2",
      "\u5438",
      "\u52A9",
      "\u6607",
      "\u967D",
      "\u4E92",
      "\u521D",
      "\u5275",
      "\u6297",
      "\u8003",
      "\u6295",
      "\u58DE",
      "\u7B56",
      "\u53E4",
      "\u5F91",
      "\u63DB",
      "\u672A",
      "\u8DD1",
      "\u7559",
      "\u92FC",
      "\u66FE",
      "\u7AEF",
      "\u8CAC",
      "\u7AD9",
      "\u7C21",
      "\u8FF0",
      "\u9322",
      "\u526F",
      "\u76E1",
      "\u5E1D",
      "\u5C04",
      "\u8349",
      "\u885D",
      "\u627F",
      "\u7368",
      "\u4EE4",
      "\u9650",
      "\u963F",
      "\u5BA3",
      "\u74B0",
      "\u96D9",
      "\u8ACB",
      "\u8D85",
      "\u5FAE",
      "\u8B93",
      "\u63A7",
      "\u5DDE",
      "\u826F",
      "\u8EF8",
      "\u627E",
      "\u5426",
      "\u7D00",
      "\u76CA",
      "\u4F9D",
      "\u512A",
      "\u9802",
      "\u790E",
      "\u8F09",
      "\u5012",
      "\u623F",
      "\u7A81",
      "\u5750",
      "\u7C89",
      "\u6575",
      "\u7565",
      "\u5BA2",
      "\u8881",
      "\u51B7",
      "\u52DD",
      "\u7D55",
      "\u6790",
      "\u584A",
      "\u5291",
      "\u6E2C",
      "\u7D72",
      "\u5354",
      "\u8A34",
      "\u5FF5",
      "\u9673",
      "\u4ECD",
      "\u7F85",
      "\u9E7D",
      "\u53CB",
      "\u6D0B",
      "\u932F",
      "\u82E6",
      "\u591C",
      "\u5211",
      "\u79FB",
      "\u983B",
      "\u9010",
      "\u9760",
      "\u6DF7",
      "\u6BCD",
      "\u77ED",
      "\u76AE",
      "\u7D42",
      "\u805A",
      "\u6C7D",
      "\u6751",
      "\u96F2",
      "\u54EA",
      "\u65E2",
      "\u8DDD",
      "\u885B",
      "\u505C",
      "\u70C8",
      "\u592E",
      "\u5BDF",
      "\u71D2",
      "\u8FC5",
      "\u5883",
      "\u82E5",
      "\u5370",
      "\u6D32",
      "\u523B",
      "\u62EC",
      "\u6FC0",
      "\u5B54",
      "\u641E",
      "\u751A",
      "\u5BA4",
      "\u5F85",
      "\u6838",
      "\u6821",
      "\u6563",
      "\u4FB5",
      "\u5427",
      "\u7532",
      "\u904A",
      "\u4E45",
      "\u83DC",
      "\u5473",
      "\u820A",
      "\u6A21",
      "\u6E56",
      "\u8CA8",
      "\u640D",
      "\u9810",
      "\u963B",
      "\u6BEB",
      "\u666E",
      "\u7A69",
      "\u4E59",
      "\u5ABD",
      "\u690D",
      "\u606F",
      "\u64F4",
      "\u9280",
      "\u8A9E",
      "\u63EE",
      "\u9152",
      "\u5B88",
      "\u62FF",
      "\u5E8F",
      "\u7D19",
      "\u91AB",
      "\u7F3A",
      "\u96E8",
      "\u55CE",
      "\u91DD",
      "\u5289",
      "\u554A",
      "\u6025",
      "\u5531",
      "\u8AA4",
      "\u8A13",
      "\u9858",
      "\u5BE9",
      "\u9644",
      "\u7372",
      "\u8336",
      "\u9BAE",
      "\u7CE7",
      "\u65A4",
      "\u5B69",
      "\u812B",
      "\u786B",
      "\u80A5",
      "\u5584",
      "\u9F8D",
      "\u6F14",
      "\u7236",
      "\u6F38",
      "\u8840",
      "\u6B61",
      "\u68B0",
      "\u638C",
      "\u6B4C",
      "\u6C99",
      "\u525B",
      "\u653B",
      "\u8B02",
      "\u76FE",
      "\u8A0E",
      "\u665A",
      "\u7C92",
      "\u4E82",
      "\u71C3",
      "\u77DB",
      "\u4E4E",
      "\u6BBA",
      "\u85E5",
      "\u5BE7",
      "\u9B6F",
      "\u8CB4",
      "\u9418",
      "\u7164",
      "\u8B80",
      "\u73ED",
      "\u4F2F",
      "\u9999",
      "\u4ECB",
      "\u8FEB",
      "\u53E5",
      "\u8C50",
      "\u57F9",
      "\u63E1",
      "\u862D",
      "\u64D4",
      "\u5F26",
      "\u86CB",
      "\u6C89",
      "\u5047",
      "\u7A7F",
      "\u57F7",
      "\u7B54",
      "\u6A02",
      "\u8AB0",
      "\u9806",
      "\u7159",
      "\u7E2E",
      "\u5FB5",
      "\u81C9",
      "\u559C",
      "\u677E",
      "\u8173",
      "\u56F0",
      "\u7570",
      "\u514D",
      "\u80CC",
      "\u661F",
      "\u798F",
      "\u8CB7",
      "\u67D3",
      "\u4E95",
      "\u6982",
      "\u6162",
      "\u6015",
      "\u78C1",
      "\u500D",
      "\u7956",
      "\u7687",
      "\u4FC3",
      "\u975C",
      "\u88DC",
      "\u8A55",
      "\u7FFB",
      "\u8089",
      "\u8E10",
      "\u5C3C",
      "\u8863",
      "\u5BEC",
      "\u63DA",
      "\u68C9",
      "\u5E0C",
      "\u50B7",
      "\u64CD",
      "\u5782",
      "\u79CB",
      "\u5B9C",
      "\u6C2B",
      "\u5957",
      "\u7763",
      "\u632F",
      "\u67B6",
      "\u4EAE",
      "\u672B",
      "\u61B2",
      "\u6176",
      "\u7DE8",
      "\u725B",
      "\u89F8",
      "\u6620",
      "\u96F7",
      "\u92B7",
      "\u8A69",
      "\u5EA7",
      "\u5C45",
      "\u6293",
      "\u88C2",
      "\u80DE",
      "\u547C",
      "\u5A18",
      "\u666F",
      "\u5A01",
      "\u7DA0",
      "\u6676",
      "\u539A",
      "\u76DF",
      "\u8861",
      "\u96DE",
      "\u5B6B",
      "\u5EF6",
      "\u5371",
      "\u81A0",
      "\u5C4B",
      "\u9109",
      "\u81E8",
      "\u9678",
      "\u9867",
      "\u6389",
      "\u5440",
      "\u71C8",
      "\u6B72",
      "\u63AA",
      "\u675F",
      "\u8010",
      "\u5287",
      "\u7389",
      "\u8D99",
      "\u8DF3",
      "\u54E5",
      "\u5B63",
      "\u8AB2",
      "\u51F1",
      "\u80E1",
      "\u984D",
      "\u6B3E",
      "\u7D39",
      "\u5377",
      "\u9F4A",
      "\u5049",
      "\u84B8",
      "\u6B96",
      "\u6C38",
      "\u5B97",
      "\u82D7",
      "\u5DDD",
      "\u7210",
      "\u5CA9",
      "\u5F31",
      "\u96F6",
      "\u694A",
      "\u594F",
      "\u6CBF",
      "\u9732",
      "\u687F",
      "\u63A2",
      "\u6ED1",
      "\u93AE",
      "\u98EF",
      "\u6FC3",
      "\u822A",
      "\u61F7",
      "\u8D95",
      "\u5EAB",
      "\u596A",
      "\u4F0A",
      "\u9748",
      "\u7A05",
      "\u9014",
      "\u6EC5",
      "\u8CFD",
      "\u6B78",
      "\u53EC",
      "\u9F13",
      "\u64AD",
      "\u76E4",
      "\u88C1",
      "\u96AA",
      "\u5EB7",
      "\u552F",
      "\u9304",
      "\u83CC",
      "\u7D14",
      "\u501F",
      "\u7CD6",
      "\u84CB",
      "\u6A6B",
      "\u7B26",
      "\u79C1",
      "\u52AA",
      "\u5802",
      "\u57DF",
      "\u69CD",
      "\u6F64",
      "\u5E45",
      "\u54C8",
      "\u7ADF",
      "\u719F",
      "\u87F2",
      "\u6FA4",
      "\u8166",
      "\u58E4",
      "\u78B3",
      "\u6B50",
      "\u904D",
      "\u5074",
      "\u5BE8",
      "\u6562",
      "\u5FB9",
      "\u616E",
      "\u659C",
      "\u8584",
      "\u5EAD",
      "\u7D0D",
      "\u5F48",
      "\u98FC",
      "\u4F38",
      "\u6298",
      "\u9EA5",
      "\u6FD5",
      "\u6697",
      "\u8377",
      "\u74E6",
      "\u585E",
      "\u5E8A",
      "\u7BC9",
      "\u60E1",
      "\u6236",
      "\u8A2A",
      "\u5854",
      "\u5947",
      "\u900F",
      "\u6881",
      "\u5200",
      "\u65CB",
      "\u8DE1",
      "\u5361",
      "\u6C2F",
      "\u9047",
      "\u4EFD",
      "\u6BD2",
      "\u6CE5",
      "\u9000",
      "\u6D17",
      "\u64FA",
      "\u7070",
      "\u5F69",
      "\u8CE3",
      "\u8017",
      "\u590F",
      "\u64C7",
      "\u5FD9",
      "\u9285",
      "\u737B",
      "\u786C",
      "\u4E88",
      "\u7E41",
      "\u5708",
      "\u96EA",
      "\u51FD",
      "\u4EA6",
      "\u62BD",
      "\u7BC7",
      "\u9663",
      "\u9670",
      "\u4E01",
      "\u5C3A",
      "\u8FFD",
      "\u5806",
      "\u96C4",
      "\u8FCE",
      "\u6CDB",
      "\u7238",
      "\u6A13",
      "\u907F",
      "\u8B00",
      "\u5678",
      "\u91CE",
      "\u8C6C",
      "\u65D7",
      "\u7D2F",
      "\u504F",
      "\u5178",
      "\u9928",
      "\u7D22",
      "\u79E6",
      "\u8102",
      "\u6F6E",
      "\u723A",
      "\u8C46",
      "\u5FFD",
      "\u6258",
      "\u9A5A",
      "\u5851",
      "\u907A",
      "\u6108",
      "\u6731",
      "\u66FF",
      "\u7E96",
      "\u7C97",
      "\u50BE",
      "\u5C1A",
      "\u75DB",
      "\u695A",
      "\u8B1D",
      "\u596E",
      "\u8CFC",
      "\u78E8",
      "\u541B",
      "\u6C60",
      "\u65C1",
      "\u788E",
      "\u9AA8",
      "\u76E3",
      "\u6355",
      "\u5F1F",
      "\u66B4",
      "\u5272",
      "\u8CAB",
      "\u6B8A",
      "\u91CB",
      "\u8A5E",
      "\u4EA1",
      "\u58C1",
      "\u9813",
      "\u5BF6",
      "\u5348",
      "\u5875",
      "\u805E",
      "\u63ED",
      "\u70AE",
      "\u6B98",
      "\u51AC",
      "\u6A4B",
      "\u5A66",
      "\u8B66",
      "\u7D9C",
      "\u62DB",
      "\u5433",
      "\u4ED8",
      "\u6D6E",
      "\u906D",
      "\u5F90",
      "\u60A8",
      "\u6416",
      "\u8C37",
      "\u8D0A",
      "\u7BB1",
      "\u9694",
      "\u8A02",
      "\u7537",
      "\u5439",
      "\u5712",
      "\u7D1B",
      "\u5510",
      "\u6557",
      "\u5B8B",
      "\u73BB",
      "\u5DE8",
      "\u8015",
      "\u5766",
      "\u69AE",
      "\u9589",
      "\u7063",
      "\u9375",
      "\u51E1",
      "\u99D0",
      "\u934B",
      "\u6551",
      "\u6069",
      "\u525D",
      "\u51DD",
      "\u9E7C",
      "\u9F52",
      "\u622A",
      "\u7149",
      "\u9EBB",
      "\u7D21",
      "\u7981",
      "\u5EE2",
      "\u76DB",
      "\u7248",
      "\u7DE9",
      "\u6DE8",
      "\u775B",
      "\u660C",
      "\u5A5A",
      "\u6D89",
      "\u7B52",
      "\u5634",
      "\u63D2",
      "\u5CB8",
      "\u6717",
      "\u838A",
      "\u8857",
      "\u85CF",
      "\u59D1",
      "\u8CBF",
      "\u8150",
      "\u5974",
      "\u5566",
      "\u6163",
      "\u4E58",
      "\u5925",
      "\u6062",
      "\u52FB",
      "\u7D17",
      "\u624E",
      "\u8FAF",
      "\u8033",
      "\u5F6A",
      "\u81E3",
      "\u5104",
      "\u7483",
      "\u62B5",
      "\u8108",
      "\u79C0",
      "\u85A9",
      "\u4FC4",
      "\u7DB2",
      "\u821E",
      "\u5E97",
      "\u5674",
      "\u7E31",
      "\u5BF8",
      "\u6C57",
      "\u639B",
      "\u6D2A",
      "\u8CC0",
      "\u9583",
      "\u67EC",
      "\u7206",
      "\u70EF",
      "\u6D25",
      "\u7A3B",
      "\u7246",
      "\u8EDF",
      "\u52C7",
      "\u50CF",
      "\u6EFE",
      "\u5398",
      "\u8499",
      "\u82B3",
      "\u80AF",
      "\u5761",
      "\u67F1",
      "\u76EA",
      "\u817F",
      "\u5100",
      "\u65C5",
      "\u5C3E",
      "\u8ECB",
      "\u51B0",
      "\u8CA2",
      "\u767B",
      "\u9ECE",
      "\u524A",
      "\u947D",
      "\u52D2",
      "\u9003",
      "\u969C",
      "\u6C28",
      "\u90ED",
      "\u5CF0",
      "\u5E63",
      "\u6E2F",
      "\u4F0F",
      "\u8ECC",
      "\u755D",
      "\u7562",
      "\u64E6",
      "\u83AB",
      "\u523A",
      "\u6D6A",
      "\u79D8",
      "\u63F4",
      "\u682A",
      "\u5065",
      "\u552E",
      "\u80A1",
      "\u5CF6",
      "\u7518",
      "\u6CE1",
      "\u7761",
      "\u7AE5",
      "\u9444",
      "\u6E6F",
      "\u95A5",
      "\u4F11",
      "\u532F",
      "\u820D",
      "\u7267",
      "\u7E5E",
      "\u70B8",
      "\u54F2",
      "\u78F7",
      "\u7E3E",
      "\u670B",
      "\u6DE1",
      "\u5C16",
      "\u555F",
      "\u9677",
      "\u67F4",
      "\u5448",
      "\u5F92",
      "\u984F",
      "\u6DDA",
      "\u7A0D",
      "\u5FD8",
      "\u6CF5",
      "\u85CD",
      "\u62D6",
      "\u6D1E",
      "\u6388",
      "\u93E1",
      "\u8F9B",
      "\u58EF",
      "\u92D2",
      "\u8CA7",
      "\u865B",
      "\u5F4E",
      "\u6469",
      "\u6CF0",
      "\u5E7C",
      "\u5EF7",
      "\u5C0A",
      "\u7A97",
      "\u7DB1",
      "\u5F04",
      "\u96B8",
      "\u7591",
      "\u6C0F",
      "\u5BAE",
      "\u59D0",
      "\u9707",
      "\u745E",
      "\u602A",
      "\u5C24",
      "\u7434",
      "\u5FAA",
      "\u63CF",
      "\u819C",
      "\u9055",
      "\u593E",
      "\u8170",
      "\u7DE3",
      "\u73E0",
      "\u7AAE",
      "\u68EE",
      "\u679D",
      "\u7AF9",
      "\u6E9D",
      "\u50AC",
      "\u7E69",
      "\u61B6",
      "\u90A6",
      "\u5269",
      "\u5E78",
      "\u6F3F",
      "\u6B04",
      "\u64C1",
      "\u7259",
      "\u8CAF",
      "\u79AE",
      "\u6FFE",
      "\u9209",
      "\u7D0B",
      "\u7F77",
      "\u62CD",
      "\u54B1",
      "\u558A",
      "\u8896",
      "\u57C3",
      "\u52E4",
      "\u7F70",
      "\u7126",
      "\u6F5B",
      "\u4F0D",
      "\u58A8",
      "\u6B32",
      "\u7E2B",
      "\u59D3",
      "\u520A",
      "\u98FD",
      "\u4EFF",
      "\u734E",
      "\u92C1",
      "\u9B3C",
      "\u9E97",
      "\u8DE8",
      "\u9ED8",
      "\u6316",
      "\u93C8",
      "\u6383",
      "\u559D",
      "\u888B",
      "\u70AD",
      "\u6C61",
      "\u5E55",
      "\u8AF8",
      "\u5F27",
      "\u52F5",
      "\u6885",
      "\u5976",
      "\u6F54",
      "\u707D",
      "\u821F",
      "\u9451",
      "\u82EF",
      "\u8A1F",
      "\u62B1",
      "\u6BC0",
      "\u61C2",
      "\u5BD2",
      "\u667A",
      "\u57D4",
      "\u5BC4",
      "\u5C46",
      "\u8E8D",
      "\u6E21",
      "\u6311",
      "\u4E39",
      "\u8271",
      "\u8C9D",
      "\u78B0",
      "\u62D4",
      "\u7239",
      "\u6234",
      "\u78BC",
      "\u5922",
      "\u82BD",
      "\u7194",
      "\u8D64",
      "\u6F01",
      "\u54ED",
      "\u656C",
      "\u9846",
      "\u5954",
      "\u925B",
      "\u4EF2",
      "\u864E",
      "\u7A00",
      "\u59B9",
      "\u4E4F",
      "\u73CD",
      "\u7533",
      "\u684C",
      "\u9075",
      "\u5141",
      "\u9686",
      "\u87BA",
      "\u5009",
      "\u9B4F",
      "\u92B3",
      "\u66C9",
      "\u6C2E",
      "\u517C",
      "\u96B1",
      "\u7919",
      "\u8D6B",
      "\u64A5",
      "\u5FE0",
      "\u8085",
      "\u7F38",
      "\u727D",
      "\u6436",
      "\u535A",
      "\u5DE7",
      "\u6BBC",
      "\u5144",
      "\u675C",
      "\u8A0A",
      "\u8AA0",
      "\u78A7",
      "\u7965",
      "\u67EF",
      "\u9801",
      "\u5DE1",
      "\u77E9",
      "\u60B2",
      "\u704C",
      "\u9F61",
      "\u502B",
      "\u7968",
      "\u5C0B",
      "\u6842",
      "\u92EA",
      "\u8056",
      "\u6050",
      "\u6070",
      "\u912D",
      "\u8DA3",
      "\u62AC",
      "\u8352",
      "\u9A30",
      "\u8CBC",
      "\u67D4",
      "\u6EF4",
      "\u731B",
      "\u95CA",
      "\u8F1B",
      "\u59BB",
      "\u586B",
      "\u64A4",
      "\u5132",
      "\u7C3D",
      "\u9B27",
      "\u64FE",
      "\u7D2B",
      "\u7802",
      "\u905E",
      "\u6232",
      "\u540A",
      "\u9676",
      "\u4F10",
      "\u9935",
      "\u7642",
      "\u74F6",
      "\u5A46",
      "\u64AB",
      "\u81C2",
      "\u6478",
      "\u5FCD",
      "\u8766",
      "\u881F",
      "\u9130",
      "\u80F8",
      "\u978F",
      "\u64E0",
      "\u5076",
      "\u68C4",
      "\u69FD",
      "\u52C1",
      "\u4E73",
      "\u9127",
      "\u5409",
      "\u4EC1",
      "\u721B",
      "\u78DA",
      "\u79DF",
      "\u70CF",
      "\u8266",
      "\u4F34",
      "\u74DC",
      "\u6DFA",
      "\u4E19",
      "\u66AB",
      "\u71E5",
      "\u6A61",
      "\u67F3",
      "\u8FF7",
      "\u6696",
      "\u724C",
      "\u79E7",
      "\u81BD",
      "\u8A73",
      "\u7C27",
      "\u8E0F",
      "\u74F7",
      "\u8B5C",
      "\u5446",
      "\u8CD3",
      "\u7CCA",
      "\u6D1B",
      "\u8F1D",
      "\u61A4",
      "\u7AF6",
      "\u9699",
      "\u6012",
      "\u7C98",
      "\u4E43",
      "\u7DD2",
      "\u80A9",
      "\u7C4D",
      "\u654F",
      "\u5857",
      "\u7199",
      "\u7686",
      "\u5075",
      "\u61F8",
      "\u6398",
      "\u4EAB",
      "\u7CFE",
      "\u9192",
      "\u72C2",
      "\u9396",
      "\u6DC0",
      "\u6068",
      "\u7272",
      "\u9738",
      "\u722C",
      "\u8CDE",
      "\u9006",
      "\u73A9",
      "\u9675",
      "\u795D",
      "\u79D2",
      "\u6D59",
      "\u8C8C",
      "\u5F79",
      "\u5F7C",
      "\u6089",
      "\u9D28",
      "\u8DA8",
      "\u9CF3",
      "\u6668",
      "\u755C",
      "\u8F29",
      "\u79E9",
      "\u5375",
      "\u7F72",
      "\u68AF",
      "\u708E",
      "\u7058",
      "\u68CB",
      "\u9A45",
      "\u7BE9",
      "\u5CFD",
      "\u5192",
      "\u5565",
      "\u58FD",
      "\u8B6F",
      "\u6D78",
      "\u6CC9",
      "\u5E3D",
      "\u9072",
      "\u77FD",
      "\u7586",
      "\u8CB8",
      "\u6F0F",
      "\u7A3F",
      "\u51A0",
      "\u5AE9",
      "\u8105",
      "\u82AF",
      "\u7262",
      "\u53DB",
      "\u8755",
      "\u5967",
      "\u9CF4",
      "\u5DBA",
      "\u7F8A",
      "\u6191",
      "\u4E32",
      "\u5858",
      "\u7E6A",
      "\u9175",
      "\u878D",
      "\u76C6",
      "\u932B",
      "\u5EDF",
      "\u7C4C",
      "\u51CD",
      "\u8F14",
      "\u651D",
      "\u8972",
      "\u7B4B",
      "\u62D2",
      "\u50DA",
      "\u65F1",
      "\u9240",
      "\u9CE5",
      "\u6F06",
      "\u6C88",
      "\u7709",
      "\u758F",
      "\u6DFB",
      "\u68D2",
      "\u7A57",
      "\u785D",
      "\u97D3",
      "\u903C",
      "\u626D",
      "\u50D1",
      "\u6DBC",
      "\u633A",
      "\u7897",
      "\u683D",
      "\u7092",
      "\u676F",
      "\u60A3",
      "\u993E",
      "\u52F8",
      "\u8C6A",
      "\u907C",
      "\u52C3",
      "\u9D3B",
      "\u65E6",
      "\u540F",
      "\u62DC",
      "\u72D7",
      "\u57CB",
      "\u8F25",
      "\u63A9",
      "\u98F2",
      "\u642C",
      "\u7F75",
      "\u8FAD",
      "\u52FE",
      "\u6263",
      "\u4F30",
      "\u8523",
      "\u7D68",
      "\u9727",
      "\u4E08",
      "\u6735",
      "\u59C6",
      "\u64EC",
      "\u5B87",
      "\u8F2F",
      "\u965D",
      "\u96D5",
      "\u511F",
      "\u84C4",
      "\u5D07",
      "\u526A",
      "\u5021",
      "\u5EF3",
      "\u54AC",
      "\u99DB",
      "\u85AF",
      "\u5237",
      "\u65A5",
      "\u756A",
      "\u8CE6",
      "\u5949",
      "\u4F5B",
      "\u6F86",
      "\u6F2B",
      "\u66FC",
      "\u6247",
      "\u9223",
      "\u6843",
      "\u6276",
      "\u4ED4",
      "\u8FD4",
      "\u4FD7",
      "\u8667",
      "\u8154",
      "\u978B",
      "\u68F1",
      "\u8986",
      "\u6846",
      "\u6084",
      "\u53D4",
      "\u649E",
      "\u9A19",
      "\u52D8",
      "\u65FA",
      "\u6CB8",
      "\u5B64",
      "\u5410",
      "\u5B5F",
      "\u6E20",
      "\u5C48",
      "\u75BE",
      "\u5999",
      "\u60DC",
      "\u4EF0",
      "\u72E0",
      "\u8139",
      "\u8AE7",
      "\u62CB",
      "\u9EF4",
      "\u6851",
      "\u5D17",
      "\u561B",
      "\u8870",
      "\u76DC",
      "\u6EF2",
      "\u81DF",
      "\u8CF4",
      "\u6E67",
      "\u751C",
      "\u66F9",
      "\u95B1",
      "\u808C",
      "\u54E9",
      "\u53B2",
      "\u70F4",
      "\u7DEF",
      "\u6BC5",
      "\u6628",
      "\u507D",
      "\u75C7",
      "\u716E",
      "\u5606",
      "\u91D8",
      "\u642D",
      "\u8396",
      "\u7C60",
      "\u9177",
      "\u5077",
      "\u5F13",
      "\u9310",
      "\u6046",
      "\u5091",
      "\u5751",
      "\u9F3B",
      "\u7FFC",
      "\u7DB8",
      "\u6558",
      "\u7344",
      "\u902E",
      "\u7F50",
      "\u7D61",
      "\u68DA",
      "\u6291",
      "\u81A8",
      "\u852C",
      "\u5BFA",
      "\u9A5F",
      "\u7A46",
      "\u51B6",
      "\u67AF",
      "\u518A",
      "\u5C4D",
      "\u51F8",
      "\u7D33",
      "\u576F",
      "\u72A7",
      "\u7130",
      "\u8F5F",
      "\u6B23",
      "\u6649",
      "\u7626",
      "\u79A6",
      "\u9320",
      "\u9326",
      "\u55AA",
      "\u65EC",
      "\u935B",
      "\u58DF",
      "\u641C",
      "\u64B2",
      "\u9080",
      "\u4EAD",
      "\u916F",
      "\u9081",
      "\u8212",
      "\u8106",
      "\u9176",
      "\u9592",
      "\u6182",
      "\u915A",
      "\u9811",
      "\u7FBD",
      "\u6F32",
      "\u5378",
      "\u4ED7",
      "\u966A",
      "\u95E2",
      "\u61F2",
      "\u676D",
      "\u59DA",
      "\u809A",
      "\u6349",
      "\u98C4",
      "\u6F02",
      "\u6606",
      "\u6B3A",
      "\u543E",
      "\u90CE",
      "\u70F7",
      "\u6C41",
      "\u5475",
      "\u98FE",
      "\u856D",
      "\u96C5",
      "\u90F5",
      "\u9077",
      "\u71D5",
      "\u6492",
      "\u59FB",
      "\u8D74",
      "\u5BB4",
      "\u7169",
      "\u50B5",
      "\u5E33",
      "\u6591",
      "\u9234",
      "\u65E8",
      "\u9187",
      "\u8463",
      "\u9905",
      "\u96DB",
      "\u59FF",
      "\u62CC",
      "\u5085",
      "\u8179",
      "\u59A5",
      "\u63C9",
      "\u8CE2",
      "\u62C6",
      "\u6B6A",
      "\u8461",
      "\u80FA",
      "\u4E1F",
      "\u6D69",
      "\u5FBD",
      "\u6602",
      "\u588A",
      "\u64CB",
      "\u89BD",
      "\u8CAA",
      "\u6170",
      "\u7E73",
      "\u6C6A",
      "\u614C",
      "\u99AE",
      "\u8AFE",
      "\u59DC",
      "\u8ABC",
      "\u5147",
      "\u52A3",
      "\u8AA3",
      "\u8000",
      "\u660F",
      "\u8EBA",
      "\u76C8",
      "\u9A0E",
      "\u55AC",
      "\u6EAA",
      "\u53E2",
      "\u76E7",
      "\u62B9",
      "\u60B6",
      "\u8AEE",
      "\u522E",
      "\u99D5",
      "\u7E9C",
      "\u609F",
      "\u6458",
      "\u927A",
      "\u64F2",
      "\u9817",
      "\u5E7B",
      "\u67C4",
      "\u60E0",
      "\u6158",
      "\u4F73",
      "\u4EC7",
      "\u81D8",
      "\u7AA9",
      "\u6ECC",
      "\u528D",
      "\u77A7",
      "\u5821",
      "\u6F51",
      "\u8525",
      "\u7F69",
      "\u970D",
      "\u6488",
      "\u80CE",
      "\u84BC",
      "\u6FF1",
      "\u5006",
      "\u6345",
      "\u6E58",
      "\u780D",
      "\u971E",
      "\u90B5",
      "\u8404",
      "\u760B",
      "\u6DEE",
      "\u9042",
      "\u718A",
      "\u7CDE",
      "\u70D8",
      "\u5BBF",
      "\u6A94",
      "\u6208",
      "\u99C1",
      "\u5AC2",
      "\u88D5",
      "\u5F99",
      "\u7BAD",
      "\u6350",
      "\u8178",
      "\u6490",
      "\u66EC",
      "\u8FA8",
      "\u6BBF",
      "\u84EE",
      "\u6524",
      "\u652A",
      "\u91AC",
      "\u5C4F",
      "\u75AB",
      "\u54C0",
      "\u8521",
      "\u5835",
      "\u6CAB",
      "\u76BA",
      "\u66A2",
      "\u758A",
      "\u95A3",
      "\u840A",
      "\u6572",
      "\u8F44",
      "\u9264",
      "\u75D5",
      "\u58E9",
      "\u5DF7",
      "\u9913",
      "\u798D",
      "\u4E18",
      "\u7384",
      "\u6E9C",
      "\u66F0",
      "\u908F",
      "\u5F6D",
      "\u5617",
      "\u537F",
      "\u59A8",
      "\u8247",
      "\u541E",
      "\u97CB",
      "\u6028",
      "\u77EE",
      "\u6B47"
    ];
  }
});

// node_modules/bip39/src/wordlists/korean.json
var require_korean = __commonJS({
  "node_modules/bip39/src/wordlists/korean.json"(exports, module) {
    module.exports = [
      "\u1100\u1161\u1100\u1167\u11A8",
      "\u1100\u1161\u1101\u1173\u11B7",
      "\u1100\u1161\u1102\u1161\u11AB",
      "\u1100\u1161\u1102\u1173\u11BC",
      "\u1100\u1161\u1103\u1173\u11A8",
      "\u1100\u1161\u1105\u1173\u110E\u1175\u11B7",
      "\u1100\u1161\u1106\u116E\u11B7",
      "\u1100\u1161\u1107\u1161\u11BC",
      "\u1100\u1161\u1109\u1161\u11BC",
      "\u1100\u1161\u1109\u1173\u11B7",
      "\u1100\u1161\u110B\u116E\u11AB\u1103\u1166",
      "\u1100\u1161\u110B\u1173\u11AF",
      "\u1100\u1161\u110B\u1175\u1103\u1173",
      "\u1100\u1161\u110B\u1175\u11B8",
      "\u1100\u1161\u110C\u1161\u11BC",
      "\u1100\u1161\u110C\u1165\u11BC",
      "\u1100\u1161\u110C\u1169\u11A8",
      "\u1100\u1161\u110C\u116E\u11A8",
      "\u1100\u1161\u11A8\u110B\u1169",
      "\u1100\u1161\u11A8\u110C\u1161",
      "\u1100\u1161\u11AB\u1100\u1167\u11A8",
      "\u1100\u1161\u11AB\u1107\u116E",
      "\u1100\u1161\u11AB\u1109\u1165\u11B8",
      "\u1100\u1161\u11AB\u110C\u1161\u11BC",
      "\u1100\u1161\u11AB\u110C\u1165\u11B8",
      "\u1100\u1161\u11AB\u1111\u1161\u11AB",
      "\u1100\u1161\u11AF\u1103\u1173\u11BC",
      "\u1100\u1161\u11AF\u1107\u1175",
      "\u1100\u1161\u11AF\u1109\u1162\u11A8",
      "\u1100\u1161\u11AF\u110C\u1173\u11BC",
      "\u1100\u1161\u11B7\u1100\u1161\u11A8",
      "\u1100\u1161\u11B7\u1100\u1175",
      "\u1100\u1161\u11B7\u1109\u1169",
      "\u1100\u1161\u11B7\u1109\u116E\u1109\u1165\u11BC",
      "\u1100\u1161\u11B7\u110C\u1161",
      "\u1100\u1161\u11B7\u110C\u1165\u11BC",
      "\u1100\u1161\u11B8\u110C\u1161\u1100\u1175",
      "\u1100\u1161\u11BC\u1102\u1161\u11B7",
      "\u1100\u1161\u11BC\u1103\u1161\u11BC",
      "\u1100\u1161\u11BC\u1103\u1169",
      "\u1100\u1161\u11BC\u1105\u1167\u11A8\u1112\u1175",
      "\u1100\u1161\u11BC\u1107\u1167\u11AB",
      "\u1100\u1161\u11BC\u1107\u116E\u11A8",
      "\u1100\u1161\u11BC\u1109\u1161",
      "\u1100\u1161\u11BC\u1109\u116E\u1105\u1163\u11BC",
      "\u1100\u1161\u11BC\u110B\u1161\u110C\u1175",
      "\u1100\u1161\u11BC\u110B\u116F\u11AB\u1103\u1169",
      "\u1100\u1161\u11BC\u110B\u1174",
      "\u1100\u1161\u11BC\u110C\u1166",
      "\u1100\u1161\u11BC\u110C\u1169",
      "\u1100\u1161\u11C0\u110B\u1175",
      "\u1100\u1162\u1100\u116E\u1105\u1175",
      "\u1100\u1162\u1102\u1161\u1105\u1175",
      "\u1100\u1162\u1107\u1161\u11BC",
      "\u1100\u1162\u1107\u1167\u11AF",
      "\u1100\u1162\u1109\u1165\u11AB",
      "\u1100\u1162\u1109\u1165\u11BC",
      "\u1100\u1162\u110B\u1175\u11AB",
      "\u1100\u1162\u11A8\u1100\u116A\u11AB\u110C\u1165\u11A8",
      "\u1100\u1165\u1109\u1175\u11AF",
      "\u1100\u1165\u110B\u1162\u11A8",
      "\u1100\u1165\u110B\u116E\u11AF",
      "\u1100\u1165\u110C\u1175\u11BA",
      "\u1100\u1165\u1111\u116E\u11B7",
      "\u1100\u1165\u11A8\u110C\u1165\u11BC",
      "\u1100\u1165\u11AB\u1100\u1161\u11BC",
      "\u1100\u1165\u11AB\u1106\u116E\u11AF",
      "\u1100\u1165\u11AB\u1109\u1165\u11AF",
      "\u1100\u1165\u11AB\u110C\u1169",
      "\u1100\u1165\u11AB\u110E\u116E\u11A8",
      "\u1100\u1165\u11AF\u110B\u1173\u11B7",
      "\u1100\u1165\u11B7\u1109\u1161",
      "\u1100\u1165\u11B7\u1110\u1169",
      "\u1100\u1166\u1109\u1175\u1111\u1161\u11AB",
      "\u1100\u1166\u110B\u1175\u11B7",
      "\u1100\u1167\u110B\u116E\u11AF",
      "\u1100\u1167\u11AB\u1112\u1162",
      "\u1100\u1167\u11AF\u1100\u116A",
      "\u1100\u1167\u11AF\u1100\u116E\u11A8",
      "\u1100\u1167\u11AF\u1105\u1169\u11AB",
      "\u1100\u1167\u11AF\u1109\u1165\u11A8",
      "\u1100\u1167\u11AF\u1109\u1173\u11BC",
      "\u1100\u1167\u11AF\u1109\u1175\u11B7",
      "\u1100\u1167\u11AF\u110C\u1165\u11BC",
      "\u1100\u1167\u11AF\u1112\u1169\u11AB",
      "\u1100\u1167\u11BC\u1100\u1168",
      "\u1100\u1167\u11BC\u1100\u1169",
      "\u1100\u1167\u11BC\u1100\u1175",
      "\u1100\u1167\u11BC\u1105\u1167\u11A8",
      "\u1100\u1167\u11BC\u1107\u1169\u11A8\u1100\u116E\u11BC",
      "\u1100\u1167\u11BC\u1107\u1175",
      "\u1100\u1167\u11BC\u1109\u1161\u11BC\u1103\u1169",
      "\u1100\u1167\u11BC\u110B\u1167\u11BC",
      "\u1100\u1167\u11BC\u110B\u116E",
      "\u1100\u1167\u11BC\u110C\u1162\u11BC",
      "\u1100\u1167\u11BC\u110C\u1166",
      "\u1100\u1167\u11BC\u110C\u116E",
      "\u1100\u1167\u11BC\u110E\u1161\u11AF",
      "\u1100\u1167\u11BC\u110E\u1175",
      "\u1100\u1167\u11BC\u1112\u1163\u11BC",
      "\u1100\u1167\u11BC\u1112\u1165\u11B7",
      "\u1100\u1168\u1100\u1169\u11A8",
      "\u1100\u1168\u1103\u1161\u11AB",
      "\u1100\u1168\u1105\u1161\u11AB",
      "\u1100\u1168\u1109\u1161\u11AB",
      "\u1100\u1168\u1109\u1169\u11A8",
      "\u1100\u1168\u110B\u1163\u11A8",
      "\u1100\u1168\u110C\u1165\u11AF",
      "\u1100\u1168\u110E\u1173\u11BC",
      "\u1100\u1168\u1112\u116C\u11A8",
      "\u1100\u1169\u1100\u1162\u11A8",
      "\u1100\u1169\u1100\u116E\u1105\u1167",
      "\u1100\u1169\u1100\u116E\u11BC",
      "\u1100\u1169\u1100\u1173\u11B8",
      "\u1100\u1169\u1103\u1173\u11BC\u1112\u1161\u11A8\u1109\u1162\u11BC",
      "\u1100\u1169\u1106\u116E\u1109\u1175\u11AB",
      "\u1100\u1169\u1106\u1175\u11AB",
      "\u1100\u1169\u110B\u1163\u11BC\u110B\u1175",
      "\u1100\u1169\u110C\u1161\u11BC",
      "\u1100\u1169\u110C\u1165\u11AB",
      "\u1100\u1169\u110C\u1175\u11B8",
      "\u1100\u1169\u110E\u116E\u11BA\u1100\u1161\u1105\u116E",
      "\u1100\u1169\u1110\u1169\u11BC",
      "\u1100\u1169\u1112\u1163\u11BC",
      "\u1100\u1169\u11A8\u1109\u1175\u11A8",
      "\u1100\u1169\u11AF\u1106\u1169\u11A8",
      "\u1100\u1169\u11AF\u110D\u1161\u1100\u1175",
      "\u1100\u1169\u11AF\u1111\u1173",
      "\u1100\u1169\u11BC\u1100\u1161\u11AB",
      "\u1100\u1169\u11BC\u1100\u1162",
      "\u1100\u1169\u11BC\u1100\u1167\u11A8",
      "\u1100\u1169\u11BC\u1100\u116E\u11AB",
      "\u1100\u1169\u11BC\u1100\u1173\u11B8",
      "\u1100\u1169\u11BC\u1100\u1175",
      "\u1100\u1169\u11BC\u1103\u1169\u11BC",
      "\u1100\u1169\u11BC\u1106\u116E\u110B\u116F\u11AB",
      "\u1100\u1169\u11BC\u1107\u116E",
      "\u1100\u1169\u11BC\u1109\u1161",
      "\u1100\u1169\u11BC\u1109\u1175\u11A8",
      "\u1100\u1169\u11BC\u110B\u1165\u11B8",
      "\u1100\u1169\u11BC\u110B\u1167\u11AB",
      "\u1100\u1169\u11BC\u110B\u116F\u11AB",
      "\u1100\u1169\u11BC\u110C\u1161\u11BC",
      "\u1100\u1169\u11BC\u110D\u1161",
      "\u1100\u1169\u11BC\u110E\u1162\u11A8",
      "\u1100\u1169\u11BC\u1110\u1169\u11BC",
      "\u1100\u1169\u11BC\u1111\u1169",
      "\u1100\u1169\u11BC\u1112\u1161\u11BC",
      "\u1100\u1169\u11BC\u1112\u1172\u110B\u1175\u11AF",
      "\u1100\u116A\u1106\u1169\u11A8",
      "\u1100\u116A\u110B\u1175\u11AF",
      "\u1100\u116A\u110C\u1161\u11BC",
      "\u1100\u116A\u110C\u1165\u11BC",
      "\u1100\u116A\u1112\u1161\u11A8",
      "\u1100\u116A\u11AB\u1100\u1162\u11A8",
      "\u1100\u116A\u11AB\u1100\u1168",
      "\u1100\u116A\u11AB\u1100\u116A\u11BC",
      "\u1100\u116A\u11AB\u1102\u1167\u11B7",
      "\u1100\u116A\u11AB\u1105\u1161\u11B7",
      "\u1100\u116A\u11AB\u1105\u1167\u11AB",
      "\u1100\u116A\u11AB\u1105\u1175",
      "\u1100\u116A\u11AB\u1109\u1173\u11B8",
      "\u1100\u116A\u11AB\u1109\u1175\u11B7",
      "\u1100\u116A\u11AB\u110C\u1165\u11B7",
      "\u1100\u116A\u11AB\u110E\u1161\u11AF",
      "\u1100\u116A\u11BC\u1100\u1167\u11BC",
      "\u1100\u116A\u11BC\u1100\u1169",
      "\u1100\u116A\u11BC\u110C\u1161\u11BC",
      "\u1100\u116A\u11BC\u110C\u116E",
      "\u1100\u116C\u1105\u1169\u110B\u116E\u11B7",
      "\u1100\u116C\u11BC\u110C\u1161\u11BC\u1112\u1175",
      "\u1100\u116D\u1100\u116A\u1109\u1165",
      "\u1100\u116D\u1106\u116E\u11AB",
      "\u1100\u116D\u1107\u1169\u11A8",
      "\u1100\u116D\u1109\u1175\u11AF",
      "\u1100\u116D\u110B\u1163\u11BC",
      "\u1100\u116D\u110B\u1172\u11A8",
      "\u1100\u116D\u110C\u1161\u11BC",
      "\u1100\u116D\u110C\u1175\u11A8",
      "\u1100\u116D\u1110\u1169\u11BC",
      "\u1100\u116D\u1112\u116A\u11AB",
      "\u1100\u116D\u1112\u116E\u11AB",
      "\u1100\u116E\u1100\u1167\u11BC",
      "\u1100\u116E\u1105\u1173\u11B7",
      "\u1100\u116E\u1106\u1165\u11BC",
      "\u1100\u116E\u1107\u1167\u11AF",
      "\u1100\u116E\u1107\u116E\u11AB",
      "\u1100\u116E\u1109\u1165\u11A8",
      "\u1100\u116E\u1109\u1165\u11BC",
      "\u1100\u116E\u1109\u1169\u11A8",
      "\u1100\u116E\u110B\u1167\u11A8",
      "\u1100\u116E\u110B\u1175\u11B8",
      "\u1100\u116E\u110E\u1165\u11BC",
      "\u1100\u116E\u110E\u1166\u110C\u1165\u11A8",
      "\u1100\u116E\u11A8\u1100\u1161",
      "\u1100\u116E\u11A8\u1100\u1175",
      "\u1100\u116E\u11A8\u1102\u1162",
      "\u1100\u116E\u11A8\u1105\u1175\u11B8",
      "\u1100\u116E\u11A8\u1106\u116E\u11AF",
      "\u1100\u116E\u11A8\u1106\u1175\u11AB",
      "\u1100\u116E\u11A8\u1109\u116E",
      "\u1100\u116E\u11A8\u110B\u1165",
      "\u1100\u116E\u11A8\u110B\u116A\u11BC",
      "\u1100\u116E\u11A8\u110C\u1165\u11A8",
      "\u1100\u116E\u11A8\u110C\u1166",
      "\u1100\u116E\u11A8\u1112\u116C",
      "\u1100\u116E\u11AB\u1103\u1162",
      "\u1100\u116E\u11AB\u1109\u1161",
      "\u1100\u116E\u11AB\u110B\u1175\u11AB",
      "\u1100\u116E\u11BC\u1100\u1173\u11A8\u110C\u1165\u11A8",
      "\u1100\u116F\u11AB\u1105\u1175",
      "\u1100\u116F\u11AB\u110B\u1171",
      "\u1100\u116F\u11AB\u1110\u116E",
      "\u1100\u1171\u1100\u116E\u11A8",
      "\u1100\u1171\u1109\u1175\u11AB",
      "\u1100\u1172\u110C\u1165\u11BC",
      "\u1100\u1172\u110E\u1175\u11A8",
      "\u1100\u1172\u11AB\u1112\u1167\u11BC",
      "\u1100\u1173\u1102\u1161\u11AF",
      "\u1100\u1173\u1102\u1163\u11BC",
      "\u1100\u1173\u1102\u1173\u11AF",
      "\u1100\u1173\u1105\u1165\u1102\u1161",
      "\u1100\u1173\u1105\u116E\u11B8",
      "\u1100\u1173\u1105\u1173\u11BA",
      "\u1100\u1173\u1105\u1175\u11B7",
      "\u1100\u1173\u110C\u1166\u1109\u1165\u110B\u1163",
      "\u1100\u1173\u1110\u1169\u1105\u1169\u11A8",
      "\u1100\u1173\u11A8\u1107\u1169\u11A8",
      "\u1100\u1173\u11A8\u1112\u1175",
      "\u1100\u1173\u11AB\u1100\u1165",
      "\u1100\u1173\u11AB\u1100\u116D",
      "\u1100\u1173\u11AB\u1105\u1162",
      "\u1100\u1173\u11AB\u1105\u1169",
      "\u1100\u1173\u11AB\u1106\u116E",
      "\u1100\u1173\u11AB\u1107\u1169\u11AB",
      "\u1100\u1173\u11AB\u110B\u116F\u11AB",
      "\u1100\u1173\u11AB\u110B\u1172\u11A8",
      "\u1100\u1173\u11AB\u110E\u1165",
      "\u1100\u1173\u11AF\u110A\u1175",
      "\u1100\u1173\u11AF\u110C\u1161",
      "\u1100\u1173\u11B7\u1100\u1161\u11BC\u1109\u1161\u11AB",
      "\u1100\u1173\u11B7\u1100\u1169",
      "\u1100\u1173\u11B7\u1102\u1167\u11AB",
      "\u1100\u1173\u11B7\u1106\u1166\u1103\u1161\u11AF",
      "\u1100\u1173\u11B7\u110B\u1162\u11A8",
      "\u1100\u1173\u11B7\u110B\u1167\u11AB",
      "\u1100\u1173\u11B7\u110B\u116D\u110B\u1175\u11AF",
      "\u1100\u1173\u11B7\u110C\u1175",
      "\u1100\u1173\u11BC\u110C\u1165\u11BC\u110C\u1165\u11A8",
      "\u1100\u1175\u1100\u1161\u11AB",
      "\u1100\u1175\u1100\u116A\u11AB",
      "\u1100\u1175\u1102\u1167\u11B7",
      "\u1100\u1175\u1102\u1173\u11BC",
      "\u1100\u1175\u1103\u1169\u11A8\u1100\u116D",
      "\u1100\u1175\u1103\u116E\u11BC",
      "\u1100\u1175\u1105\u1169\u11A8",
      "\u1100\u1175\u1105\u1173\u11B7",
      "\u1100\u1175\u1107\u1165\u11B8",
      "\u1100\u1175\u1107\u1169\u11AB",
      "\u1100\u1175\u1107\u116E\u11AB",
      "\u1100\u1175\u1108\u1173\u11B7",
      "\u1100\u1175\u1109\u116E\u11A8\u1109\u1161",
      "\u1100\u1175\u1109\u116E\u11AF",
      "\u1100\u1175\u110B\u1165\u11A8",
      "\u1100\u1175\u110B\u1165\u11B8",
      "\u1100\u1175\u110B\u1169\u11AB",
      "\u1100\u1175\u110B\u116E\u11AB",
      "\u1100\u1175\u110B\u116F\u11AB",
      "\u1100\u1175\u110C\u1165\u11A8",
      "\u1100\u1175\u110C\u116E\u11AB",
      "\u1100\u1175\u110E\u1175\u11B7",
      "\u1100\u1175\u1112\u1169\u11AB",
      "\u1100\u1175\u1112\u116C\u11A8",
      "\u1100\u1175\u11AB\u1100\u1173\u11B8",
      "\u1100\u1175\u11AB\u110C\u1161\u11BC",
      "\u1100\u1175\u11AF\u110B\u1175",
      "\u1100\u1175\u11B7\u1107\u1161\u11B8",
      "\u1100\u1175\u11B7\u110E\u1175",
      "\u1100\u1175\u11B7\u1111\u1169\u1100\u1169\u11BC\u1112\u1161\u11BC",
      "\u1101\u1161\u11A8\u1103\u116E\u1100\u1175",
      "\u1101\u1161\u11B7\u1108\u1161\u11A8",
      "\u1101\u1162\u1103\u1161\u11AF\u110B\u1173\u11B7",
      "\u1101\u1162\u1109\u1169\u1100\u1173\u11B7",
      "\u1101\u1165\u11B8\u110C\u1175\u11AF",
      "\u1101\u1169\u11A8\u1103\u1162\u1100\u1175",
      "\u1101\u1169\u11BE\u110B\u1175\u11C1",
      "\u1102\u1161\u1103\u1173\u11AF\u110B\u1175",
      "\u1102\u1161\u1105\u1161\u11AB\u1112\u1175",
      "\u1102\u1161\u1106\u1165\u110C\u1175",
      "\u1102\u1161\u1106\u116E\u11AF",
      "\u1102\u1161\u110E\u1175\u11B7\u1107\u1161\u11AB",
      "\u1102\u1161\u1112\u1173\u11AF",
      "\u1102\u1161\u11A8\u110B\u1167\u11B8",
      "\u1102\u1161\u11AB\u1107\u1161\u11BC",
      "\u1102\u1161\u11AF\u1100\u1162",
      "\u1102\u1161\u11AF\u110A\u1175",
      "\u1102\u1161\u11AF\u110D\u1161",
      "\u1102\u1161\u11B7\u1102\u1167",
      "\u1102\u1161\u11B7\u1103\u1162\u1106\u116E\u11AB",
      "\u1102\u1161\u11B7\u1106\u1162",
      "\u1102\u1161\u11B7\u1109\u1161\u11AB",
      "\u1102\u1161\u11B7\u110C\u1161",
      "\u1102\u1161\u11B7\u1111\u1167\u11AB",
      "\u1102\u1161\u11B7\u1112\u1161\u11A8\u1109\u1162\u11BC",
      "\u1102\u1161\u11BC\u1107\u1175",
      "\u1102\u1161\u11C0\u1106\u1161\u11AF",
      "\u1102\u1162\u1102\u1167\u11AB",
      "\u1102\u1162\u110B\u116D\u11BC",
      "\u1102\u1162\u110B\u1175\u11AF",
      "\u1102\u1162\u11B7\u1107\u1175",
      "\u1102\u1162\u11B7\u1109\u1162",
      "\u1102\u1162\u11BA\u1106\u116E\u11AF",
      "\u1102\u1162\u11BC\u1103\u1169\u11BC",
      "\u1102\u1162\u11BC\u1106\u1167\u11AB",
      "\u1102\u1162\u11BC\u1107\u1161\u11BC",
      "\u1102\u1162\u11BC\u110C\u1161\u11BC\u1100\u1169",
      "\u1102\u1166\u11A8\u1110\u1161\u110B\u1175",
      "\u1102\u1166\u11BA\u110D\u1162",
      "\u1102\u1169\u1103\u1169\u11BC",
      "\u1102\u1169\u1105\u1161\u11AB\u1109\u1162\u11A8",
      "\u1102\u1169\u1105\u1167\u11A8",
      "\u1102\u1169\u110B\u1175\u11AB",
      "\u1102\u1169\u11A8\u110B\u1173\u11B7",
      "\u1102\u1169\u11A8\u110E\u1161",
      "\u1102\u1169\u11A8\u1112\u116A",
      "\u1102\u1169\u11AB\u1105\u1175",
      "\u1102\u1169\u11AB\u1106\u116E\u11AB",
      "\u1102\u1169\u11AB\u110C\u1162\u11BC",
      "\u1102\u1169\u11AF\u110B\u1175",
      "\u1102\u1169\u11BC\u1100\u116E",
      "\u1102\u1169\u11BC\u1103\u1161\u11B7",
      "\u1102\u1169\u11BC\u1106\u1175\u11AB",
      "\u1102\u1169\u11BC\u1107\u116E",
      "\u1102\u1169\u11BC\u110B\u1165\u11B8",
      "\u1102\u1169\u11BC\u110C\u1161\u11BC",
      "\u1102\u1169\u11BC\u110E\u1169\u11AB",
      "\u1102\u1169\u11C1\u110B\u1175",
      "\u1102\u116E\u11AB\u1103\u1169\u11BC\u110C\u1161",
      "\u1102\u116E\u11AB\u1106\u116E\u11AF",
      "\u1102\u116E\u11AB\u110A\u1165\u11B8",
      "\u1102\u1172\u110B\u116D\u11A8",
      "\u1102\u1173\u1101\u1175\u11B7",
      "\u1102\u1173\u11A8\u1103\u1162",
      "\u1102\u1173\u11BC\u1103\u1169\u11BC\u110C\u1165\u11A8",
      "\u1102\u1173\u11BC\u1105\u1167\u11A8",
      "\u1103\u1161\u1107\u1161\u11BC",
      "\u1103\u1161\u110B\u1163\u11BC\u1109\u1165\u11BC",
      "\u1103\u1161\u110B\u1173\u11B7",
      "\u1103\u1161\u110B\u1175\u110B\u1165\u1110\u1173",
      "\u1103\u1161\u1112\u1162\u11BC",
      "\u1103\u1161\u11AB\u1100\u1168",
      "\u1103\u1161\u11AB\u1100\u1169\u11AF",
      "\u1103\u1161\u11AB\u1103\u1169\u11A8",
      "\u1103\u1161\u11AB\u1106\u1161\u11BA",
      "\u1103\u1161\u11AB\u1109\u116E\u11AB",
      "\u1103\u1161\u11AB\u110B\u1165",
      "\u1103\u1161\u11AB\u110B\u1171",
      "\u1103\u1161\u11AB\u110C\u1165\u11B7",
      "\u1103\u1161\u11AB\u110E\u1166",
      "\u1103\u1161\u11AB\u110E\u116E",
      "\u1103\u1161\u11AB\u1111\u1167\u11AB",
      "\u1103\u1161\u11AB\u1111\u116E\u11BC",
      "\u1103\u1161\u11AF\u1100\u1163\u11AF",
      "\u1103\u1161\u11AF\u1105\u1165",
      "\u1103\u1161\u11AF\u1105\u1167\u11A8",
      "\u1103\u1161\u11AF\u1105\u1175",
      "\u1103\u1161\u11B0\u1100\u1169\u1100\u1175",
      "\u1103\u1161\u11B7\u1103\u1161\u11BC",
      "\u1103\u1161\u11B7\u1107\u1162",
      "\u1103\u1161\u11B7\u110B\u116D",
      "\u1103\u1161\u11B7\u110B\u1175\u11B7",
      "\u1103\u1161\u11B8\u1107\u1167\u11AB",
      "\u1103\u1161\u11B8\u110C\u1161\u11BC",
      "\u1103\u1161\u11BC\u1100\u1173\u11AB",
      "\u1103\u1161\u11BC\u1107\u116E\u11AB\u1100\u1161\u11AB",
      "\u1103\u1161\u11BC\u110B\u1167\u11AB\u1112\u1175",
      "\u1103\u1161\u11BC\u110C\u1161\u11BC",
      "\u1103\u1162\u1100\u1172\u1106\u1169",
      "\u1103\u1162\u1102\u1161\u11BD",
      "\u1103\u1162\u1103\u1161\u11AB\u1112\u1175",
      "\u1103\u1162\u1103\u1161\u11B8",
      "\u1103\u1162\u1103\u1169\u1109\u1175",
      "\u1103\u1162\u1105\u1163\u11A8",
      "\u1103\u1162\u1105\u1163\u11BC",
      "\u1103\u1162\u1105\u1172\u11A8",
      "\u1103\u1162\u1106\u116E\u11AB",
      "\u1103\u1162\u1107\u116E\u1107\u116E\u11AB",
      "\u1103\u1162\u1109\u1175\u11AB",
      "\u1103\u1162\u110B\u1173\u11BC",
      "\u1103\u1162\u110C\u1161\u11BC",
      "\u1103\u1162\u110C\u1165\u11AB",
      "\u1103\u1162\u110C\u1165\u11B8",
      "\u1103\u1162\u110C\u116E\u11BC",
      "\u1103\u1162\u110E\u1162\u11A8",
      "\u1103\u1162\u110E\u116E\u11AF",
      "\u1103\u1162\u110E\u116E\u11BC",
      "\u1103\u1162\u1110\u1169\u11BC\u1105\u1167\u11BC",
      "\u1103\u1162\u1112\u1161\u11A8",
      "\u1103\u1162\u1112\u1161\u11AB\u1106\u1175\u11AB\u1100\u116E\u11A8",
      "\u1103\u1162\u1112\u1161\u11B8\u1109\u1175\u11AF",
      "\u1103\u1162\u1112\u1167\u11BC",
      "\u1103\u1165\u11BC\u110B\u1165\u1105\u1175",
      "\u1103\u1166\u110B\u1175\u1110\u1173",
      "\u1103\u1169\u1103\u1162\u110E\u1166",
      "\u1103\u1169\u1103\u1165\u11A8",
      "\u1103\u1169\u1103\u116E\u11A8",
      "\u1103\u1169\u1106\u1161\u11BC",
      "\u1103\u1169\u1109\u1165\u1100\u116A\u11AB",
      "\u1103\u1169\u1109\u1175\u11B7",
      "\u1103\u1169\u110B\u116E\u11B7",
      "\u1103\u1169\u110B\u1175\u11B8",
      "\u1103\u1169\u110C\u1161\u1100\u1175",
      "\u1103\u1169\u110C\u1165\u1112\u1175",
      "\u1103\u1169\u110C\u1165\u11AB",
      "\u1103\u1169\u110C\u116E\u11BC",
      "\u1103\u1169\u110E\u1161\u11A8",
      "\u1103\u1169\u11A8\u1100\u1161\u11B7",
      "\u1103\u1169\u11A8\u1105\u1175\u11B8",
      "\u1103\u1169\u11A8\u1109\u1165",
      "\u1103\u1169\u11A8\u110B\u1175\u11AF",
      "\u1103\u1169\u11A8\u110E\u1161\u11BC\u110C\u1165\u11A8",
      "\u1103\u1169\u11BC\u1112\u116A\u110E\u1162\u11A8",
      "\u1103\u1171\u11BA\u1106\u1169\u1109\u1173\u11B8",
      "\u1103\u1171\u11BA\u1109\u1161\u11AB",
      "\u1104\u1161\u11AF\u110B\u1161\u110B\u1175",
      "\u1106\u1161\u1102\u116E\u1105\u1161",
      "\u1106\u1161\u1102\u1173\u11AF",
      "\u1106\u1161\u1103\u1161\u11BC",
      "\u1106\u1161\u1105\u1161\u1110\u1169\u11AB",
      "\u1106\u1161\u1105\u1167\u11AB",
      "\u1106\u1161\u1106\u116E\u1105\u1175",
      "\u1106\u1161\u1109\u1161\u110C\u1175",
      "\u1106\u1161\u110B\u1163\u11A8",
      "\u1106\u1161\u110B\u116D\u1102\u1166\u110C\u1173",
      "\u1106\u1161\u110B\u1173\u11AF",
      "\u1106\u1161\u110B\u1173\u11B7",
      "\u1106\u1161\u110B\u1175\u110F\u1173",
      "\u1106\u1161\u110C\u116E\u11BC",
      "\u1106\u1161\u110C\u1175\u1106\u1161\u11A8",
      "\u1106\u1161\u110E\u1161\u11AB\u1100\u1161\u110C\u1175",
      "\u1106\u1161\u110E\u1161\u11AF",
      "\u1106\u1161\u1112\u1173\u11AB",
      "\u1106\u1161\u11A8\u1100\u1165\u11AF\u1105\u1175",
      "\u1106\u1161\u11A8\u1102\u1162",
      "\u1106\u1161\u11A8\u1109\u1161\u11BC",
      "\u1106\u1161\u11AB\u1102\u1161\u11B7",
      "\u1106\u1161\u11AB\u1103\u116E",
      "\u1106\u1161\u11AB\u1109\u1166",
      "\u1106\u1161\u11AB\u110B\u1163\u11A8",
      "\u1106\u1161\u11AB\u110B\u1175\u11AF",
      "\u1106\u1161\u11AB\u110C\u1165\u11B7",
      "\u1106\u1161\u11AB\u110C\u1169\u11A8",
      "\u1106\u1161\u11AB\u1112\u116A",
      "\u1106\u1161\u11AD\u110B\u1175",
      "\u1106\u1161\u11AF\u1100\u1175",
      "\u1106\u1161\u11AF\u110A\u1173\u11B7",
      "\u1106\u1161\u11AF\u1110\u116E",
      "\u1106\u1161\u11B7\u1103\u1162\u1105\u1169",
      "\u1106\u1161\u11BC\u110B\u116F\u11AB\u1100\u1167\u11BC",
      "\u1106\u1162\u1102\u1167\u11AB",
      "\u1106\u1162\u1103\u1161\u11AF",
      "\u1106\u1162\u1105\u1167\u11A8",
      "\u1106\u1162\u1107\u1165\u11AB",
      "\u1106\u1162\u1109\u1173\u110F\u1165\u11B7",
      "\u1106\u1162\u110B\u1175\u11AF",
      "\u1106\u1162\u110C\u1161\u11BC",
      "\u1106\u1162\u11A8\u110C\u116E",
      "\u1106\u1165\u11A8\u110B\u1175",
      "\u1106\u1165\u11AB\u110C\u1165",
      "\u1106\u1165\u11AB\u110C\u1175",
      "\u1106\u1165\u11AF\u1105\u1175",
      "\u1106\u1166\u110B\u1175\u11AF",
      "\u1106\u1167\u1102\u1173\u1105\u1175",
      "\u1106\u1167\u110E\u1175\u11AF",
      "\u1106\u1167\u11AB\u1103\u1161\u11B7",
      "\u1106\u1167\u11AF\u110E\u1175",
      "\u1106\u1167\u11BC\u1103\u1161\u11AB",
      "\u1106\u1167\u11BC\u1105\u1167\u11BC",
      "\u1106\u1167\u11BC\u110B\u1168",
      "\u1106\u1167\u11BC\u110B\u1174",
      "\u1106\u1167\u11BC\u110C\u1165\u11AF",
      "\u1106\u1167\u11BC\u110E\u1175\u11BC",
      "\u1106\u1167\u11BC\u1112\u1161\u11B7",
      "\u1106\u1169\u1100\u1173\u11B7",
      "\u1106\u1169\u1102\u1175\u1110\u1165",
      "\u1106\u1169\u1103\u1166\u11AF",
      "\u1106\u1169\u1103\u1173\u11AB",
      "\u1106\u1169\u1107\u1165\u11B7",
      "\u1106\u1169\u1109\u1173\u11B8",
      "\u1106\u1169\u110B\u1163\u11BC",
      "\u1106\u1169\u110B\u1175\u11B7",
      "\u1106\u1169\u110C\u1169\u1105\u1175",
      "\u1106\u1169\u110C\u1175\u11B8",
      "\u1106\u1169\u1110\u116E\u11BC\u110B\u1175",
      "\u1106\u1169\u11A8\u1100\u1165\u11AF\u110B\u1175",
      "\u1106\u1169\u11A8\u1105\u1169\u11A8",
      "\u1106\u1169\u11A8\u1109\u1161",
      "\u1106\u1169\u11A8\u1109\u1169\u1105\u1175",
      "\u1106\u1169\u11A8\u1109\u116E\u11B7",
      "\u1106\u1169\u11A8\u110C\u1165\u11A8",
      "\u1106\u1169\u11A8\u1111\u116D",
      "\u1106\u1169\u11AF\u1105\u1162",
      "\u1106\u1169\u11B7\u1106\u1162",
      "\u1106\u1169\u11B7\u1106\u116E\u1100\u1166",
      "\u1106\u1169\u11B7\u1109\u1161\u11AF",
      "\u1106\u1169\u11B7\u1109\u1169\u11A8",
      "\u1106\u1169\u11B7\u110C\u1175\u11BA",
      "\u1106\u1169\u11B7\u1110\u1169\u11BC",
      "\u1106\u1169\u11B8\u1109\u1175",
      "\u1106\u116E\u1100\u116A\u11AB\u1109\u1175\u11B7",
      "\u1106\u116E\u1100\u116E\u11BC\u1112\u116A",
      "\u1106\u116E\u1103\u1165\u110B\u1171",
      "\u1106\u116E\u1103\u1165\u11B7",
      "\u1106\u116E\u1105\u1173\u11C1",
      "\u1106\u116E\u1109\u1173\u11AB",
      "\u1106\u116E\u110B\u1165\u11BA",
      "\u1106\u116E\u110B\u1167\u11A8",
      "\u1106\u116E\u110B\u116D\u11BC",
      "\u1106\u116E\u110C\u1169\u1100\u1165\u11AB",
      "\u1106\u116E\u110C\u1175\u1100\u1162",
      "\u1106\u116E\u110E\u1165\u11A8",
      "\u1106\u116E\u11AB\u1100\u116E",
      "\u1106\u116E\u11AB\u1103\u1173\u11A8",
      "\u1106\u116E\u11AB\u1107\u1165\u11B8",
      "\u1106\u116E\u11AB\u1109\u1165",
      "\u1106\u116E\u11AB\u110C\u1166",
      "\u1106\u116E\u11AB\u1112\u1161\u11A8",
      "\u1106\u116E\u11AB\u1112\u116A",
      "\u1106\u116E\u11AF\u1100\u1161",
      "\u1106\u116E\u11AF\u1100\u1165\u11AB",
      "\u1106\u116E\u11AF\u1100\u1167\u11AF",
      "\u1106\u116E\u11AF\u1100\u1169\u1100\u1175",
      "\u1106\u116E\u11AF\u1105\u1169\u11AB",
      "\u1106\u116E\u11AF\u1105\u1175\u1112\u1161\u11A8",
      "\u1106\u116E\u11AF\u110B\u1173\u11B7",
      "\u1106\u116E\u11AF\u110C\u1175\u11AF",
      "\u1106\u116E\u11AF\u110E\u1166",
      "\u1106\u1175\u1100\u116E\u11A8",
      "\u1106\u1175\u1103\u1175\u110B\u1165",
      "\u1106\u1175\u1109\u1161\u110B\u1175\u11AF",
      "\u1106\u1175\u1109\u116E\u11AF",
      "\u1106\u1175\u110B\u1167\u11A8",
      "\u1106\u1175\u110B\u116D\u11BC\u1109\u1175\u11AF",
      "\u1106\u1175\u110B\u116E\u11B7",
      "\u1106\u1175\u110B\u1175\u11AB",
      "\u1106\u1175\u1110\u1175\u11BC",
      "\u1106\u1175\u1112\u1169\u11AB",
      "\u1106\u1175\u11AB\u1100\u1161\u11AB",
      "\u1106\u1175\u11AB\u110C\u1169\u11A8",
      "\u1106\u1175\u11AB\u110C\u116E",
      "\u1106\u1175\u11AE\u110B\u1173\u11B7",
      "\u1106\u1175\u11AF\u1100\u1161\u1105\u116E",
      "\u1106\u1175\u11AF\u1105\u1175\u1106\u1175\u1110\u1165",
      "\u1106\u1175\u11C0\u1107\u1161\u1103\u1161\u11A8",
      "\u1107\u1161\u1100\u1161\u110C\u1175",
      "\u1107\u1161\u1100\u116E\u1102\u1175",
      "\u1107\u1161\u1102\u1161\u1102\u1161",
      "\u1107\u1161\u1102\u1173\u11AF",
      "\u1107\u1161\u1103\u1161\u11A8",
      "\u1107\u1161\u1103\u1161\u11BA\u1100\u1161",
      "\u1107\u1161\u1105\u1161\u11B7",
      "\u1107\u1161\u110B\u1175\u1105\u1165\u1109\u1173",
      "\u1107\u1161\u1110\u1161\u11BC",
      "\u1107\u1161\u11A8\u1106\u116E\u11AF\u1100\u116A\u11AB",
      "\u1107\u1161\u11A8\u1109\u1161",
      "\u1107\u1161\u11A8\u1109\u116E",
      "\u1107\u1161\u11AB\u1103\u1162",
      "\u1107\u1161\u11AB\u1103\u1173\u1109\u1175",
      "\u1107\u1161\u11AB\u1106\u1161\u11AF",
      "\u1107\u1161\u11AB\u1107\u1161\u11AF",
      "\u1107\u1161\u11AB\u1109\u1165\u11BC",
      "\u1107\u1161\u11AB\u110B\u1173\u11BC",
      "\u1107\u1161\u11AB\u110C\u1161\u11BC",
      "\u1107\u1161\u11AB\u110C\u116E\u11A8",
      "\u1107\u1161\u11AB\u110C\u1175",
      "\u1107\u1161\u11AB\u110E\u1161\u11AB",
      "\u1107\u1161\u11AE\u110E\u1175\u11B7",
      "\u1107\u1161\u11AF\u1100\u1161\u1105\u1161\u11A8",
      "\u1107\u1161\u11AF\u1100\u1165\u11AF\u110B\u1173\u11B7",
      "\u1107\u1161\u11AF\u1100\u1167\u11AB",
      "\u1107\u1161\u11AF\u1103\u1161\u11AF",
      "\u1107\u1161\u11AF\u1105\u1166",
      "\u1107\u1161\u11AF\u1106\u1169\u11A8",
      "\u1107\u1161\u11AF\u1107\u1161\u1103\u1161\u11A8",
      "\u1107\u1161\u11AF\u1109\u1162\u11BC",
      "\u1107\u1161\u11AF\u110B\u1173\u11B7",
      "\u1107\u1161\u11AF\u110C\u1161\u1100\u116E\u11A8",
      "\u1107\u1161\u11AF\u110C\u1165\u11AB",
      "\u1107\u1161\u11AF\u1110\u1169\u11B8",
      "\u1107\u1161\u11AF\u1111\u116D",
      "\u1107\u1161\u11B7\u1112\u1161\u1102\u1173\u11AF",
      "\u1107\u1161\u11B8\u1100\u1173\u1105\u1173\u11BA",
      "\u1107\u1161\u11B8\u1106\u1161\u11BA",
      "\u1107\u1161\u11B8\u1109\u1161\u11BC",
      "\u1107\u1161\u11B8\u1109\u1169\u11C0",
      "\u1107\u1161\u11BC\u1100\u1173\u11B7",
      "\u1107\u1161\u11BC\u1106\u1167\u11AB",
      "\u1107\u1161\u11BC\u1106\u116E\u11AB",
      "\u1107\u1161\u11BC\u1107\u1161\u1103\u1161\u11A8",
      "\u1107\u1161\u11BC\u1107\u1165\u11B8",
      "\u1107\u1161\u11BC\u1109\u1169\u11BC",
      "\u1107\u1161\u11BC\u1109\u1175\u11A8",
      "\u1107\u1161\u11BC\u110B\u1161\u11AB",
      "\u1107\u1161\u11BC\u110B\u116E\u11AF",
      "\u1107\u1161\u11BC\u110C\u1175",
      "\u1107\u1161\u11BC\u1112\u1161\u11A8",
      "\u1107\u1161\u11BC\u1112\u1162",
      "\u1107\u1161\u11BC\u1112\u1163\u11BC",
      "\u1107\u1162\u1100\u1167\u11BC",
      "\u1107\u1162\u1101\u1169\u11B8",
      "\u1107\u1162\u1103\u1161\u11AF",
      "\u1107\u1162\u1103\u1173\u1106\u1175\u11AB\u1110\u1165\u11AB",
      "\u1107\u1162\u11A8\u1103\u116E\u1109\u1161\u11AB",
      "\u1107\u1162\u11A8\u1109\u1162\u11A8",
      "\u1107\u1162\u11A8\u1109\u1165\u11BC",
      "\u1107\u1162\u11A8\u110B\u1175\u11AB",
      "\u1107\u1162\u11A8\u110C\u1166",
      "\u1107\u1162\u11A8\u1112\u116A\u110C\u1165\u11B7",
      "\u1107\u1165\u1105\u1173\u11BA",
      "\u1107\u1165\u1109\u1165\u11BA",
      "\u1107\u1165\u1110\u1173\u11AB",
      "\u1107\u1165\u11AB\u1100\u1162",
      "\u1107\u1165\u11AB\u110B\u1167\u11A8",
      "\u1107\u1165\u11AB\u110C\u1175",
      "\u1107\u1165\u11AB\u1112\u1169",
      "\u1107\u1165\u11AF\u1100\u1173\u11B7",
      "\u1107\u1165\u11AF\u1105\u1166",
      "\u1107\u1165\u11AF\u110A\u1165",
      "\u1107\u1165\u11B7\u110B\u1171",
      "\u1107\u1165\u11B7\u110B\u1175\u11AB",
      "\u1107\u1165\u11B7\u110C\u116C",
      "\u1107\u1165\u11B8\u1105\u1172\u11AF",
      "\u1107\u1165\u11B8\u110B\u116F\u11AB",
      "\u1107\u1165\u11B8\u110C\u1165\u11A8",
      "\u1107\u1165\u11B8\u110E\u1175\u11A8",
      "\u1107\u1166\u110B\u1175\u110C\u1175\u11BC",
      "\u1107\u1166\u11AF\u1110\u1173",
      "\u1107\u1167\u11AB\u1100\u1167\u11BC",
      "\u1107\u1167\u11AB\u1103\u1169\u11BC",
      "\u1107\u1167\u11AB\u1106\u1167\u11BC",
      "\u1107\u1167\u11AB\u1109\u1175\u11AB",
      "\u1107\u1167\u11AB\u1112\u1169\u1109\u1161",
      "\u1107\u1167\u11AB\u1112\u116A",
      "\u1107\u1167\u11AF\u1103\u1169",
      "\u1107\u1167\u11AF\u1106\u1167\u11BC",
      "\u1107\u1167\u11AF\u110B\u1175\u11AF",
      "\u1107\u1167\u11BC\u1109\u1175\u11AF",
      "\u1107\u1167\u11BC\u110B\u1161\u1105\u1175",
      "\u1107\u1167\u11BC\u110B\u116F\u11AB",
      "\u1107\u1169\u1100\u116A\u11AB",
      "\u1107\u1169\u1102\u1165\u1109\u1173",
      "\u1107\u1169\u1105\u1161\u1109\u1162\u11A8",
      "\u1107\u1169\u1105\u1161\u11B7",
      "\u1107\u1169\u1105\u1173\u11B7",
      "\u1107\u1169\u1109\u1161\u11BC",
      "\u1107\u1169\u110B\u1161\u11AB",
      "\u1107\u1169\u110C\u1161\u1100\u1175",
      "\u1107\u1169\u110C\u1161\u11BC",
      "\u1107\u1169\u110C\u1165\u11AB",
      "\u1107\u1169\u110C\u1169\u11AB",
      "\u1107\u1169\u1110\u1169\u11BC",
      "\u1107\u1169\u1111\u1167\u11AB\u110C\u1165\u11A8",
      "\u1107\u1169\u1112\u1165\u11B7",
      "\u1107\u1169\u11A8\u1103\u1169",
      "\u1107\u1169\u11A8\u1109\u1161",
      "\u1107\u1169\u11A8\u1109\u116E\u11BC\u110B\u1161",
      "\u1107\u1169\u11A8\u1109\u1173\u11B8",
      "\u1107\u1169\u11A9\u110B\u1173\u11B7",
      "\u1107\u1169\u11AB\u1100\u1167\u11A8\u110C\u1165\u11A8",
      "\u1107\u1169\u11AB\u1105\u1162",
      "\u1107\u1169\u11AB\u1107\u116E",
      "\u1107\u1169\u11AB\u1109\u1161",
      "\u1107\u1169\u11AB\u1109\u1165\u11BC",
      "\u1107\u1169\u11AB\u110B\u1175\u11AB",
      "\u1107\u1169\u11AB\u110C\u1175\u11AF",
      "\u1107\u1169\u11AF\u1111\u1166\u11AB",
      "\u1107\u1169\u11BC\u1109\u1161",
      "\u1107\u1169\u11BC\u110C\u1175",
      "\u1107\u1169\u11BC\u1110\u116E",
      "\u1107\u116E\u1100\u1173\u11AB",
      "\u1107\u116E\u1101\u1173\u1105\u1165\u110B\u116E\u11B7",
      "\u1107\u116E\u1103\u1161\u11B7",
      "\u1107\u116E\u1103\u1169\u11BC\u1109\u1161\u11AB",
      "\u1107\u116E\u1106\u116E\u11AB",
      "\u1107\u116E\u1107\u116E\u11AB",
      "\u1107\u116E\u1109\u1161\u11AB",
      "\u1107\u116E\u1109\u1161\u11BC",
      "\u1107\u116E\u110B\u1165\u11BF",
      "\u1107\u116E\u110B\u1175\u11AB",
      "\u1107\u116E\u110C\u1161\u11A8\u110B\u116D\u11BC",
      "\u1107\u116E\u110C\u1161\u11BC",
      "\u1107\u116E\u110C\u1165\u11BC",
      "\u1107\u116E\u110C\u1169\u11A8",
      "\u1107\u116E\u110C\u1175\u1105\u1165\u11AB\u1112\u1175",
      "\u1107\u116E\u110E\u1175\u11AB",
      "\u1107\u116E\u1110\u1161\u11A8",
      "\u1107\u116E\u1111\u116E\u11B7",
      "\u1107\u116E\u1112\u116C\u110C\u1161\u11BC",
      "\u1107\u116E\u11A8\u1107\u116E",
      "\u1107\u116E\u11A8\u1112\u1161\u11AB",
      "\u1107\u116E\u11AB\u1102\u1169",
      "\u1107\u116E\u11AB\u1105\u1163\u11BC",
      "\u1107\u116E\u11AB\u1105\u1175",
      "\u1107\u116E\u11AB\u1106\u1167\u11BC",
      "\u1107\u116E\u11AB\u1109\u1165\u11A8",
      "\u1107\u116E\u11AB\u110B\u1163",
      "\u1107\u116E\u11AB\u110B\u1171\u1100\u1175",
      "\u1107\u116E\u11AB\u1111\u1175\u11AF",
      "\u1107\u116E\u11AB\u1112\u1169\u11BC\u1109\u1162\u11A8",
      "\u1107\u116E\u11AF\u1100\u1169\u1100\u1175",
      "\u1107\u116E\u11AF\u1100\u116A",
      "\u1107\u116E\u11AF\u1100\u116D",
      "\u1107\u116E\u11AF\u1101\u1169\u11BE",
      "\u1107\u116E\u11AF\u1106\u1161\u11AB",
      "\u1107\u116E\u11AF\u1107\u1165\u11B8",
      "\u1107\u116E\u11AF\u1107\u1175\u11BE",
      "\u1107\u116E\u11AF\u110B\u1161\u11AB",
      "\u1107\u116E\u11AF\u110B\u1175\u110B\u1175\u11A8",
      "\u1107\u116E\u11AF\u1112\u1162\u11BC",
      "\u1107\u1173\u1105\u1162\u11AB\u1103\u1173",
      "\u1107\u1175\u1100\u1173\u11A8",
      "\u1107\u1175\u1102\u1161\u11AB",
      "\u1107\u1175\u1102\u1175\u11AF",
      "\u1107\u1175\u1103\u116E\u11AF\u1100\u1175",
      "\u1107\u1175\u1103\u1175\u110B\u1169",
      "\u1107\u1175\u1105\u1169\u1109\u1169",
      "\u1107\u1175\u1106\u1161\u11AB",
      "\u1107\u1175\u1106\u1167\u11BC",
      "\u1107\u1175\u1106\u1175\u11AF",
      "\u1107\u1175\u1107\u1161\u1105\u1161\u11B7",
      "\u1107\u1175\u1107\u1175\u11B7\u1107\u1161\u11B8",
      "\u1107\u1175\u1109\u1161\u11BC",
      "\u1107\u1175\u110B\u116D\u11BC",
      "\u1107\u1175\u110B\u1172\u11AF",
      "\u1107\u1175\u110C\u116E\u11BC",
      "\u1107\u1175\u1110\u1161\u1106\u1175\u11AB",
      "\u1107\u1175\u1111\u1161\u11AB",
      "\u1107\u1175\u11AF\u1103\u1175\u11BC",
      "\u1107\u1175\u11BA\u1106\u116E\u11AF",
      "\u1107\u1175\u11BA\u1107\u1161\u11BC\u110B\u116E\u11AF",
      "\u1107\u1175\u11BA\u110C\u116E\u11AF\u1100\u1175",
      "\u1107\u1175\u11BE\u1101\u1161\u11AF",
      "\u1108\u1161\u11AF\u1100\u1161\u11AB\u1109\u1162\u11A8",
      "\u1108\u1161\u11AF\u1105\u1162",
      "\u1108\u1161\u11AF\u1105\u1175",
      "\u1109\u1161\u1100\u1165\u11AB",
      "\u1109\u1161\u1100\u1168\u110C\u1165\u11AF",
      "\u1109\u1161\u1102\u1161\u110B\u1175",
      "\u1109\u1161\u1102\u1163\u11BC",
      "\u1109\u1161\u1105\u1161\u11B7",
      "\u1109\u1161\u1105\u1161\u11BC",
      "\u1109\u1161\u1105\u1175\u11B8",
      "\u1109\u1161\u1106\u1169\u1102\u1175\u11B7",
      "\u1109\u1161\u1106\u116E\u11AF",
      "\u1109\u1161\u1107\u1161\u11BC",
      "\u1109\u1161\u1109\u1161\u11BC",
      "\u1109\u1161\u1109\u1162\u11BC\u1112\u116A\u11AF",
      "\u1109\u1161\u1109\u1165\u11AF",
      "\u1109\u1161\u1109\u1173\u11B7",
      "\u1109\u1161\u1109\u1175\u11AF",
      "\u1109\u1161\u110B\u1165\u11B8",
      "\u1109\u1161\u110B\u116D\u11BC",
      "\u1109\u1161\u110B\u116F\u11AF",
      "\u1109\u1161\u110C\u1161\u11BC",
      "\u1109\u1161\u110C\u1165\u11AB",
      "\u1109\u1161\u110C\u1175\u11AB",
      "\u1109\u1161\u110E\u1169\u11AB",
      "\u1109\u1161\u110E\u116E\u11AB\u1100\u1175",
      "\u1109\u1161\u1110\u1161\u11BC",
      "\u1109\u1161\u1110\u116E\u1105\u1175",
      "\u1109\u1161\u1112\u1173\u11AF",
      "\u1109\u1161\u11AB\u1100\u1175\u11AF",
      "\u1109\u1161\u11AB\u1107\u116E\u110B\u1175\u11AB\u1100\u116A",
      "\u1109\u1161\u11AB\u110B\u1165\u11B8",
      "\u1109\u1161\u11AB\u110E\u1162\u11A8",
      "\u1109\u1161\u11AF\u1105\u1175\u11B7",
      "\u1109\u1161\u11AF\u110B\u1175\u11AB",
      "\u1109\u1161\u11AF\u110D\u1161\u11A8",
      "\u1109\u1161\u11B7\u1100\u1168\u1110\u1161\u11BC",
      "\u1109\u1161\u11B7\u1100\u116E\u11A8",
      "\u1109\u1161\u11B7\u1109\u1175\u11B8",
      "\u1109\u1161\u11B7\u110B\u116F\u11AF",
      "\u1109\u1161\u11B7\u110E\u1169\u11AB",
      "\u1109\u1161\u11BC\u1100\u116A\u11AB",
      "\u1109\u1161\u11BC\u1100\u1173\u11B7",
      "\u1109\u1161\u11BC\u1103\u1162",
      "\u1109\u1161\u11BC\u1105\u1172",
      "\u1109\u1161\u11BC\u1107\u1161\u11AB\u1100\u1175",
      "\u1109\u1161\u11BC\u1109\u1161\u11BC",
      "\u1109\u1161\u11BC\u1109\u1175\u11A8",
      "\u1109\u1161\u11BC\u110B\u1165\u11B8",
      "\u1109\u1161\u11BC\u110B\u1175\u11AB",
      "\u1109\u1161\u11BC\u110C\u1161",
      "\u1109\u1161\u11BC\u110C\u1165\u11B7",
      "\u1109\u1161\u11BC\u110E\u1165",
      "\u1109\u1161\u11BC\u110E\u116E",
      "\u1109\u1161\u11BC\u1110\u1162",
      "\u1109\u1161\u11BC\u1111\u116D",
      "\u1109\u1161\u11BC\u1111\u116E\u11B7",
      "\u1109\u1161\u11BC\u1112\u116A\u11BC",
      "\u1109\u1162\u1107\u1167\u11A8",
      "\u1109\u1162\u11A8\u1101\u1161\u11AF",
      "\u1109\u1162\u11A8\u110B\u1167\u11AB\u1111\u1175\u11AF",
      "\u1109\u1162\u11BC\u1100\u1161\u11A8",
      "\u1109\u1162\u11BC\u1106\u1167\u11BC",
      "\u1109\u1162\u11BC\u1106\u116E\u11AF",
      "\u1109\u1162\u11BC\u1107\u1161\u11BC\u1109\u1169\u11BC",
      "\u1109\u1162\u11BC\u1109\u1161\u11AB",
      "\u1109\u1162\u11BC\u1109\u1165\u11AB",
      "\u1109\u1162\u11BC\u1109\u1175\u11AB",
      "\u1109\u1162\u11BC\u110B\u1175\u11AF",
      "\u1109\u1162\u11BC\u1112\u116A\u11AF",
      "\u1109\u1165\u1105\u1161\u11B8",
      "\u1109\u1165\u1105\u1173\u11AB",
      "\u1109\u1165\u1106\u1167\u11BC",
      "\u1109\u1165\u1106\u1175\u11AB",
      "\u1109\u1165\u1107\u1175\u1109\u1173",
      "\u1109\u1165\u110B\u1163\u11BC",
      "\u1109\u1165\u110B\u116E\u11AF",
      "\u1109\u1165\u110C\u1165\u11A8",
      "\u1109\u1165\u110C\u1165\u11B7",
      "\u1109\u1165\u110D\u1169\u11A8",
      "\u1109\u1165\u110F\u1173\u11AF",
      "\u1109\u1165\u11A8\u1109\u1161",
      "\u1109\u1165\u11A8\u110B\u1172",
      "\u1109\u1165\u11AB\u1100\u1165",
      "\u1109\u1165\u11AB\u1106\u116E\u11AF",
      "\u1109\u1165\u11AB\u1107\u1162",
      "\u1109\u1165\u11AB\u1109\u1162\u11BC",
      "\u1109\u1165\u11AB\u1109\u116E",
      "\u1109\u1165\u11AB\u110B\u116F\u11AB",
      "\u1109\u1165\u11AB\u110C\u1161\u11BC",
      "\u1109\u1165\u11AB\u110C\u1165\u11AB",
      "\u1109\u1165\u11AB\u1110\u1162\u11A8",
      "\u1109\u1165\u11AB\u1111\u116E\u11BC\u1100\u1175",
      "\u1109\u1165\u11AF\u1100\u1165\u110C\u1175",
      "\u1109\u1165\u11AF\u1102\u1161\u11AF",
      "\u1109\u1165\u11AF\u1105\u1165\u11BC\u1110\u1161\u11BC",
      "\u1109\u1165\u11AF\u1106\u1167\u11BC",
      "\u1109\u1165\u11AF\u1106\u116E\u11AB",
      "\u1109\u1165\u11AF\u1109\u1161",
      "\u1109\u1165\u11AF\u110B\u1161\u11A8\u1109\u1161\u11AB",
      "\u1109\u1165\u11AF\u110E\u1175",
      "\u1109\u1165\u11AF\u1110\u1161\u11BC",
      "\u1109\u1165\u11B8\u110A\u1175",
      "\u1109\u1165\u11BC\u1100\u1169\u11BC",
      "\u1109\u1165\u11BC\u1103\u1161\u11BC",
      "\u1109\u1165\u11BC\u1106\u1167\u11BC",
      "\u1109\u1165\u11BC\u1107\u1167\u11AF",
      "\u1109\u1165\u11BC\u110B\u1175\u11AB",
      "\u1109\u1165\u11BC\u110C\u1161\u11BC",
      "\u1109\u1165\u11BC\u110C\u1165\u11A8",
      "\u1109\u1165\u11BC\u110C\u1175\u11AF",
      "\u1109\u1165\u11BC\u1112\u1161\u11B7",
      "\u1109\u1166\u1100\u1173\u11B7",
      "\u1109\u1166\u1106\u1175\u1102\u1161",
      "\u1109\u1166\u1109\u1161\u11BC",
      "\u1109\u1166\u110B\u116F\u11AF",
      "\u1109\u1166\u110C\u1169\u11BC\u1103\u1162\u110B\u116A\u11BC",
      "\u1109\u1166\u1110\u1161\u11A8",
      "\u1109\u1166\u11AB\u1110\u1165",
      "\u1109\u1166\u11AB\u1110\u1175\u1106\u1175\u1110\u1165",
      "\u1109\u1166\u11BA\u110D\u1162",
      "\u1109\u1169\u1100\u1172\u1106\u1169",
      "\u1109\u1169\u1100\u1173\u11A8\u110C\u1165\u11A8",
      "\u1109\u1169\u1100\u1173\u11B7",
      "\u1109\u1169\u1102\u1161\u1100\u1175",
      "\u1109\u1169\u1102\u1167\u11AB",
      "\u1109\u1169\u1103\u1173\u11A8",
      "\u1109\u1169\u1106\u1161\u11BC",
      "\u1109\u1169\u1106\u116E\u11AB",
      "\u1109\u1169\u1109\u1165\u11AF",
      "\u1109\u1169\u1109\u1169\u11A8",
      "\u1109\u1169\u110B\u1161\u1100\u116A",
      "\u1109\u1169\u110B\u116D\u11BC",
      "\u1109\u1169\u110B\u116F\u11AB",
      "\u1109\u1169\u110B\u1173\u11B7",
      "\u1109\u1169\u110C\u116E\u11BC\u1112\u1175",
      "\u1109\u1169\u110C\u1175\u1111\u116E\u11B7",
      "\u1109\u1169\u110C\u1175\u11AF",
      "\u1109\u1169\u1111\u116E\u11BC",
      "\u1109\u1169\u1112\u1167\u11BC",
      "\u1109\u1169\u11A8\u1103\u1161\u11B7",
      "\u1109\u1169\u11A8\u1103\u1169",
      "\u1109\u1169\u11A8\u110B\u1169\u11BA",
      "\u1109\u1169\u11AB\u1100\u1161\u1105\u1161\u11A8",
      "\u1109\u1169\u11AB\u1100\u1175\u11AF",
      "\u1109\u1169\u11AB\u1102\u1167",
      "\u1109\u1169\u11AB\u1102\u1175\u11B7",
      "\u1109\u1169\u11AB\u1103\u1173\u11BC",
      "\u1109\u1169\u11AB\u1106\u1169\u11A8",
      "\u1109\u1169\u11AB\u1108\u1167\u11A8",
      "\u1109\u1169\u11AB\u1109\u1175\u11AF",
      "\u1109\u1169\u11AB\u110C\u1175\u11AF",
      "\u1109\u1169\u11AB\u1110\u1169\u11B8",
      "\u1109\u1169\u11AB\u1112\u1162",
      "\u1109\u1169\u11AF\u110C\u1175\u11A8\u1112\u1175",
      "\u1109\u1169\u11B7\u110A\u1175",
      "\u1109\u1169\u11BC\u110B\u1161\u110C\u1175",
      "\u1109\u1169\u11BC\u110B\u1175",
      "\u1109\u1169\u11BC\u1111\u1167\u11AB",
      "\u1109\u116C\u1100\u1169\u1100\u1175",
      "\u1109\u116D\u1111\u1175\u11BC",
      "\u1109\u116E\u1100\u1165\u11AB",
      "\u1109\u116E\u1102\u1167\u11AB",
      "\u1109\u116E\u1103\u1161\u11AB",
      "\u1109\u116E\u1103\u1169\u11BA\u1106\u116E\u11AF",
      "\u1109\u116E\u1103\u1169\u11BC\u110C\u1165\u11A8",
      "\u1109\u116E\u1106\u1167\u11AB",
      "\u1109\u116E\u1106\u1167\u11BC",
      "\u1109\u116E\u1107\u1161\u11A8",
      "\u1109\u116E\u1109\u1161\u11BC",
      "\u1109\u116E\u1109\u1165\u11A8",
      "\u1109\u116E\u1109\u116E\u11AF",
      "\u1109\u116E\u1109\u1175\u1105\u1169",
      "\u1109\u116E\u110B\u1165\u11B8",
      "\u1109\u116E\u110B\u1167\u11B7",
      "\u1109\u116E\u110B\u1167\u11BC",
      "\u1109\u116E\u110B\u1175\u11B8",
      "\u1109\u116E\u110C\u116E\u11AB",
      "\u1109\u116E\u110C\u1175\u11B8",
      "\u1109\u116E\u110E\u116E\u11AF",
      "\u1109\u116E\u110F\u1165\u11BA",
      "\u1109\u116E\u1111\u1175\u11AF",
      "\u1109\u116E\u1112\u1161\u11A8",
      "\u1109\u116E\u1112\u1165\u11B7\u1109\u1162\u11BC",
      "\u1109\u116E\u1112\u116A\u1100\u1175",
      "\u1109\u116E\u11A8\u1102\u1167",
      "\u1109\u116E\u11A8\u1109\u1169",
      "\u1109\u116E\u11A8\u110C\u1166",
      "\u1109\u116E\u11AB\u1100\u1161\u11AB",
      "\u1109\u116E\u11AB\u1109\u1165",
      "\u1109\u116E\u11AB\u1109\u116E",
      "\u1109\u116E\u11AB\u1109\u1175\u11A8\u1100\u1161\u11AB",
      "\u1109\u116E\u11AB\u110B\u1171",
      "\u1109\u116E\u11AE\u1100\u1161\u1105\u1161\u11A8",
      "\u1109\u116E\u11AF\u1107\u1167\u11BC",
      "\u1109\u116E\u11AF\u110C\u1175\u11B8",
      "\u1109\u116E\u11BA\u110C\u1161",
      "\u1109\u1173\u1102\u1175\u11B7",
      "\u1109\u1173\u1106\u116E\u11AF",
      "\u1109\u1173\u1109\u1173\u1105\u1169",
      "\u1109\u1173\u1109\u1173\u11BC",
      "\u1109\u1173\u110B\u1170\u1110\u1165",
      "\u1109\u1173\u110B\u1171\u110E\u1175",
      "\u1109\u1173\u110F\u1166\u110B\u1175\u1110\u1173",
      "\u1109\u1173\u1110\u1172\u1103\u1175\u110B\u1169",
      "\u1109\u1173\u1110\u1173\u1105\u1166\u1109\u1173",
      "\u1109\u1173\u1111\u1169\u110E\u1173",
      "\u1109\u1173\u11AF\u110D\u1165\u11A8",
      "\u1109\u1173\u11AF\u1111\u1173\u11B7",
      "\u1109\u1173\u11B8\u1100\u116A\u11AB",
      "\u1109\u1173\u11B8\u1100\u1175",
      "\u1109\u1173\u11BC\u1100\u1162\u11A8",
      "\u1109\u1173\u11BC\u1105\u1175",
      "\u1109\u1173\u11BC\u1107\u116E",
      "\u1109\u1173\u11BC\u110B\u116D\u11BC\u110E\u1161",
      "\u1109\u1173\u11BC\u110C\u1175\u11AB",
      "\u1109\u1175\u1100\u1161\u11A8",
      "\u1109\u1175\u1100\u1161\u11AB",
      "\u1109\u1175\u1100\u1169\u11AF",
      "\u1109\u1175\u1100\u1173\u11B7\u110E\u1175",
      "\u1109\u1175\u1102\u1161\u1105\u1175\u110B\u1169",
      "\u1109\u1175\u1103\u1162\u11A8",
      "\u1109\u1175\u1105\u1175\u110C\u1173",
      "\u1109\u1175\u1106\u1166\u11AB\u1110\u1173",
      "\u1109\u1175\u1106\u1175\u11AB",
      "\u1109\u1175\u1107\u116E\u1106\u1169",
      "\u1109\u1175\u1109\u1165\u11AB",
      "\u1109\u1175\u1109\u1165\u11AF",
      "\u1109\u1175\u1109\u1173\u1110\u1166\u11B7",
      "\u1109\u1175\u110B\u1161\u1107\u1165\u110C\u1175",
      "\u1109\u1175\u110B\u1165\u1106\u1165\u1102\u1175",
      "\u1109\u1175\u110B\u116F\u11AF",
      "\u1109\u1175\u110B\u1175\u11AB",
      "\u1109\u1175\u110B\u1175\u11AF",
      "\u1109\u1175\u110C\u1161\u11A8",
      "\u1109\u1175\u110C\u1161\u11BC",
      "\u1109\u1175\u110C\u1165\u11AF",
      "\u1109\u1175\u110C\u1165\u11B7",
      "\u1109\u1175\u110C\u116E\u11BC",
      "\u1109\u1175\u110C\u1173\u11AB",
      "\u1109\u1175\u110C\u1175\u11B8",
      "\u1109\u1175\u110E\u1165\u11BC",
      "\u1109\u1175\u1112\u1161\u11B8",
      "\u1109\u1175\u1112\u1165\u11B7",
      "\u1109\u1175\u11A8\u1100\u116E",
      "\u1109\u1175\u11A8\u1100\u1175",
      "\u1109\u1175\u11A8\u1103\u1161\u11BC",
      "\u1109\u1175\u11A8\u1105\u1163\u11BC",
      "\u1109\u1175\u11A8\u1105\u116D\u1111\u116E\u11B7",
      "\u1109\u1175\u11A8\u1106\u116E\u11AF",
      "\u1109\u1175\u11A8\u1108\u1161\u11BC",
      "\u1109\u1175\u11A8\u1109\u1161",
      "\u1109\u1175\u11A8\u1109\u1162\u11BC\u1112\u116A\u11AF",
      "\u1109\u1175\u11A8\u110E\u1169",
      "\u1109\u1175\u11A8\u1110\u1161\u11A8",
      "\u1109\u1175\u11A8\u1111\u116E\u11B7",
      "\u1109\u1175\u11AB\u1100\u1169",
      "\u1109\u1175\u11AB\u1100\u1172",
      "\u1109\u1175\u11AB\u1102\u1167\u11B7",
      "\u1109\u1175\u11AB\u1106\u116E\u11AB",
      "\u1109\u1175\u11AB\u1107\u1161\u11AF",
      "\u1109\u1175\u11AB\u1107\u1175",
      "\u1109\u1175\u11AB\u1109\u1161",
      "\u1109\u1175\u11AB\u1109\u1166",
      "\u1109\u1175\u11AB\u110B\u116D\u11BC",
      "\u1109\u1175\u11AB\u110C\u1166\u1111\u116E\u11B7",
      "\u1109\u1175\u11AB\u110E\u1165\u11BC",
      "\u1109\u1175\u11AB\u110E\u1166",
      "\u1109\u1175\u11AB\u1112\u116A",
      "\u1109\u1175\u11AF\u1100\u1161\u11B7",
      "\u1109\u1175\u11AF\u1102\u1162",
      "\u1109\u1175\u11AF\u1105\u1167\u11A8",
      "\u1109\u1175\u11AF\u1105\u1168",
      "\u1109\u1175\u11AF\u1106\u1161\u11BC",
      "\u1109\u1175\u11AF\u1109\u116E",
      "\u1109\u1175\u11AF\u1109\u1173\u11B8",
      "\u1109\u1175\u11AF\u1109\u1175",
      "\u1109\u1175\u11AF\u110C\u1161\u11BC",
      "\u1109\u1175\u11AF\u110C\u1165\u11BC",
      "\u1109\u1175\u11AF\u110C\u1175\u11AF\u110C\u1165\u11A8",
      "\u1109\u1175\u11AF\u110E\u1165\u11AB",
      "\u1109\u1175\u11AF\u110E\u1166",
      "\u1109\u1175\u11AF\u110F\u1165\u11BA",
      "\u1109\u1175\u11AF\u1110\u1162",
      "\u1109\u1175\u11AF\u1111\u1162",
      "\u1109\u1175\u11AF\u1112\u1165\u11B7",
      "\u1109\u1175\u11AF\u1112\u1167\u11AB",
      "\u1109\u1175\u11B7\u1105\u1175",
      "\u1109\u1175\u11B7\u1107\u116E\u1105\u1173\u11B7",
      "\u1109\u1175\u11B7\u1109\u1161",
      "\u1109\u1175\u11B7\u110C\u1161\u11BC",
      "\u1109\u1175\u11B7\u110C\u1165\u11BC",
      "\u1109\u1175\u11B7\u1111\u1161\u11AB",
      "\u110A\u1161\u11BC\u1103\u116E\u11BC\u110B\u1175",
      "\u110A\u1175\u1105\u1173\u11B7",
      "\u110A\u1175\u110B\u1161\u11BA",
      "\u110B\u1161\u1100\u1161\u110A\u1175",
      "\u110B\u1161\u1102\u1161\u110B\u116E\u11AB\u1109\u1165",
      "\u110B\u1161\u1103\u1173\u1102\u1175\u11B7",
      "\u110B\u1161\u1103\u1173\u11AF",
      "\u110B\u1161\u1109\u1171\u110B\u116E\u11B7",
      "\u110B\u1161\u1109\u1173\u1111\u1161\u11AF\u1110\u1173",
      "\u110B\u1161\u1109\u1175\u110B\u1161",
      "\u110B\u1161\u110B\u116E\u11AF\u1105\u1165",
      "\u110B\u1161\u110C\u1165\u110A\u1175",
      "\u110B\u1161\u110C\u116E\u11B7\u1106\u1161",
      "\u110B\u1161\u110C\u1175\u11A8",
      "\u110B\u1161\u110E\u1175\u11B7",
      "\u110B\u1161\u1111\u1161\u1110\u1173",
      "\u110B\u1161\u1111\u1173\u1105\u1175\u110F\u1161",
      "\u110B\u1161\u1111\u1173\u11B7",
      "\u110B\u1161\u1112\u1169\u11B8",
      "\u110B\u1161\u1112\u1173\u11AB",
      "\u110B\u1161\u11A8\u1100\u1175",
      "\u110B\u1161\u11A8\u1106\u1169\u11BC",
      "\u110B\u1161\u11A8\u1109\u116E",
      "\u110B\u1161\u11AB\u1100\u1162",
      "\u110B\u1161\u11AB\u1100\u1167\u11BC",
      "\u110B\u1161\u11AB\u1100\u116A",
      "\u110B\u1161\u11AB\u1102\u1162",
      "\u110B\u1161\u11AB\u1102\u1167\u11BC",
      "\u110B\u1161\u11AB\u1103\u1169\u11BC",
      "\u110B\u1161\u11AB\u1107\u1161\u11BC",
      "\u110B\u1161\u11AB\u1107\u116E",
      "\u110B\u1161\u11AB\u110C\u116E",
      "\u110B\u1161\u11AF\u1105\u116E\u1106\u1175\u1102\u1172\u11B7",
      "\u110B\u1161\u11AF\u110F\u1169\u110B\u1169\u11AF",
      "\u110B\u1161\u11B7\u1109\u1175",
      "\u110B\u1161\u11B7\u110F\u1165\u11BA",
      "\u110B\u1161\u11B8\u1105\u1167\u11A8",
      "\u110B\u1161\u11C1\u1102\u1161\u11AF",
      "\u110B\u1161\u11C1\u1106\u116E\u11AB",
      "\u110B\u1162\u110B\u1175\u11AB",
      "\u110B\u1162\u110C\u1165\u11BC",
      "\u110B\u1162\u11A8\u1109\u116E",
      "\u110B\u1162\u11AF\u1107\u1165\u11B7",
      "\u110B\u1163\u1100\u1161\u11AB",
      "\u110B\u1163\u1103\u1161\u11AB",
      "\u110B\u1163\u110B\u1169\u11BC",
      "\u110B\u1163\u11A8\u1100\u1161\u11AB",
      "\u110B\u1163\u11A8\u1100\u116E\u11A8",
      "\u110B\u1163\u11A8\u1109\u1169\u11A8",
      "\u110B\u1163\u11A8\u1109\u116E",
      "\u110B\u1163\u11A8\u110C\u1165\u11B7",
      "\u110B\u1163\u11A8\u1111\u116E\u11B7",
      "\u110B\u1163\u11A8\u1112\u1169\u11AB\u1102\u1167",
      "\u110B\u1163\u11BC\u1102\u1167\u11B7",
      "\u110B\u1163\u11BC\u1105\u1167\u11A8",
      "\u110B\u1163\u11BC\u1106\u1161\u11AF",
      "\u110B\u1163\u11BC\u1107\u1162\u110E\u116E",
      "\u110B\u1163\u11BC\u110C\u116E",
      "\u110B\u1163\u11BC\u1111\u1161",
      "\u110B\u1165\u1103\u116E\u11B7",
      "\u110B\u1165\u1105\u1167\u110B\u116E\u11B7",
      "\u110B\u1165\u1105\u1173\u11AB",
      "\u110B\u1165\u110C\u1166\u11BA\u1107\u1161\u11B7",
      "\u110B\u1165\u110D\u1162\u11BB\u1103\u1173\u11AB",
      "\u110B\u1165\u110D\u1165\u1103\u1161\u1100\u1161",
      "\u110B\u1165\u110D\u1165\u11AB\u110C\u1175",
      "\u110B\u1165\u11AB\u1102\u1175",
      "\u110B\u1165\u11AB\u1103\u1165\u11A8",
      "\u110B\u1165\u11AB\u1105\u1169\u11AB",
      "\u110B\u1165\u11AB\u110B\u1165",
      "\u110B\u1165\u11AF\u1100\u116E\u11AF",
      "\u110B\u1165\u11AF\u1105\u1173\u11AB",
      "\u110B\u1165\u11AF\u110B\u1173\u11B7",
      "\u110B\u1165\u11AF\u1111\u1175\u11BA",
      "\u110B\u1165\u11B7\u1106\u1161",
      "\u110B\u1165\u11B8\u1106\u116E",
      "\u110B\u1165\u11B8\u110C\u1169\u11BC",
      "\u110B\u1165\u11B8\u110E\u1166",
      "\u110B\u1165\u11BC\u1103\u1165\u11BC\u110B\u1175",
      "\u110B\u1165\u11BC\u1106\u1161\u11BC",
      "\u110B\u1165\u11BC\u1110\u1165\u1105\u1175",
      "\u110B\u1165\u11BD\u1100\u1173\u110C\u1166",
      "\u110B\u1166\u1102\u1165\u110C\u1175",
      "\u110B\u1166\u110B\u1165\u110F\u1165\u11AB",
      "\u110B\u1166\u11AB\u110C\u1175\u11AB",
      "\u110B\u1167\u1100\u1165\u11AB",
      "\u110B\u1167\u1100\u1169\u1109\u1162\u11BC",
      "\u110B\u1167\u1100\u116A\u11AB",
      "\u110B\u1167\u1100\u116E\u11AB",
      "\u110B\u1167\u1100\u116F\u11AB",
      "\u110B\u1167\u1103\u1162\u1109\u1162\u11BC",
      "\u110B\u1167\u1103\u1165\u11B2",
      "\u110B\u1167\u1103\u1169\u11BC\u1109\u1162\u11BC",
      "\u110B\u1167\u1103\u1173\u11AB",
      "\u110B\u1167\u1105\u1169\u11AB",
      "\u110B\u1167\u1105\u1173\u11B7",
      "\u110B\u1167\u1109\u1165\u11BA",
      "\u110B\u1167\u1109\u1165\u11BC",
      "\u110B\u1167\u110B\u116A\u11BC",
      "\u110B\u1167\u110B\u1175\u11AB",
      "\u110B\u1167\u110C\u1165\u11AB\u1112\u1175",
      "\u110B\u1167\u110C\u1175\u11A8\u110B\u116F\u11AB",
      "\u110B\u1167\u1112\u1161\u11A8\u1109\u1162\u11BC",
      "\u110B\u1167\u1112\u1162\u11BC",
      "\u110B\u1167\u11A8\u1109\u1161",
      "\u110B\u1167\u11A8\u1109\u1175",
      "\u110B\u1167\u11A8\u1112\u1161\u11AF",
      "\u110B\u1167\u11AB\u1100\u1167\u11AF",
      "\u110B\u1167\u11AB\u1100\u116E",
      "\u110B\u1167\u11AB\u1100\u1173\u11A8",
      "\u110B\u1167\u11AB\u1100\u1175",
      "\u110B\u1167\u11AB\u1105\u1161\u11A8",
      "\u110B\u1167\u11AB\u1109\u1165\u11AF",
      "\u110B\u1167\u11AB\u1109\u1166",
      "\u110B\u1167\u11AB\u1109\u1169\u11A8",
      "\u110B\u1167\u11AB\u1109\u1173\u11B8",
      "\u110B\u1167\u11AB\u110B\u1162",
      "\u110B\u1167\u11AB\u110B\u1168\u110B\u1175\u11AB",
      "\u110B\u1167\u11AB\u110B\u1175\u11AB",
      "\u110B\u1167\u11AB\u110C\u1161\u11BC",
      "\u110B\u1167\u11AB\u110C\u116E",
      "\u110B\u1167\u11AB\u110E\u116E\u11AF",
      "\u110B\u1167\u11AB\u1111\u1175\u11AF",
      "\u110B\u1167\u11AB\u1112\u1161\u11B8",
      "\u110B\u1167\u11AB\u1112\u1172",
      "\u110B\u1167\u11AF\u1100\u1175",
      "\u110B\u1167\u11AF\u1106\u1162",
      "\u110B\u1167\u11AF\u1109\u116C",
      "\u110B\u1167\u11AF\u1109\u1175\u11B7\u1112\u1175",
      "\u110B\u1167\u11AF\u110C\u1165\u11BC",
      "\u110B\u1167\u11AF\u110E\u1161",
      "\u110B\u1167\u11AF\u1112\u1173\u11AF",
      "\u110B\u1167\u11B7\u1105\u1167",
      "\u110B\u1167\u11B8\u1109\u1165",
      "\u110B\u1167\u11BC\u1100\u116E\u11A8",
      "\u110B\u1167\u11BC\u1102\u1161\u11B7",
      "\u110B\u1167\u11BC\u1109\u1161\u11BC",
      "\u110B\u1167\u11BC\u110B\u1163\u11BC",
      "\u110B\u1167\u11BC\u110B\u1167\u11A8",
      "\u110B\u1167\u11BC\u110B\u116E\u11BC",
      "\u110B\u1167\u11BC\u110B\u116F\u11AB\u1112\u1175",
      "\u110B\u1167\u11BC\u1112\u1161",
      "\u110B\u1167\u11BC\u1112\u1163\u11BC",
      "\u110B\u1167\u11BC\u1112\u1169\u11AB",
      "\u110B\u1167\u11BC\u1112\u116A",
      "\u110B\u1167\u11C1\u1100\u116E\u1105\u1175",
      "\u110B\u1167\u11C1\u1107\u1161\u11BC",
      "\u110B\u1167\u11C1\u110C\u1175\u11B8",
      "\u110B\u1168\u1100\u1161\u11B7",
      "\u110B\u1168\u1100\u1173\u11B7",
      "\u110B\u1168\u1107\u1161\u11BC",
      "\u110B\u1168\u1109\u1161\u11AB",
      "\u110B\u1168\u1109\u1161\u11BC",
      "\u110B\u1168\u1109\u1165\u11AB",
      "\u110B\u1168\u1109\u116E\u11AF",
      "\u110B\u1168\u1109\u1173\u11B8",
      "\u110B\u1168\u1109\u1175\u11A8\u110C\u1161\u11BC",
      "\u110B\u1168\u110B\u1163\u11A8",
      "\u110B\u1168\u110C\u1165\u11AB",
      "\u110B\u1168\u110C\u1165\u11AF",
      "\u110B\u1168\u110C\u1165\u11BC",
      "\u110B\u1168\u110F\u1165\u11AB\u1103\u1162",
      "\u110B\u1168\u11BA\u1102\u1161\u11AF",
      "\u110B\u1169\u1102\u1173\u11AF",
      "\u110B\u1169\u1105\u1161\u11A8",
      "\u110B\u1169\u1105\u1162\u11BA\u1103\u1169\u11BC\u110B\u1161\u11AB",
      "\u110B\u1169\u1105\u1166\u11AB\u110C\u1175",
      "\u110B\u1169\u1105\u1169\u110C\u1175",
      "\u110B\u1169\u1105\u1173\u11AB\u1107\u1161\u11AF",
      "\u110B\u1169\u1107\u1173\u11AB",
      "\u110B\u1169\u1109\u1175\u11B8",
      "\u110B\u1169\u110B\u1167\u11B7",
      "\u110B\u1169\u110B\u116F\u11AF",
      "\u110B\u1169\u110C\u1165\u11AB",
      "\u110B\u1169\u110C\u1175\u11A8",
      "\u110B\u1169\u110C\u1175\u11BC\u110B\u1165",
      "\u110B\u1169\u1111\u1166\u1105\u1161",
      "\u110B\u1169\u1111\u1175\u1109\u1173\u1110\u1166\u11AF",
      "\u110B\u1169\u1112\u1175\u1105\u1167",
      "\u110B\u1169\u11A8\u1109\u1161\u11BC",
      "\u110B\u1169\u11A8\u1109\u116E\u1109\u116E",
      "\u110B\u1169\u11AB\u1100\u1161\u11BD",
      "\u110B\u1169\u11AB\u1105\u1161\u110B\u1175\u11AB",
      "\u110B\u1169\u11AB\u1106\u1169\u11B7",
      "\u110B\u1169\u11AB\u110C\u1169\u11BC\u110B\u1175\u11AF",
      "\u110B\u1169\u11AB\u1110\u1169\u11BC",
      "\u110B\u1169\u11AF\u1100\u1161\u110B\u1173\u11AF",
      "\u110B\u1169\u11AF\u1105\u1175\u11B7\u1111\u1175\u11A8",
      "\u110B\u1169\u11AF\u1112\u1162",
      "\u110B\u1169\u11BA\u110E\u1161\u1105\u1175\u11B7",
      "\u110B\u116A\u110B\u1175\u1109\u1167\u110E\u1173",
      "\u110B\u116A\u110B\u1175\u11AB",
      "\u110B\u116A\u11AB\u1109\u1165\u11BC",
      "\u110B\u116A\u11AB\u110C\u1165\u11AB",
      "\u110B\u116A\u11BC\u1107\u1175",
      "\u110B\u116A\u11BC\u110C\u1161",
      "\u110B\u116B\u1102\u1163\u1112\u1161\u1106\u1167\u11AB",
      "\u110B\u116B\u11AB\u110C\u1175",
      "\u110B\u116C\u1100\u1161\u11BA\u110C\u1175\u11B8",
      "\u110B\u116C\u1100\u116E\u11A8",
      "\u110B\u116C\u1105\u1169\u110B\u116E\u11B7",
      "\u110B\u116C\u1109\u1161\u11B7\u110E\u1169\u11AB",
      "\u110B\u116C\u110E\u116E\u11AF",
      "\u110B\u116C\u110E\u1175\u11B7",
      "\u110B\u116C\u1112\u1161\u11AF\u1106\u1165\u1102\u1175",
      "\u110B\u116C\u11AB\u1107\u1161\u11AF",
      "\u110B\u116C\u11AB\u1109\u1169\u11AB",
      "\u110B\u116C\u11AB\u110D\u1169\u11A8",
      "\u110B\u116D\u1100\u1173\u11B7",
      "\u110B\u116D\u110B\u1175\u11AF",
      "\u110B\u116D\u110C\u1173\u11B7",
      "\u110B\u116D\u110E\u1165\u11BC",
      "\u110B\u116D\u11BC\u1100\u1175",
      "\u110B\u116D\u11BC\u1109\u1165",
      "\u110B\u116D\u11BC\u110B\u1165",
      "\u110B\u116E\u1109\u1161\u11AB",
      "\u110B\u116E\u1109\u1165\u11AB",
      "\u110B\u116E\u1109\u1173\u11BC",
      "\u110B\u116E\u110B\u1167\u11AB\u1112\u1175",
      "\u110B\u116E\u110C\u1165\u11BC",
      "\u110B\u116E\u110E\u1166\u1100\u116E\u11A8",
      "\u110B\u116E\u1111\u1167\u11AB",
      "\u110B\u116E\u11AB\u1103\u1169\u11BC",
      "\u110B\u116E\u11AB\u1106\u1167\u11BC",
      "\u110B\u116E\u11AB\u1107\u1161\u11AB",
      "\u110B\u116E\u11AB\u110C\u1165\u11AB",
      "\u110B\u116E\u11AB\u1112\u1162\u11BC",
      "\u110B\u116E\u11AF\u1109\u1161\u11AB",
      "\u110B\u116E\u11AF\u110B\u1173\u11B7",
      "\u110B\u116E\u11B7\u110C\u1175\u11A8\u110B\u1175\u11B7",
      "\u110B\u116E\u11BA\u110B\u1165\u1105\u1173\u11AB",
      "\u110B\u116E\u11BA\u110B\u1173\u11B7",
      "\u110B\u116F\u1102\u1161\u11A8",
      "\u110B\u116F\u11AB\u1100\u1169",
      "\u110B\u116F\u11AB\u1105\u1162",
      "\u110B\u116F\u11AB\u1109\u1165",
      "\u110B\u116F\u11AB\u1109\u116E\u11BC\u110B\u1175",
      "\u110B\u116F\u11AB\u110B\u1175\u11AB",
      "\u110B\u116F\u11AB\u110C\u1161\u11BC",
      "\u110B\u116F\u11AB\u1111\u1175\u1109\u1173",
      "\u110B\u116F\u11AF\u1100\u1173\u11B8",
      "\u110B\u116F\u11AF\u1103\u1173\u110F\u1165\u11B8",
      "\u110B\u116F\u11AF\u1109\u1166",
      "\u110B\u116F\u11AF\u110B\u116D\u110B\u1175\u11AF",
      "\u110B\u1170\u110B\u1175\u1110\u1165",
      "\u110B\u1171\u1107\u1161\u11AB",
      "\u110B\u1171\u1107\u1165\u11B8",
      "\u110B\u1171\u1109\u1165\u11BC",
      "\u110B\u1171\u110B\u116F\u11AB",
      "\u110B\u1171\u1112\u1165\u11B7",
      "\u110B\u1171\u1112\u1167\u11B8",
      "\u110B\u1171\u11BA\u1109\u1161\u1105\u1161\u11B7",
      "\u110B\u1172\u1102\u1161\u11AB\u1112\u1175",
      "\u110B\u1172\u1105\u1165\u11B8",
      "\u110B\u1172\u1106\u1167\u11BC",
      "\u110B\u1172\u1106\u116E\u11AF",
      "\u110B\u1172\u1109\u1161\u11AB",
      "\u110B\u1172\u110C\u1165\u11A8",
      "\u110B\u1172\u110E\u1175\u110B\u116F\u11AB",
      "\u110B\u1172\u1112\u1161\u11A8",
      "\u110B\u1172\u1112\u1162\u11BC",
      "\u110B\u1172\u1112\u1167\u11BC",
      "\u110B\u1172\u11A8\u1100\u116E\u11AB",
      "\u110B\u1172\u11A8\u1109\u1161\u11BC",
      "\u110B\u1172\u11A8\u1109\u1175\u11B8",
      "\u110B\u1172\u11A8\u110E\u1166",
      "\u110B\u1173\u11AB\u1112\u1162\u11BC",
      "\u110B\u1173\u11B7\u1105\u1167\u11A8",
      "\u110B\u1173\u11B7\u1105\u116D",
      "\u110B\u1173\u11B7\u1107\u1161\u11AB",
      "\u110B\u1173\u11B7\u1109\u1165\u11BC",
      "\u110B\u1173\u11B7\u1109\u1175\u11A8",
      "\u110B\u1173\u11B7\u110B\u1161\u11A8",
      "\u110B\u1173\u11B7\u110C\u116E",
      "\u110B\u1174\u1100\u1167\u11AB",
      "\u110B\u1174\u1102\u1169\u11AB",
      "\u110B\u1174\u1106\u116E\u11AB",
      "\u110B\u1174\u1107\u1169\u11A8",
      "\u110B\u1174\u1109\u1175\u11A8",
      "\u110B\u1174\u1109\u1175\u11B7",
      "\u110B\u1174\u110B\u116C\u1105\u1169",
      "\u110B\u1174\u110B\u116D\u11A8",
      "\u110B\u1174\u110B\u116F\u11AB",
      "\u110B\u1174\u1112\u1161\u11A8",
      "\u110B\u1175\u1100\u1165\u11BA",
      "\u110B\u1175\u1100\u1169\u11BA",
      "\u110B\u1175\u1102\u1167\u11B7",
      "\u110B\u1175\u1102\u1169\u11B7",
      "\u110B\u1175\u1103\u1161\u11AF",
      "\u110B\u1175\u1103\u1162\u1105\u1169",
      "\u110B\u1175\u1103\u1169\u11BC",
      "\u110B\u1175\u1105\u1165\u11C2\u1100\u1166",
      "\u110B\u1175\u1105\u1167\u11A8\u1109\u1165",
      "\u110B\u1175\u1105\u1169\u11AB\u110C\u1165\u11A8",
      "\u110B\u1175\u1105\u1173\u11B7",
      "\u110B\u1175\u1106\u1175\u11AB",
      "\u110B\u1175\u1107\u1161\u11AF\u1109\u1169",
      "\u110B\u1175\u1107\u1167\u11AF",
      "\u110B\u1175\u1107\u116E\u11AF",
      "\u110B\u1175\u1108\u1161\u11AF",
      "\u110B\u1175\u1109\u1161\u11BC",
      "\u110B\u1175\u1109\u1165\u11BC",
      "\u110B\u1175\u1109\u1173\u11AF",
      "\u110B\u1175\u110B\u1163\u1100\u1175",
      "\u110B\u1175\u110B\u116D\u11BC",
      "\u110B\u1175\u110B\u116E\u11BA",
      "\u110B\u1175\u110B\u116F\u11AF",
      "\u110B\u1175\u110B\u1173\u11A8\u1100\u1169",
      "\u110B\u1175\u110B\u1175\u11A8",
      "\u110B\u1175\u110C\u1165\u11AB",
      "\u110B\u1175\u110C\u116E\u11BC",
      "\u110B\u1175\u1110\u1173\u11AE\u1102\u1161\u11AF",
      "\u110B\u1175\u1110\u1173\u11AF",
      "\u110B\u1175\u1112\u1169\u11AB",
      "\u110B\u1175\u11AB\u1100\u1161\u11AB",
      "\u110B\u1175\u11AB\u1100\u1167\u11A8",
      "\u110B\u1175\u11AB\u1100\u1169\u11BC",
      "\u110B\u1175\u11AB\u1100\u116E",
      "\u110B\u1175\u11AB\u1100\u1173\u11AB",
      "\u110B\u1175\u11AB\u1100\u1175",
      "\u110B\u1175\u11AB\u1103\u1169",
      "\u110B\u1175\u11AB\u1105\u1172",
      "\u110B\u1175\u11AB\u1106\u116E\u11AF",
      "\u110B\u1175\u11AB\u1109\u1162\u11BC",
      "\u110B\u1175\u11AB\u1109\u116B",
      "\u110B\u1175\u11AB\u110B\u1167\u11AB",
      "\u110B\u1175\u11AB\u110B\u116F\u11AB",
      "\u110B\u1175\u11AB\u110C\u1162",
      "\u110B\u1175\u11AB\u110C\u1169\u11BC",
      "\u110B\u1175\u11AB\u110E\u1165\u11AB",
      "\u110B\u1175\u11AB\u110E\u1166",
      "\u110B\u1175\u11AB\u1110\u1165\u1102\u1166\u11BA",
      "\u110B\u1175\u11AB\u1112\u1161",
      "\u110B\u1175\u11AB\u1112\u1167\u11BC",
      "\u110B\u1175\u11AF\u1100\u1169\u11B8",
      "\u110B\u1175\u11AF\u1100\u1175",
      "\u110B\u1175\u11AF\u1103\u1161\u11AB",
      "\u110B\u1175\u11AF\u1103\u1162",
      "\u110B\u1175\u11AF\u1103\u1173\u11BC",
      "\u110B\u1175\u11AF\u1107\u1161\u11AB",
      "\u110B\u1175\u11AF\u1107\u1169\u11AB",
      "\u110B\u1175\u11AF\u1107\u116E",
      "\u110B\u1175\u11AF\u1109\u1161\u11BC",
      "\u110B\u1175\u11AF\u1109\u1162\u11BC",
      "\u110B\u1175\u11AF\u1109\u1169\u11AB",
      "\u110B\u1175\u11AF\u110B\u116D\u110B\u1175\u11AF",
      "\u110B\u1175\u11AF\u110B\u116F\u11AF",
      "\u110B\u1175\u11AF\u110C\u1165\u11BC",
      "\u110B\u1175\u11AF\u110C\u1169\u11BC",
      "\u110B\u1175\u11AF\u110C\u116E\u110B\u1175\u11AF",
      "\u110B\u1175\u11AF\u110D\u1175\u11A8",
      "\u110B\u1175\u11AF\u110E\u1166",
      "\u110B\u1175\u11AF\u110E\u1175",
      "\u110B\u1175\u11AF\u1112\u1162\u11BC",
      "\u110B\u1175\u11AF\u1112\u116C\u110B\u116D\u11BC",
      "\u110B\u1175\u11B7\u1100\u1173\u11B7",
      "\u110B\u1175\u11B7\u1106\u116E",
      "\u110B\u1175\u11B8\u1103\u1162",
      "\u110B\u1175\u11B8\u1105\u1167\u11A8",
      "\u110B\u1175\u11B8\u1106\u1161\u11BA",
      "\u110B\u1175\u11B8\u1109\u1161",
      "\u110B\u1175\u11B8\u1109\u116E\u11AF",
      "\u110B\u1175\u11B8\u1109\u1175",
      "\u110B\u1175\u11B8\u110B\u116F\u11AB",
      "\u110B\u1175\u11B8\u110C\u1161\u11BC",
      "\u110B\u1175\u11B8\u1112\u1161\u11A8",
      "\u110C\u1161\u1100\u1161\u110B\u116D\u11BC",
      "\u110C\u1161\u1100\u1167\u11A8",
      "\u110C\u1161\u1100\u1173\u11A8",
      "\u110C\u1161\u1103\u1169\u11BC",
      "\u110C\u1161\u1105\u1161\u11BC",
      "\u110C\u1161\u1107\u116E\u1109\u1175\u11B7",
      "\u110C\u1161\u1109\u1175\u11A8",
      "\u110C\u1161\u1109\u1175\u11AB",
      "\u110C\u1161\u110B\u1167\u11AB",
      "\u110C\u1161\u110B\u116F\u11AB",
      "\u110C\u1161\u110B\u1172\u11AF",
      "\u110C\u1161\u110C\u1165\u11AB\u1100\u1165",
      "\u110C\u1161\u110C\u1165\u11BC",
      "\u110C\u1161\u110C\u1169\u11AB\u1109\u1175\u11B7",
      "\u110C\u1161\u1111\u1161\u11AB",
      "\u110C\u1161\u11A8\u1100\u1161",
      "\u110C\u1161\u11A8\u1102\u1167\u11AB",
      "\u110C\u1161\u11A8\u1109\u1165\u11BC",
      "\u110C\u1161\u11A8\u110B\u1165\u11B8",
      "\u110C\u1161\u11A8\u110B\u116D\u11BC",
      "\u110C\u1161\u11A8\u110B\u1173\u11AB\u1104\u1161\u11AF",
      "\u110C\u1161\u11A8\u1111\u116E\u11B7",
      "\u110C\u1161\u11AB\u1103\u1175",
      "\u110C\u1161\u11AB\u1104\u1173\u11A8",
      "\u110C\u1161\u11AB\u110E\u1175",
      "\u110C\u1161\u11AF\u1106\u1169\u11BA",
      "\u110C\u1161\u11B7\u1101\u1161\u11AB",
      "\u110C\u1161\u11B7\u1109\u116E\u1112\u1161\u11B7",
      "\u110C\u1161\u11B7\u1109\u1175",
      "\u110C\u1161\u11B7\u110B\u1169\u11BA",
      "\u110C\u1161\u11B7\u110C\u1161\u1105\u1175",
      "\u110C\u1161\u11B8\u110C\u1175",
      "\u110C\u1161\u11BC\u1100\u116A\u11AB",
      "\u110C\u1161\u11BC\u1100\u116E\u11AB",
      "\u110C\u1161\u11BC\u1100\u1175\u1100\u1161\u11AB",
      "\u110C\u1161\u11BC\u1105\u1162",
      "\u110C\u1161\u11BC\u1105\u1168",
      "\u110C\u1161\u11BC\u1105\u1173",
      "\u110C\u1161\u11BC\u1106\u1161",
      "\u110C\u1161\u11BC\u1106\u1167\u11AB",
      "\u110C\u1161\u11BC\u1106\u1169",
      "\u110C\u1161\u11BC\u1106\u1175",
      "\u110C\u1161\u11BC\u1107\u1175",
      "\u110C\u1161\u11BC\u1109\u1161",
      "\u110C\u1161\u11BC\u1109\u1169",
      "\u110C\u1161\u11BC\u1109\u1175\u11A8",
      "\u110C\u1161\u11BC\u110B\u1162\u110B\u1175\u11AB",
      "\u110C\u1161\u11BC\u110B\u1175\u11AB",
      "\u110C\u1161\u11BC\u110C\u1165\u11B7",
      "\u110C\u1161\u11BC\u110E\u1161",
      "\u110C\u1161\u11BC\u1112\u1161\u11A8\u1100\u1173\u11B7",
      "\u110C\u1162\u1102\u1173\u11BC",
      "\u110C\u1162\u1108\u1161\u11AF\u1105\u1175",
      "\u110C\u1162\u1109\u1161\u11AB",
      "\u110C\u1162\u1109\u1162\u11BC",
      "\u110C\u1162\u110C\u1161\u11A8\u1102\u1167\u11AB",
      "\u110C\u1162\u110C\u1165\u11BC",
      "\u110C\u1162\u110E\u1162\u1100\u1175",
      "\u110C\u1162\u1111\u1161\u11AB",
      "\u110C\u1162\u1112\u1161\u11A8",
      "\u110C\u1162\u1112\u116A\u11AF\u110B\u116D\u11BC",
      "\u110C\u1165\u1100\u1165\u11BA",
      "\u110C\u1165\u1100\u1169\u1105\u1175",
      "\u110C\u1165\u1100\u1169\u11BA",
      "\u110C\u1165\u1102\u1167\u11A8",
      "\u110C\u1165\u1105\u1165\u11AB",
      "\u110C\u1165\u1105\u1165\u11C2\u1100\u1166",
      "\u110C\u1165\u1107\u1165\u11AB",
      "\u110C\u1165\u110B\u116E\u11AF",
      "\u110C\u1165\u110C\u1165\u11AF\u1105\u1169",
      "\u110C\u1165\u110E\u116E\u11A8",
      "\u110C\u1165\u11A8\u1100\u1173\u11A8",
      "\u110C\u1165\u11A8\u1103\u1161\u11BC\u1112\u1175",
      "\u110C\u1165\u11A8\u1109\u1165\u11BC",
      "\u110C\u1165\u11A8\u110B\u116D\u11BC",
      "\u110C\u1165\u11A8\u110B\u1173\u11BC",
      "\u110C\u1165\u11AB\u1100\u1162",
      "\u110C\u1165\u11AB\u1100\u1169\u11BC",
      "\u110C\u1165\u11AB\u1100\u1175",
      "\u110C\u1165\u11AB\u1103\u1161\u11AF",
      "\u110C\u1165\u11AB\u1105\u1161\u1103\u1169",
      "\u110C\u1165\u11AB\u1106\u1161\u11BC",
      "\u110C\u1165\u11AB\u1106\u116E\u11AB",
      "\u110C\u1165\u11AB\u1107\u1161\u11AB",
      "\u110C\u1165\u11AB\u1107\u116E",
      "\u110C\u1165\u11AB\u1109\u1166",
      "\u110C\u1165\u11AB\u1109\u1175",
      "\u110C\u1165\u11AB\u110B\u116D\u11BC",
      "\u110C\u1165\u11AB\u110C\u1161",
      "\u110C\u1165\u11AB\u110C\u1162\u11BC",
      "\u110C\u1165\u11AB\u110C\u116E",
      "\u110C\u1165\u11AB\u110E\u1165\u11AF",
      "\u110C\u1165\u11AB\u110E\u1166",
      "\u110C\u1165\u11AB\u1110\u1169\u11BC",
      "\u110C\u1165\u11AB\u1112\u1167",
      "\u110C\u1165\u11AB\u1112\u116E",
      "\u110C\u1165\u11AF\u1103\u1162",
      "\u110C\u1165\u11AF\u1106\u1161\u11BC",
      "\u110C\u1165\u11AF\u1107\u1161\u11AB",
      "\u110C\u1165\u11AF\u110B\u1163\u11A8",
      "\u110C\u1165\u11AF\u110E\u1161",
      "\u110C\u1165\u11B7\u1100\u1165\u11B7",
      "\u110C\u1165\u11B7\u1109\u116E",
      "\u110C\u1165\u11B7\u1109\u1175\u11B7",
      "\u110C\u1165\u11B7\u110B\u116F\u11AB",
      "\u110C\u1165\u11B7\u110C\u1165\u11B7",
      "\u110C\u1165\u11B7\u110E\u1161",
      "\u110C\u1165\u11B8\u1100\u1173\u11AB",
      "\u110C\u1165\u11B8\u1109\u1175",
      "\u110C\u1165\u11B8\u110E\u1169\u11A8",
      "\u110C\u1165\u11BA\u1100\u1161\u1105\u1161\u11A8",
      "\u110C\u1165\u11BC\u1100\u1165\u110C\u1161\u11BC",
      "\u110C\u1165\u11BC\u1103\u1169",
      "\u110C\u1165\u11BC\u1105\u1172\u110C\u1161\u11BC",
      "\u110C\u1165\u11BC\u1105\u1175",
      "\u110C\u1165\u11BC\u1106\u1161\u11AF",
      "\u110C\u1165\u11BC\u1106\u1167\u11AB",
      "\u110C\u1165\u11BC\u1106\u116E\u11AB",
      "\u110C\u1165\u11BC\u1107\u1161\u11AB\u1103\u1162",
      "\u110C\u1165\u11BC\u1107\u1169",
      "\u110C\u1165\u11BC\u1107\u116E",
      "\u110C\u1165\u11BC\u1107\u1175",
      "\u110C\u1165\u11BC\u1109\u1161\u11BC",
      "\u110C\u1165\u11BC\u1109\u1165\u11BC",
      "\u110C\u1165\u11BC\u110B\u1169",
      "\u110C\u1165\u11BC\u110B\u116F\u11AB",
      "\u110C\u1165\u11BC\u110C\u1161\u11BC",
      "\u110C\u1165\u11BC\u110C\u1175",
      "\u110C\u1165\u11BC\u110E\u1175",
      "\u110C\u1165\u11BC\u1112\u116A\u11A8\u1112\u1175",
      "\u110C\u1166\u1100\u1169\u11BC",
      "\u110C\u1166\u1100\u116A\u110C\u1165\u11B7",
      "\u110C\u1166\u1103\u1162\u1105\u1169",
      "\u110C\u1166\u1106\u1169\u11A8",
      "\u110C\u1166\u1107\u1161\u11AF",
      "\u110C\u1166\u1107\u1165\u11B8",
      "\u110C\u1166\u1109\u1161\u11BA\u1102\u1161\u11AF",
      "\u110C\u1166\u110B\u1161\u11AB",
      "\u110C\u1166\u110B\u1175\u11AF",
      "\u110C\u1166\u110C\u1161\u11A8",
      "\u110C\u1166\u110C\u116E\u1103\u1169",
      "\u110C\u1166\u110E\u116E\u11AF",
      "\u110C\u1166\u1111\u116E\u11B7",
      "\u110C\u1166\u1112\u1161\u11AB",
      "\u110C\u1169\u1100\u1161\u11A8",
      "\u110C\u1169\u1100\u1165\u11AB",
      "\u110C\u1169\u1100\u1173\u11B7",
      "\u110C\u1169\u1100\u1175\u11BC",
      "\u110C\u1169\u1106\u1167\u11BC",
      "\u110C\u1169\u1106\u1175\u1105\u116D",
      "\u110C\u1169\u1109\u1161\u11BC",
      "\u110C\u1169\u1109\u1165\u11AB",
      "\u110C\u1169\u110B\u116D\u11BC\u1112\u1175",
      "\u110C\u1169\u110C\u1165\u11AF",
      "\u110C\u1169\u110C\u1165\u11BC",
      "\u110C\u1169\u110C\u1175\u11A8",
      "\u110C\u1169\u11AB\u1103\u1162\u11BA\u1106\u1161\u11AF",
      "\u110C\u1169\u11AB\u110C\u1162",
      "\u110C\u1169\u11AF\u110B\u1165\u11B8",
      "\u110C\u1169\u11AF\u110B\u1173\u11B7",
      "\u110C\u1169\u11BC\u1100\u116D",
      "\u110C\u1169\u11BC\u1105\u1169",
      "\u110C\u1169\u11BC\u1105\u1172",
      "\u110C\u1169\u11BC\u1109\u1169\u1105\u1175",
      "\u110C\u1169\u11BC\u110B\u1165\u11B8\u110B\u116F\u11AB",
      "\u110C\u1169\u11BC\u110C\u1169\u11BC",
      "\u110C\u1169\u11BC\u1112\u1161\u11B8",
      "\u110C\u116A\u1109\u1165\u11A8",
      "\u110C\u116C\u110B\u1175\u11AB",
      "\u110C\u116E\u1100\u116A\u11AB\u110C\u1165\u11A8",
      "\u110C\u116E\u1105\u1173\u11B7",
      "\u110C\u116E\u1106\u1161\u11AF",
      "\u110C\u116E\u1106\u1165\u1102\u1175",
      "\u110C\u116E\u1106\u1165\u11A8",
      "\u110C\u116E\u1106\u116E\u11AB",
      "\u110C\u116E\u1106\u1175\u11AB",
      "\u110C\u116E\u1107\u1161\u11BC",
      "\u110C\u116E\u1107\u1167\u11AB",
      "\u110C\u116E\u1109\u1175\u11A8",
      "\u110C\u116E\u110B\u1175\u11AB",
      "\u110C\u116E\u110B\u1175\u11AF",
      "\u110C\u116E\u110C\u1161\u11BC",
      "\u110C\u116E\u110C\u1165\u11AB\u110C\u1161",
      "\u110C\u116E\u1110\u1162\u11A8",
      "\u110C\u116E\u11AB\u1107\u1175",
      "\u110C\u116E\u11AF\u1100\u1165\u1105\u1175",
      "\u110C\u116E\u11AF\u1100\u1175",
      "\u110C\u116E\u11AF\u1106\u116E\u1102\u1174",
      "\u110C\u116E\u11BC\u1100\u1161\u11AB",
      "\u110C\u116E\u11BC\u1100\u1168\u1107\u1161\u11BC\u1109\u1169\u11BC",
      "\u110C\u116E\u11BC\u1100\u116E\u11A8",
      "\u110C\u116E\u11BC\u1102\u1167\u11AB",
      "\u110C\u116E\u11BC\u1103\u1161\u11AB",
      "\u110C\u116E\u11BC\u1103\u1169\u11A8",
      "\u110C\u116E\u11BC\u1107\u1161\u11AB",
      "\u110C\u116E\u11BC\u1107\u116E",
      "\u110C\u116E\u11BC\u1109\u1166",
      "\u110C\u116E\u11BC\u1109\u1169\u1100\u1175\u110B\u1165\u11B8",
      "\u110C\u116E\u11BC\u1109\u116E\u11AB",
      "\u110C\u116E\u11BC\u110B\u1161\u11BC",
      "\u110C\u116E\u11BC\u110B\u116D",
      "\u110C\u116E\u11BC\u1112\u1161\u11A8\u1100\u116D",
      "\u110C\u1173\u11A8\u1109\u1165\u11A8",
      "\u110C\u1173\u11A8\u1109\u1175",
      "\u110C\u1173\u11AF\u1100\u1165\u110B\u116E\u11B7",
      "\u110C\u1173\u11BC\u1100\u1161",
      "\u110C\u1173\u11BC\u1100\u1165",
      "\u110C\u1173\u11BC\u1100\u116F\u11AB",
      "\u110C\u1173\u11BC\u1109\u1161\u11BC",
      "\u110C\u1173\u11BC\u1109\u1166",
      "\u110C\u1175\u1100\u1161\u11A8",
      "\u110C\u1175\u1100\u1161\u11B8",
      "\u110C\u1175\u1100\u1167\u11BC",
      "\u110C\u1175\u1100\u1173\u11A8\u1112\u1175",
      "\u110C\u1175\u1100\u1173\u11B7",
      "\u110C\u1175\u1100\u1173\u11B8",
      "\u110C\u1175\u1102\u1173\u11BC",
      "\u110C\u1175\u1105\u1173\u11B7\u1100\u1175\u11AF",
      "\u110C\u1175\u1105\u1175\u1109\u1161\u11AB",
      "\u110C\u1175\u1107\u1161\u11BC",
      "\u110C\u1175\u1107\u116E\u11BC",
      "\u110C\u1175\u1109\u1175\u11A8",
      "\u110C\u1175\u110B\u1167\u11A8",
      "\u110C\u1175\u110B\u116E\u1100\u1162",
      "\u110C\u1175\u110B\u116F\u11AB",
      "\u110C\u1175\u110C\u1165\u11A8",
      "\u110C\u1175\u110C\u1165\u11B7",
      "\u110C\u1175\u110C\u1175\u11AB",
      "\u110C\u1175\u110E\u116E\u11AF",
      "\u110C\u1175\u11A8\u1109\u1165\u11AB",
      "\u110C\u1175\u11A8\u110B\u1165\u11B8",
      "\u110C\u1175\u11A8\u110B\u116F\u11AB",
      "\u110C\u1175\u11A8\u110C\u1161\u11BC",
      "\u110C\u1175\u11AB\u1100\u1173\u11B8",
      "\u110C\u1175\u11AB\u1103\u1169\u11BC",
      "\u110C\u1175\u11AB\u1105\u1169",
      "\u110C\u1175\u11AB\u1105\u116D",
      "\u110C\u1175\u11AB\u1105\u1175",
      "\u110C\u1175\u11AB\u110D\u1161",
      "\u110C\u1175\u11AB\u110E\u1161\u11AF",
      "\u110C\u1175\u11AB\u110E\u116E\u11AF",
      "\u110C\u1175\u11AB\u1110\u1169\u11BC",
      "\u110C\u1175\u11AB\u1112\u1162\u11BC",
      "\u110C\u1175\u11AF\u1106\u116E\u11AB",
      "\u110C\u1175\u11AF\u1107\u1167\u11BC",
      "\u110C\u1175\u11AF\u1109\u1165",
      "\u110C\u1175\u11B7\u110C\u1161\u11A8",
      "\u110C\u1175\u11B8\u1103\u1161\u11AB",
      "\u110C\u1175\u11B8\u110B\u1161\u11AB",
      "\u110C\u1175\u11B8\u110C\u116E\u11BC",
      "\u110D\u1161\u110C\u1173\u11BC",
      "\u110D\u1175\u1101\u1165\u1100\u1175",
      "\u110E\u1161\u1102\u1161\u11B7",
      "\u110E\u1161\u1105\u1161\u1105\u1175",
      "\u110E\u1161\u1105\u1163\u11BC",
      "\u110E\u1161\u1105\u1175\u11B7",
      "\u110E\u1161\u1107\u1167\u11AF",
      "\u110E\u1161\u1109\u1165\u11AB",
      "\u110E\u1161\u110E\u1173\u11B7",
      "\u110E\u1161\u11A8\u1100\u1161\u11A8",
      "\u110E\u1161\u11AB\u1106\u116E\u11AF",
      "\u110E\u1161\u11AB\u1109\u1165\u11BC",
      "\u110E\u1161\u11B7\u1100\u1161",
      "\u110E\u1161\u11B7\u1100\u1175\u1105\u1173\u11B7",
      "\u110E\u1161\u11B7\u1109\u1162",
      "\u110E\u1161\u11B7\u1109\u1165\u11A8",
      "\u110E\u1161\u11B7\u110B\u1167",
      "\u110E\u1161\u11B7\u110B\u116C",
      "\u110E\u1161\u11B7\u110C\u1169",
      "\u110E\u1161\u11BA\u110C\u1161\u11AB",
      "\u110E\u1161\u11BC\u1100\u1161",
      "\u110E\u1161\u11BC\u1100\u1169",
      "\u110E\u1161\u11BC\u1100\u116E",
      "\u110E\u1161\u11BC\u1106\u116E\u11AB",
      "\u110E\u1161\u11BC\u1107\u1161\u11A9",
      "\u110E\u1161\u11BC\u110C\u1161\u11A8",
      "\u110E\u1161\u11BC\u110C\u1169",
      "\u110E\u1162\u1102\u1165\u11AF",
      "\u110E\u1162\u110C\u1165\u11B7",
      "\u110E\u1162\u11A8\u1100\u1161\u1107\u1161\u11BC",
      "\u110E\u1162\u11A8\u1107\u1161\u11BC",
      "\u110E\u1162\u11A8\u1109\u1161\u11BC",
      "\u110E\u1162\u11A8\u110B\u1175\u11B7",
      "\u110E\u1162\u11B7\u1111\u1175\u110B\u1165\u11AB",
      "\u110E\u1165\u1107\u1165\u11AF",
      "\u110E\u1165\u110B\u1173\u11B7",
      "\u110E\u1165\u11AB\u1100\u116E\u11A8",
      "\u110E\u1165\u11AB\u1103\u116E\u11BC",
      "\u110E\u1165\u11AB\u110C\u1161\u11BC",
      "\u110E\u1165\u11AB\u110C\u1162",
      "\u110E\u1165\u11AB\u110E\u1165\u11AB\u1112\u1175",
      "\u110E\u1165\u11AF\u1103\u1169",
      "\u110E\u1165\u11AF\u110C\u1165\u1112\u1175",
      "\u110E\u1165\u11AF\u1112\u1161\u11A8",
      "\u110E\u1165\u11BA\u1102\u1161\u11AF",
      "\u110E\u1165\u11BA\u110D\u1162",
      "\u110E\u1165\u11BC\u1102\u1167\u11AB",
      "\u110E\u1165\u11BC\u1107\u1161\u110C\u1175",
      "\u110E\u1165\u11BC\u1109\u1169",
      "\u110E\u1165\u11BC\u110E\u116E\u11AB",
      "\u110E\u1166\u1100\u1168",
      "\u110E\u1166\u1105\u1167\u11A8",
      "\u110E\u1166\u110B\u1169\u11AB",
      "\u110E\u1166\u110B\u1172\u11A8",
      "\u110E\u1166\u110C\u116E\u11BC",
      "\u110E\u1166\u1112\u1165\u11B7",
      "\u110E\u1169\u1103\u1173\u11BC\u1112\u1161\u11A8\u1109\u1162\u11BC",
      "\u110E\u1169\u1107\u1161\u11AB",
      "\u110E\u1169\u1107\u1161\u11B8",
      "\u110E\u1169\u1109\u1161\u11BC\u1112\u116A",
      "\u110E\u1169\u1109\u116E\u11AB",
      "\u110E\u1169\u110B\u1167\u1105\u1173\u11B7",
      "\u110E\u1169\u110B\u116F\u11AB",
      "\u110E\u1169\u110C\u1165\u1102\u1167\u11A8",
      "\u110E\u1169\u110C\u1165\u11B7",
      "\u110E\u1169\u110E\u1165\u11BC",
      "\u110E\u1169\u110F\u1169\u11AF\u1105\u1175\u11BA",
      "\u110E\u1169\u11BA\u1107\u116E\u11AF",
      "\u110E\u1169\u11BC\u1100\u1161\u11A8",
      "\u110E\u1169\u11BC\u1105\u1175",
      "\u110E\u1169\u11BC\u110C\u1161\u11BC",
      "\u110E\u116A\u11AF\u110B\u1167\u11BC",
      "\u110E\u116C\u1100\u1173\u11AB",
      "\u110E\u116C\u1109\u1161\u11BC",
      "\u110E\u116C\u1109\u1165\u11AB",
      "\u110E\u116C\u1109\u1175\u11AB",
      "\u110E\u116C\u110B\u1161\u11A8",
      "\u110E\u116C\u110C\u1169\u11BC",
      "\u110E\u116E\u1109\u1165\u11A8",
      "\u110E\u116E\u110B\u1165\u11A8",
      "\u110E\u116E\u110C\u1175\u11AB",
      "\u110E\u116E\u110E\u1165\u11AB",
      "\u110E\u116E\u110E\u1173\u11A8",
      "\u110E\u116E\u11A8\u1100\u116E",
      "\u110E\u116E\u11A8\u1109\u1169",
      "\u110E\u116E\u11A8\u110C\u1166",
      "\u110E\u116E\u11A8\u1112\u1161",
      "\u110E\u116E\u11AF\u1100\u1173\u11AB",
      "\u110E\u116E\u11AF\u1107\u1161\u11AF",
      "\u110E\u116E\u11AF\u1109\u1161\u11AB",
      "\u110E\u116E\u11AF\u1109\u1175\u11AB",
      "\u110E\u116E\u11AF\u110B\u1167\u11AB",
      "\u110E\u116E\u11AF\u110B\u1175\u11B8",
      "\u110E\u116E\u11AF\u110C\u1161\u11BC",
      "\u110E\u116E\u11AF\u1111\u1161\u11AB",
      "\u110E\u116E\u11BC\u1100\u1167\u11A8",
      "\u110E\u116E\u11BC\u1100\u1169",
      "\u110E\u116E\u11BC\u1103\u1169\u11AF",
      "\u110E\u116E\u11BC\u1107\u116E\u11AB\u1112\u1175",
      "\u110E\u116E\u11BC\u110E\u1165\u11BC\u1103\u1169",
      "\u110E\u1171\u110B\u1165\u11B8",
      "\u110E\u1171\u110C\u1175\u11A8",
      "\u110E\u1171\u1112\u1163\u11BC",
      "\u110E\u1175\u110B\u1163\u11A8",
      "\u110E\u1175\u11AB\u1100\u116E",
      "\u110E\u1175\u11AB\u110E\u1165\u11A8",
      "\u110E\u1175\u11AF\u1109\u1175\u11B8",
      "\u110E\u1175\u11AF\u110B\u116F\u11AF",
      "\u110E\u1175\u11AF\u1111\u1161\u11AB",
      "\u110E\u1175\u11B7\u1103\u1162",
      "\u110E\u1175\u11B7\u1106\u116E\u11A8",
      "\u110E\u1175\u11B7\u1109\u1175\u11AF",
      "\u110E\u1175\u11BA\u1109\u1169\u11AF",
      "\u110E\u1175\u11BC\u110E\u1161\u11AB",
      "\u110F\u1161\u1106\u1166\u1105\u1161",
      "\u110F\u1161\u110B\u116E\u11AB\u1110\u1165",
      "\u110F\u1161\u11AF\u1100\u116E\u11A8\u1109\u116E",
      "\u110F\u1162\u1105\u1175\u11A8\u1110\u1165",
      "\u110F\u1162\u11B7\u1111\u1165\u1109\u1173",
      "\u110F\u1162\u11B7\u1111\u1166\u110B\u1175\u11AB",
      "\u110F\u1165\u1110\u1173\u11AB",
      "\u110F\u1165\u11AB\u1103\u1175\u1109\u1167\u11AB",
      "\u110F\u1165\u11AF\u1105\u1165",
      "\u110F\u1165\u11B7\u1111\u1172\u1110\u1165",
      "\u110F\u1169\u1101\u1175\u1105\u1175",
      "\u110F\u1169\u1106\u1175\u1103\u1175",
      "\u110F\u1169\u11AB\u1109\u1165\u1110\u1173",
      "\u110F\u1169\u11AF\u1105\u1161",
      "\u110F\u1169\u11B7\u1111\u1173\u11AF\u1105\u1166\u11A8\u1109\u1173",
      "\u110F\u1169\u11BC\u1102\u1161\u1106\u116E\u11AF",
      "\u110F\u116B\u1100\u1161\u11B7",
      "\u110F\u116E\u1103\u1166\u1110\u1161",
      "\u110F\u1173\u1105\u1175\u11B7",
      "\u110F\u1173\u11AB\u1100\u1175\u11AF",
      "\u110F\u1173\u11AB\u1104\u1161\u11AF",
      "\u110F\u1173\u11AB\u1109\u1169\u1105\u1175",
      "\u110F\u1173\u11AB\u110B\u1161\u1103\u1173\u11AF",
      "\u110F\u1173\u11AB\u110B\u1165\u1106\u1165\u1102\u1175",
      "\u110F\u1173\u11AB\u110B\u1175\u11AF",
      "\u110F\u1173\u11AB\u110C\u1165\u11AF",
      "\u110F\u1173\u11AF\u1105\u1162\u1109\u1175\u11A8",
      "\u110F\u1173\u11AF\u1105\u1165\u11B8",
      "\u110F\u1175\u11AF\u1105\u1169",
      "\u1110\u1161\u110B\u1175\u11B8",
      "\u1110\u1161\u110C\u1161\u1100\u1175",
      "\u1110\u1161\u11A8\u1100\u116E",
      "\u1110\u1161\u11A8\u110C\u1161",
      "\u1110\u1161\u11AB\u1109\u1162\u11BC",
      "\u1110\u1162\u1100\u116F\u11AB\u1103\u1169",
      "\u1110\u1162\u110B\u1163\u11BC",
      "\u1110\u1162\u1111\u116E\u11BC",
      "\u1110\u1162\u11A8\u1109\u1175",
      "\u1110\u1162\u11AF\u1105\u1165\u11AB\u1110\u1173",
      "\u1110\u1165\u1102\u1165\u11AF",
      "\u1110\u1165\u1106\u1175\u1102\u1165\u11AF",
      "\u1110\u1166\u1102\u1175\u1109\u1173",
      "\u1110\u1166\u1109\u1173\u1110\u1173",
      "\u1110\u1166\u110B\u1175\u1107\u1173\u11AF",
      "\u1110\u1166\u11AF\u1105\u1166\u1107\u1175\u110C\u1165\u11AB",
      "\u1110\u1169\u1105\u1169\u11AB",
      "\u1110\u1169\u1106\u1161\u1110\u1169",
      "\u1110\u1169\u110B\u116D\u110B\u1175\u11AF",
      "\u1110\u1169\u11BC\u1100\u1168",
      "\u1110\u1169\u11BC\u1100\u116A",
      "\u1110\u1169\u11BC\u1105\u1169",
      "\u1110\u1169\u11BC\u1109\u1175\u11AB",
      "\u1110\u1169\u11BC\u110B\u1167\u11A8",
      "\u1110\u1169\u11BC\u110B\u1175\u11AF",
      "\u1110\u1169\u11BC\u110C\u1161\u11BC",
      "\u1110\u1169\u11BC\u110C\u1166",
      "\u1110\u1169\u11BC\u110C\u1173\u11BC",
      "\u1110\u1169\u11BC\u1112\u1161\u11B8",
      "\u1110\u1169\u11BC\u1112\u116A",
      "\u1110\u116C\u1100\u1173\u11AB",
      "\u1110\u116C\u110B\u116F\u11AB",
      "\u1110\u116C\u110C\u1175\u11A8\u1100\u1173\u11B7",
      "\u1110\u1171\u1100\u1175\u11B7",
      "\u1110\u1173\u1105\u1165\u11A8",
      "\u1110\u1173\u11A8\u1100\u1173\u11B8",
      "\u1110\u1173\u11A8\u1107\u1167\u11AF",
      "\u1110\u1173\u11A8\u1109\u1165\u11BC",
      "\u1110\u1173\u11A8\u1109\u116E",
      "\u1110\u1173\u11A8\u110C\u1175\u11BC",
      "\u1110\u1173\u11A8\u1112\u1175",
      "\u1110\u1173\u11AB\u1110\u1173\u11AB\u1112\u1175",
      "\u1110\u1175\u1109\u1167\u110E\u1173",
      "\u1111\u1161\u1105\u1161\u11AB\u1109\u1162\u11A8",
      "\u1111\u1161\u110B\u1175\u11AF",
      "\u1111\u1161\u110E\u116E\u11AF\u1109\u1169",
      "\u1111\u1161\u11AB\u1100\u1167\u11AF",
      "\u1111\u1161\u11AB\u1103\u1161\u11AB",
      "\u1111\u1161\u11AB\u1106\u1162",
      "\u1111\u1161\u11AB\u1109\u1161",
      "\u1111\u1161\u11AF\u1109\u1175\u11B8",
      "\u1111\u1161\u11AF\u110B\u116F\u11AF",
      "\u1111\u1161\u11B8\u1109\u1169\u11BC",
      "\u1111\u1162\u1109\u1167\u11AB",
      "\u1111\u1162\u11A8\u1109\u1173",
      "\u1111\u1162\u11A8\u1109\u1175\u1106\u1175\u11AF\u1105\u1175",
      "\u1111\u1162\u11AB\u1110\u1175",
      "\u1111\u1165\u1109\u1166\u11AB\u1110\u1173",
      "\u1111\u1166\u110B\u1175\u11AB\u1110\u1173",
      "\u1111\u1167\u11AB\u1100\u1167\u11AB",
      "\u1111\u1167\u11AB\u110B\u1174",
      "\u1111\u1167\u11AB\u110C\u1175",
      "\u1111\u1167\u11AB\u1112\u1175",
      "\u1111\u1167\u11BC\u1100\u1161",
      "\u1111\u1167\u11BC\u1100\u1172\u11AB",
      "\u1111\u1167\u11BC\u1109\u1162\u11BC",
      "\u1111\u1167\u11BC\u1109\u1169",
      "\u1111\u1167\u11BC\u110B\u1163\u11BC",
      "\u1111\u1167\u11BC\u110B\u1175\u11AF",
      "\u1111\u1167\u11BC\u1112\u116A",
      "\u1111\u1169\u1109\u1173\u1110\u1165",
      "\u1111\u1169\u110B\u1175\u11AB\u1110\u1173",
      "\u1111\u1169\u110C\u1161\u11BC",
      "\u1111\u1169\u1112\u1161\u11B7",
      "\u1111\u116D\u1106\u1167\u11AB",
      "\u1111\u116D\u110C\u1165\u11BC",
      "\u1111\u116D\u110C\u116E\u11AB",
      "\u1111\u116D\u1112\u1167\u11AB",
      "\u1111\u116E\u11B7\u1106\u1169\u11A8",
      "\u1111\u116E\u11B7\u110C\u1175\u11AF",
      "\u1111\u116E\u11BC\u1100\u1167\u11BC",
      "\u1111\u116E\u11BC\u1109\u1169\u11A8",
      "\u1111\u116E\u11BC\u1109\u1173\u11B8",
      "\u1111\u1173\u1105\u1161\u11BC\u1109\u1173",
      "\u1111\u1173\u1105\u1175\u11AB\u1110\u1165",
      "\u1111\u1173\u11AF\u1105\u1161\u1109\u1173\u1110\u1175\u11A8",
      "\u1111\u1175\u1100\u1169\u11AB",
      "\u1111\u1175\u1106\u1161\u11BC",
      "\u1111\u1175\u110B\u1161\u1102\u1169",
      "\u1111\u1175\u11AF\u1105\u1173\u11B7",
      "\u1111\u1175\u11AF\u1109\u116E",
      "\u1111\u1175\u11AF\u110B\u116D",
      "\u1111\u1175\u11AF\u110C\u1161",
      "\u1111\u1175\u11AF\u1110\u1169\u11BC",
      "\u1111\u1175\u11BC\u1100\u1168",
      "\u1112\u1161\u1102\u1173\u1102\u1175\u11B7",
      "\u1112\u1161\u1102\u1173\u11AF",
      "\u1112\u1161\u1103\u1173\u110B\u1170\u110B\u1165",
      "\u1112\u1161\u1105\u116E\u11BA\u1107\u1161\u11B7",
      "\u1112\u1161\u1107\u1161\u11AB\u1100\u1175",
      "\u1112\u1161\u1109\u116E\u11A8\u110C\u1175\u11B8",
      "\u1112\u1161\u1109\u116E\u11AB",
      "\u1112\u1161\u110B\u1167\u1110\u1173\u11AB",
      "\u1112\u1161\u110C\u1175\u1106\u1161\u11AB",
      "\u1112\u1161\u110E\u1165\u11AB",
      "\u1112\u1161\u1111\u116E\u11B7",
      "\u1112\u1161\u1111\u1175\u11AF",
      "\u1112\u1161\u11A8\u1100\u116A",
      "\u1112\u1161\u11A8\u1100\u116D",
      "\u1112\u1161\u11A8\u1100\u1173\u11B8",
      "\u1112\u1161\u11A8\u1100\u1175",
      "\u1112\u1161\u11A8\u1102\u1167\u11AB",
      "\u1112\u1161\u11A8\u1105\u1167\u11A8",
      "\u1112\u1161\u11A8\u1107\u1165\u11AB",
      "\u1112\u1161\u11A8\u1107\u116E\u1106\u1169",
      "\u1112\u1161\u11A8\u1107\u1175",
      "\u1112\u1161\u11A8\u1109\u1162\u11BC",
      "\u1112\u1161\u11A8\u1109\u116E\u11AF",
      "\u1112\u1161\u11A8\u1109\u1173\u11B8",
      "\u1112\u1161\u11A8\u110B\u116D\u11BC\u1111\u116E\u11B7",
      "\u1112\u1161\u11A8\u110B\u116F\u11AB",
      "\u1112\u1161\u11A8\u110B\u1171",
      "\u1112\u1161\u11A8\u110C\u1161",
      "\u1112\u1161\u11A8\u110C\u1165\u11B7",
      "\u1112\u1161\u11AB\u1100\u1168",
      "\u1112\u1161\u11AB\u1100\u1173\u11AF",
      "\u1112\u1161\u11AB\u1101\u1165\u1107\u1165\u11AB\u110B\u1166",
      "\u1112\u1161\u11AB\u1102\u1161\u11BD",
      "\u1112\u1161\u11AB\u1102\u116E\u11AB",
      "\u1112\u1161\u11AB\u1103\u1169\u11BC\u110B\u1161\u11AB",
      "\u1112\u1161\u11AB\u1104\u1162",
      "\u1112\u1161\u11AB\u1105\u1161\u1109\u1161\u11AB",
      "\u1112\u1161\u11AB\u1106\u1161\u1103\u1175",
      "\u1112\u1161\u11AB\u1106\u116E\u11AB",
      "\u1112\u1161\u11AB\u1107\u1165\u11AB",
      "\u1112\u1161\u11AB\u1107\u1169\u11A8",
      "\u1112\u1161\u11AB\u1109\u1175\u11A8",
      "\u1112\u1161\u11AB\u110B\u1167\u1105\u1173\u11B7",
      "\u1112\u1161\u11AB\u110D\u1169\u11A8",
      "\u1112\u1161\u11AF\u1106\u1165\u1102\u1175",
      "\u1112\u1161\u11AF\u110B\u1161\u1107\u1165\u110C\u1175",
      "\u1112\u1161\u11AF\u110B\u1175\u11AB",
      "\u1112\u1161\u11B7\u1101\u1166",
      "\u1112\u1161\u11B7\u1107\u116E\u1105\u1169",
      "\u1112\u1161\u11B8\u1100\u1167\u11A8",
      "\u1112\u1161\u11B8\u1105\u1175\u110C\u1165\u11A8",
      "\u1112\u1161\u11BC\u1100\u1169\u11BC",
      "\u1112\u1161\u11BC\u1100\u116E",
      "\u1112\u1161\u11BC\u1109\u1161\u11BC",
      "\u1112\u1161\u11BC\u110B\u1174",
      "\u1112\u1162\u1100\u1167\u11AF",
      "\u1112\u1162\u1100\u116E\u11AB",
      "\u1112\u1162\u1103\u1161\u11B8",
      "\u1112\u1162\u1103\u1161\u11BC",
      "\u1112\u1162\u1106\u116E\u11AF",
      "\u1112\u1162\u1109\u1165\u11A8",
      "\u1112\u1162\u1109\u1165\u11AF",
      "\u1112\u1162\u1109\u116E\u110B\u116D\u11A8\u110C\u1161\u11BC",
      "\u1112\u1162\u110B\u1161\u11AB",
      "\u1112\u1162\u11A8\u1109\u1175\u11B7",
      "\u1112\u1162\u11AB\u1103\u1173\u1107\u1162\u11A8",
      "\u1112\u1162\u11B7\u1107\u1165\u1100\u1165",
      "\u1112\u1162\u11BA\u1107\u1167\u11C0",
      "\u1112\u1162\u11BA\u1109\u1161\u11AF",
      "\u1112\u1162\u11BC\u1103\u1169\u11BC",
      "\u1112\u1162\u11BC\u1107\u1169\u11A8",
      "\u1112\u1162\u11BC\u1109\u1161",
      "\u1112\u1162\u11BC\u110B\u116E\u11AB",
      "\u1112\u1162\u11BC\u110B\u1171",
      "\u1112\u1163\u11BC\u1100\u1175",
      "\u1112\u1163\u11BC\u1109\u1161\u11BC",
      "\u1112\u1163\u11BC\u1109\u116E",
      "\u1112\u1165\u1105\u1161\u11A8",
      "\u1112\u1165\u110B\u116D\u11BC",
      "\u1112\u1166\u11AF\u1100\u1175",
      "\u1112\u1167\u11AB\u1100\u116A\u11AB",
      "\u1112\u1167\u11AB\u1100\u1173\u11B7",
      "\u1112\u1167\u11AB\u1103\u1162",
      "\u1112\u1167\u11AB\u1109\u1161\u11BC",
      "\u1112\u1167\u11AB\u1109\u1175\u11AF",
      "\u1112\u1167\u11AB\u110C\u1161\u11BC",
      "\u1112\u1167\u11AB\u110C\u1162",
      "\u1112\u1167\u11AB\u110C\u1175",
      "\u1112\u1167\u11AF\u110B\u1162\u11A8",
      "\u1112\u1167\u11B8\u1105\u1167\u11A8",
      "\u1112\u1167\u11BC\u1107\u116E",
      "\u1112\u1167\u11BC\u1109\u1161",
      "\u1112\u1167\u11BC\u1109\u116E",
      "\u1112\u1167\u11BC\u1109\u1175\u11A8",
      "\u1112\u1167\u11BC\u110C\u1166",
      "\u1112\u1167\u11BC\u1110\u1162",
      "\u1112\u1167\u11BC\u1111\u1167\u11AB",
      "\u1112\u1168\u1110\u1162\u11A8",
      "\u1112\u1169\u1100\u1175\u1109\u1175\u11B7",
      "\u1112\u1169\u1102\u1161\u11B7",
      "\u1112\u1169\u1105\u1161\u11BC\u110B\u1175",
      "\u1112\u1169\u1107\u1161\u11A8",
      "\u1112\u1169\u1110\u1166\u11AF",
      "\u1112\u1169\u1112\u1173\u11B8",
      "\u1112\u1169\u11A8\u1109\u1175",
      "\u1112\u1169\u11AF\u1105\u1169",
      "\u1112\u1169\u11B7\u1111\u1166\u110B\u1175\u110C\u1175",
      "\u1112\u1169\u11BC\u1107\u1169",
      "\u1112\u1169\u11BC\u1109\u116E",
      "\u1112\u1169\u11BC\u110E\u1161",
      "\u1112\u116A\u1106\u1167\u11AB",
      "\u1112\u116A\u1107\u116E\u11AB",
      "\u1112\u116A\u1109\u1161\u11AF",
      "\u1112\u116A\u110B\u116D\u110B\u1175\u11AF",
      "\u1112\u116A\u110C\u1161\u11BC",
      "\u1112\u116A\u1112\u1161\u11A8",
      "\u1112\u116A\u11A8\u1107\u1169",
      "\u1112\u116A\u11A8\u110B\u1175\u11AB",
      "\u1112\u116A\u11A8\u110C\u1161\u11BC",
      "\u1112\u116A\u11A8\u110C\u1165\u11BC",
      "\u1112\u116A\u11AB\u1100\u1161\u11B8",
      "\u1112\u116A\u11AB\u1100\u1167\u11BC",
      "\u1112\u116A\u11AB\u110B\u1167\u11BC",
      "\u1112\u116A\u11AB\u110B\u1172\u11AF",
      "\u1112\u116A\u11AB\u110C\u1161",
      "\u1112\u116A\u11AF\u1100\u1175",
      "\u1112\u116A\u11AF\u1103\u1169\u11BC",
      "\u1112\u116A\u11AF\u1107\u1161\u11AF\u1112\u1175",
      "\u1112\u116A\u11AF\u110B\u116D\u11BC",
      "\u1112\u116A\u11AF\u110D\u1161\u11A8",
      "\u1112\u116C\u1100\u1167\u11AB",
      "\u1112\u116C\u1100\u116A\u11AB",
      "\u1112\u116C\u1107\u1169\u11A8",
      "\u1112\u116C\u1109\u1162\u11A8",
      "\u1112\u116C\u110B\u116F\u11AB",
      "\u1112\u116C\u110C\u1161\u11BC",
      "\u1112\u116C\u110C\u1165\u11AB",
      "\u1112\u116C\u11BA\u1109\u116E",
      "\u1112\u116C\u11BC\u1103\u1161\u11AB\u1107\u1169\u1103\u1169",
      "\u1112\u116D\u110B\u1172\u11AF\u110C\u1165\u11A8",
      "\u1112\u116E\u1107\u1161\u11AB",
      "\u1112\u116E\u110E\u116E\u11BA\u1100\u1161\u1105\u116E",
      "\u1112\u116E\u11AB\u1105\u1167\u11AB",
      "\u1112\u116F\u11AF\u110A\u1175\u11AB",
      "\u1112\u1172\u1109\u1175\u11A8",
      "\u1112\u1172\u110B\u1175\u11AF",
      "\u1112\u1172\u11BC\u1102\u1162",
      "\u1112\u1173\u1105\u1173\u11B7",
      "\u1112\u1173\u11A8\u1107\u1162\u11A8",
      "\u1112\u1173\u11A8\u110B\u1175\u11AB",
      "\u1112\u1173\u11AB\u110C\u1165\u11A8",
      "\u1112\u1173\u11AB\u1112\u1175",
      "\u1112\u1173\u11BC\u1106\u1175",
      "\u1112\u1173\u11BC\u1107\u116E\u11AB",
      "\u1112\u1174\u1100\u1169\u11A8",
      "\u1112\u1174\u1106\u1161\u11BC",
      "\u1112\u1174\u1109\u1162\u11BC",
      "\u1112\u1174\u11AB\u1109\u1162\u11A8",
      "\u1112\u1175\u11B7\u1101\u1165\u11BA"
    ];
  }
});

// node_modules/bip39/src/wordlists/french.json
var require_french = __commonJS({
  "node_modules/bip39/src/wordlists/french.json"(exports, module) {
    module.exports = [
      "abaisser",
      "abandon",
      "abdiquer",
      "abeille",
      "abolir",
      "aborder",
      "aboutir",
      "aboyer",
      "abrasif",
      "abreuver",
      "abriter",
      "abroger",
      "abrupt",
      "absence",
      "absolu",
      "absurde",
      "abusif",
      "abyssal",
      "acade\u0301mie",
      "acajou",
      "acarien",
      "accabler",
      "accepter",
      "acclamer",
      "accolade",
      "accroche",
      "accuser",
      "acerbe",
      "achat",
      "acheter",
      "aciduler",
      "acier",
      "acompte",
      "acque\u0301rir",
      "acronyme",
      "acteur",
      "actif",
      "actuel",
      "adepte",
      "ade\u0301quat",
      "adhe\u0301sif",
      "adjectif",
      "adjuger",
      "admettre",
      "admirer",
      "adopter",
      "adorer",
      "adoucir",
      "adresse",
      "adroit",
      "adulte",
      "adverbe",
      "ae\u0301rer",
      "ae\u0301ronef",
      "affaire",
      "affecter",
      "affiche",
      "affreux",
      "affubler",
      "agacer",
      "agencer",
      "agile",
      "agiter",
      "agrafer",
      "agre\u0301able",
      "agrume",
      "aider",
      "aiguille",
      "ailier",
      "aimable",
      "aisance",
      "ajouter",
      "ajuster",
      "alarmer",
      "alchimie",
      "alerte",
      "alge\u0300bre",
      "algue",
      "alie\u0301ner",
      "aliment",
      "alle\u0301ger",
      "alliage",
      "allouer",
      "allumer",
      "alourdir",
      "alpaga",
      "altesse",
      "alve\u0301ole",
      "amateur",
      "ambigu",
      "ambre",
      "ame\u0301nager",
      "amertume",
      "amidon",
      "amiral",
      "amorcer",
      "amour",
      "amovible",
      "amphibie",
      "ampleur",
      "amusant",
      "analyse",
      "anaphore",
      "anarchie",
      "anatomie",
      "ancien",
      "ane\u0301antir",
      "angle",
      "angoisse",
      "anguleux",
      "animal",
      "annexer",
      "annonce",
      "annuel",
      "anodin",
      "anomalie",
      "anonyme",
      "anormal",
      "antenne",
      "antidote",
      "anxieux",
      "apaiser",
      "ape\u0301ritif",
      "aplanir",
      "apologie",
      "appareil",
      "appeler",
      "apporter",
      "appuyer",
      "aquarium",
      "aqueduc",
      "arbitre",
      "arbuste",
      "ardeur",
      "ardoise",
      "argent",
      "arlequin",
      "armature",
      "armement",
      "armoire",
      "armure",
      "arpenter",
      "arracher",
      "arriver",
      "arroser",
      "arsenic",
      "arte\u0301riel",
      "article",
      "aspect",
      "asphalte",
      "aspirer",
      "assaut",
      "asservir",
      "assiette",
      "associer",
      "assurer",
      "asticot",
      "astre",
      "astuce",
      "atelier",
      "atome",
      "atrium",
      "atroce",
      "attaque",
      "attentif",
      "attirer",
      "attraper",
      "aubaine",
      "auberge",
      "audace",
      "audible",
      "augurer",
      "aurore",
      "automne",
      "autruche",
      "avaler",
      "avancer",
      "avarice",
      "avenir",
      "averse",
      "aveugle",
      "aviateur",
      "avide",
      "avion",
      "aviser",
      "avoine",
      "avouer",
      "avril",
      "axial",
      "axiome",
      "badge",
      "bafouer",
      "bagage",
      "baguette",
      "baignade",
      "balancer",
      "balcon",
      "baleine",
      "balisage",
      "bambin",
      "bancaire",
      "bandage",
      "banlieue",
      "bannie\u0300re",
      "banquier",
      "barbier",
      "baril",
      "baron",
      "barque",
      "barrage",
      "bassin",
      "bastion",
      "bataille",
      "bateau",
      "batterie",
      "baudrier",
      "bavarder",
      "belette",
      "be\u0301lier",
      "belote",
      "be\u0301ne\u0301fice",
      "berceau",
      "berger",
      "berline",
      "bermuda",
      "besace",
      "besogne",
      "be\u0301tail",
      "beurre",
      "biberon",
      "bicycle",
      "bidule",
      "bijou",
      "bilan",
      "bilingue",
      "billard",
      "binaire",
      "biologie",
      "biopsie",
      "biotype",
      "biscuit",
      "bison",
      "bistouri",
      "bitume",
      "bizarre",
      "blafard",
      "blague",
      "blanchir",
      "blessant",
      "blinder",
      "blond",
      "bloquer",
      "blouson",
      "bobard",
      "bobine",
      "boire",
      "boiser",
      "bolide",
      "bonbon",
      "bondir",
      "bonheur",
      "bonifier",
      "bonus",
      "bordure",
      "borne",
      "botte",
      "boucle",
      "boueux",
      "bougie",
      "boulon",
      "bouquin",
      "bourse",
      "boussole",
      "boutique",
      "boxeur",
      "branche",
      "brasier",
      "brave",
      "brebis",
      "bre\u0300che",
      "breuvage",
      "bricoler",
      "brigade",
      "brillant",
      "brioche",
      "brique",
      "brochure",
      "broder",
      "bronzer",
      "brousse",
      "broyeur",
      "brume",
      "brusque",
      "brutal",
      "bruyant",
      "buffle",
      "buisson",
      "bulletin",
      "bureau",
      "burin",
      "bustier",
      "butiner",
      "butoir",
      "buvable",
      "buvette",
      "cabanon",
      "cabine",
      "cachette",
      "cadeau",
      "cadre",
      "cafe\u0301ine",
      "caillou",
      "caisson",
      "calculer",
      "calepin",
      "calibre",
      "calmer",
      "calomnie",
      "calvaire",
      "camarade",
      "came\u0301ra",
      "camion",
      "campagne",
      "canal",
      "caneton",
      "canon",
      "cantine",
      "canular",
      "capable",
      "caporal",
      "caprice",
      "capsule",
      "capter",
      "capuche",
      "carabine",
      "carbone",
      "caresser",
      "caribou",
      "carnage",
      "carotte",
      "carreau",
      "carton",
      "cascade",
      "casier",
      "casque",
      "cassure",
      "causer",
      "caution",
      "cavalier",
      "caverne",
      "caviar",
      "ce\u0301dille",
      "ceinture",
      "ce\u0301leste",
      "cellule",
      "cendrier",
      "censurer",
      "central",
      "cercle",
      "ce\u0301re\u0301bral",
      "cerise",
      "cerner",
      "cerveau",
      "cesser",
      "chagrin",
      "chaise",
      "chaleur",
      "chambre",
      "chance",
      "chapitre",
      "charbon",
      "chasseur",
      "chaton",
      "chausson",
      "chavirer",
      "chemise",
      "chenille",
      "che\u0301quier",
      "chercher",
      "cheval",
      "chien",
      "chiffre",
      "chignon",
      "chime\u0300re",
      "chiot",
      "chlorure",
      "chocolat",
      "choisir",
      "chose",
      "chouette",
      "chrome",
      "chute",
      "cigare",
      "cigogne",
      "cimenter",
      "cine\u0301ma",
      "cintrer",
      "circuler",
      "cirer",
      "cirque",
      "citerne",
      "citoyen",
      "citron",
      "civil",
      "clairon",
      "clameur",
      "claquer",
      "classe",
      "clavier",
      "client",
      "cligner",
      "climat",
      "clivage",
      "cloche",
      "clonage",
      "cloporte",
      "cobalt",
      "cobra",
      "cocasse",
      "cocotier",
      "coder",
      "codifier",
      "coffre",
      "cogner",
      "cohe\u0301sion",
      "coiffer",
      "coincer",
      "cole\u0300re",
      "colibri",
      "colline",
      "colmater",
      "colonel",
      "combat",
      "come\u0301die",
      "commande",
      "compact",
      "concert",
      "conduire",
      "confier",
      "congeler",
      "connoter",
      "consonne",
      "contact",
      "convexe",
      "copain",
      "copie",
      "corail",
      "corbeau",
      "cordage",
      "corniche",
      "corpus",
      "correct",
      "corte\u0300ge",
      "cosmique",
      "costume",
      "coton",
      "coude",
      "coupure",
      "courage",
      "couteau",
      "couvrir",
      "coyote",
      "crabe",
      "crainte",
      "cravate",
      "crayon",
      "cre\u0301ature",
      "cre\u0301diter",
      "cre\u0301meux",
      "creuser",
      "crevette",
      "cribler",
      "crier",
      "cristal",
      "crite\u0300re",
      "croire",
      "croquer",
      "crotale",
      "crucial",
      "cruel",
      "crypter",
      "cubique",
      "cueillir",
      "cuille\u0300re",
      "cuisine",
      "cuivre",
      "culminer",
      "cultiver",
      "cumuler",
      "cupide",
      "curatif",
      "curseur",
      "cyanure",
      "cycle",
      "cylindre",
      "cynique",
      "daigner",
      "damier",
      "danger",
      "danseur",
      "dauphin",
      "de\u0301battre",
      "de\u0301biter",
      "de\u0301border",
      "de\u0301brider",
      "de\u0301butant",
      "de\u0301caler",
      "de\u0301cembre",
      "de\u0301chirer",
      "de\u0301cider",
      "de\u0301clarer",
      "de\u0301corer",
      "de\u0301crire",
      "de\u0301cupler",
      "de\u0301dale",
      "de\u0301ductif",
      "de\u0301esse",
      "de\u0301fensif",
      "de\u0301filer",
      "de\u0301frayer",
      "de\u0301gager",
      "de\u0301givrer",
      "de\u0301glutir",
      "de\u0301grafer",
      "de\u0301jeuner",
      "de\u0301lice",
      "de\u0301loger",
      "demander",
      "demeurer",
      "de\u0301molir",
      "de\u0301nicher",
      "de\u0301nouer",
      "dentelle",
      "de\u0301nuder",
      "de\u0301part",
      "de\u0301penser",
      "de\u0301phaser",
      "de\u0301placer",
      "de\u0301poser",
      "de\u0301ranger",
      "de\u0301rober",
      "de\u0301sastre",
      "descente",
      "de\u0301sert",
      "de\u0301signer",
      "de\u0301sobe\u0301ir",
      "dessiner",
      "destrier",
      "de\u0301tacher",
      "de\u0301tester",
      "de\u0301tourer",
      "de\u0301tresse",
      "devancer",
      "devenir",
      "deviner",
      "devoir",
      "diable",
      "dialogue",
      "diamant",
      "dicter",
      "diffe\u0301rer",
      "dige\u0301rer",
      "digital",
      "digne",
      "diluer",
      "dimanche",
      "diminuer",
      "dioxyde",
      "directif",
      "diriger",
      "discuter",
      "disposer",
      "dissiper",
      "distance",
      "divertir",
      "diviser",
      "docile",
      "docteur",
      "dogme",
      "doigt",
      "domaine",
      "domicile",
      "dompter",
      "donateur",
      "donjon",
      "donner",
      "dopamine",
      "dortoir",
      "dorure",
      "dosage",
      "doseur",
      "dossier",
      "dotation",
      "douanier",
      "double",
      "douceur",
      "douter",
      "doyen",
      "dragon",
      "draper",
      "dresser",
      "dribbler",
      "droiture",
      "duperie",
      "duplexe",
      "durable",
      "durcir",
      "dynastie",
      "e\u0301blouir",
      "e\u0301carter",
      "e\u0301charpe",
      "e\u0301chelle",
      "e\u0301clairer",
      "e\u0301clipse",
      "e\u0301clore",
      "e\u0301cluse",
      "e\u0301cole",
      "e\u0301conomie",
      "e\u0301corce",
      "e\u0301couter",
      "e\u0301craser",
      "e\u0301cre\u0301mer",
      "e\u0301crivain",
      "e\u0301crou",
      "e\u0301cume",
      "e\u0301cureuil",
      "e\u0301difier",
      "e\u0301duquer",
      "effacer",
      "effectif",
      "effigie",
      "effort",
      "effrayer",
      "effusion",
      "e\u0301galiser",
      "e\u0301garer",
      "e\u0301jecter",
      "e\u0301laborer",
      "e\u0301largir",
      "e\u0301lectron",
      "e\u0301le\u0301gant",
      "e\u0301le\u0301phant",
      "e\u0301le\u0300ve",
      "e\u0301ligible",
      "e\u0301litisme",
      "e\u0301loge",
      "e\u0301lucider",
      "e\u0301luder",
      "emballer",
      "embellir",
      "embryon",
      "e\u0301meraude",
      "e\u0301mission",
      "emmener",
      "e\u0301motion",
      "e\u0301mouvoir",
      "empereur",
      "employer",
      "emporter",
      "emprise",
      "e\u0301mulsion",
      "encadrer",
      "enche\u0300re",
      "enclave",
      "encoche",
      "endiguer",
      "endosser",
      "endroit",
      "enduire",
      "e\u0301nergie",
      "enfance",
      "enfermer",
      "enfouir",
      "engager",
      "engin",
      "englober",
      "e\u0301nigme",
      "enjamber",
      "enjeu",
      "enlever",
      "ennemi",
      "ennuyeux",
      "enrichir",
      "enrobage",
      "enseigne",
      "entasser",
      "entendre",
      "entier",
      "entourer",
      "entraver",
      "e\u0301nume\u0301rer",
      "envahir",
      "enviable",
      "envoyer",
      "enzyme",
      "e\u0301olien",
      "e\u0301paissir",
      "e\u0301pargne",
      "e\u0301patant",
      "e\u0301paule",
      "e\u0301picerie",
      "e\u0301pide\u0301mie",
      "e\u0301pier",
      "e\u0301pilogue",
      "e\u0301pine",
      "e\u0301pisode",
      "e\u0301pitaphe",
      "e\u0301poque",
      "e\u0301preuve",
      "e\u0301prouver",
      "e\u0301puisant",
      "e\u0301querre",
      "e\u0301quipe",
      "e\u0301riger",
      "e\u0301rosion",
      "erreur",
      "e\u0301ruption",
      "escalier",
      "espadon",
      "espe\u0300ce",
      "espie\u0300gle",
      "espoir",
      "esprit",
      "esquiver",
      "essayer",
      "essence",
      "essieu",
      "essorer",
      "estime",
      "estomac",
      "estrade",
      "e\u0301tage\u0300re",
      "e\u0301taler",
      "e\u0301tanche",
      "e\u0301tatique",
      "e\u0301teindre",
      "e\u0301tendoir",
      "e\u0301ternel",
      "e\u0301thanol",
      "e\u0301thique",
      "ethnie",
      "e\u0301tirer",
      "e\u0301toffer",
      "e\u0301toile",
      "e\u0301tonnant",
      "e\u0301tourdir",
      "e\u0301trange",
      "e\u0301troit",
      "e\u0301tude",
      "euphorie",
      "e\u0301valuer",
      "e\u0301vasion",
      "e\u0301ventail",
      "e\u0301vidence",
      "e\u0301viter",
      "e\u0301volutif",
      "e\u0301voquer",
      "exact",
      "exage\u0301rer",
      "exaucer",
      "exceller",
      "excitant",
      "exclusif",
      "excuse",
      "exe\u0301cuter",
      "exemple",
      "exercer",
      "exhaler",
      "exhorter",
      "exigence",
      "exiler",
      "exister",
      "exotique",
      "expe\u0301dier",
      "explorer",
      "exposer",
      "exprimer",
      "exquis",
      "extensif",
      "extraire",
      "exulter",
      "fable",
      "fabuleux",
      "facette",
      "facile",
      "facture",
      "faiblir",
      "falaise",
      "fameux",
      "famille",
      "farceur",
      "farfelu",
      "farine",
      "farouche",
      "fasciner",
      "fatal",
      "fatigue",
      "faucon",
      "fautif",
      "faveur",
      "favori",
      "fe\u0301brile",
      "fe\u0301conder",
      "fe\u0301de\u0301rer",
      "fe\u0301lin",
      "femme",
      "fe\u0301mur",
      "fendoir",
      "fe\u0301odal",
      "fermer",
      "fe\u0301roce",
      "ferveur",
      "festival",
      "feuille",
      "feutre",
      "fe\u0301vrier",
      "fiasco",
      "ficeler",
      "fictif",
      "fide\u0300le",
      "figure",
      "filature",
      "filetage",
      "filie\u0300re",
      "filleul",
      "filmer",
      "filou",
      "filtrer",
      "financer",
      "finir",
      "fiole",
      "firme",
      "fissure",
      "fixer",
      "flairer",
      "flamme",
      "flasque",
      "flatteur",
      "fle\u0301au",
      "fle\u0300che",
      "fleur",
      "flexion",
      "flocon",
      "flore",
      "fluctuer",
      "fluide",
      "fluvial",
      "folie",
      "fonderie",
      "fongible",
      "fontaine",
      "forcer",
      "forgeron",
      "formuler",
      "fortune",
      "fossile",
      "foudre",
      "fouge\u0300re",
      "fouiller",
      "foulure",
      "fourmi",
      "fragile",
      "fraise",
      "franchir",
      "frapper",
      "frayeur",
      "fre\u0301gate",
      "freiner",
      "frelon",
      "fre\u0301mir",
      "fre\u0301ne\u0301sie",
      "fre\u0300re",
      "friable",
      "friction",
      "frisson",
      "frivole",
      "froid",
      "fromage",
      "frontal",
      "frotter",
      "fruit",
      "fugitif",
      "fuite",
      "fureur",
      "furieux",
      "furtif",
      "fusion",
      "futur",
      "gagner",
      "galaxie",
      "galerie",
      "gambader",
      "garantir",
      "gardien",
      "garnir",
      "garrigue",
      "gazelle",
      "gazon",
      "ge\u0301ant",
      "ge\u0301latine",
      "ge\u0301lule",
      "gendarme",
      "ge\u0301ne\u0301ral",
      "ge\u0301nie",
      "genou",
      "gentil",
      "ge\u0301ologie",
      "ge\u0301ome\u0300tre",
      "ge\u0301ranium",
      "germe",
      "gestuel",
      "geyser",
      "gibier",
      "gicler",
      "girafe",
      "givre",
      "glace",
      "glaive",
      "glisser",
      "globe",
      "gloire",
      "glorieux",
      "golfeur",
      "gomme",
      "gonfler",
      "gorge",
      "gorille",
      "goudron",
      "gouffre",
      "goulot",
      "goupille",
      "gourmand",
      "goutte",
      "graduel",
      "graffiti",
      "graine",
      "grand",
      "grappin",
      "gratuit",
      "gravir",
      "grenat",
      "griffure",
      "griller",
      "grimper",
      "grogner",
      "gronder",
      "grotte",
      "groupe",
      "gruger",
      "grutier",
      "gruye\u0300re",
      "gue\u0301pard",
      "guerrier",
      "guide",
      "guimauve",
      "guitare",
      "gustatif",
      "gymnaste",
      "gyrostat",
      "habitude",
      "hachoir",
      "halte",
      "hameau",
      "hangar",
      "hanneton",
      "haricot",
      "harmonie",
      "harpon",
      "hasard",
      "he\u0301lium",
      "he\u0301matome",
      "herbe",
      "he\u0301risson",
      "hermine",
      "he\u0301ron",
      "he\u0301siter",
      "heureux",
      "hiberner",
      "hibou",
      "hilarant",
      "histoire",
      "hiver",
      "homard",
      "hommage",
      "homoge\u0300ne",
      "honneur",
      "honorer",
      "honteux",
      "horde",
      "horizon",
      "horloge",
      "hormone",
      "horrible",
      "houleux",
      "housse",
      "hublot",
      "huileux",
      "humain",
      "humble",
      "humide",
      "humour",
      "hurler",
      "hydromel",
      "hygie\u0300ne",
      "hymne",
      "hypnose",
      "idylle",
      "ignorer",
      "iguane",
      "illicite",
      "illusion",
      "image",
      "imbiber",
      "imiter",
      "immense",
      "immobile",
      "immuable",
      "impact",
      "impe\u0301rial",
      "implorer",
      "imposer",
      "imprimer",
      "imputer",
      "incarner",
      "incendie",
      "incident",
      "incliner",
      "incolore",
      "indexer",
      "indice",
      "inductif",
      "ine\u0301dit",
      "ineptie",
      "inexact",
      "infini",
      "infliger",
      "informer",
      "infusion",
      "inge\u0301rer",
      "inhaler",
      "inhiber",
      "injecter",
      "injure",
      "innocent",
      "inoculer",
      "inonder",
      "inscrire",
      "insecte",
      "insigne",
      "insolite",
      "inspirer",
      "instinct",
      "insulter",
      "intact",
      "intense",
      "intime",
      "intrigue",
      "intuitif",
      "inutile",
      "invasion",
      "inventer",
      "inviter",
      "invoquer",
      "ironique",
      "irradier",
      "irre\u0301el",
      "irriter",
      "isoler",
      "ivoire",
      "ivresse",
      "jaguar",
      "jaillir",
      "jambe",
      "janvier",
      "jardin",
      "jauger",
      "jaune",
      "javelot",
      "jetable",
      "jeton",
      "jeudi",
      "jeunesse",
      "joindre",
      "joncher",
      "jongler",
      "joueur",
      "jouissif",
      "journal",
      "jovial",
      "joyau",
      "joyeux",
      "jubiler",
      "jugement",
      "junior",
      "jupon",
      "juriste",
      "justice",
      "juteux",
      "juve\u0301nile",
      "kayak",
      "kimono",
      "kiosque",
      "label",
      "labial",
      "labourer",
      "lace\u0301rer",
      "lactose",
      "lagune",
      "laine",
      "laisser",
      "laitier",
      "lambeau",
      "lamelle",
      "lampe",
      "lanceur",
      "langage",
      "lanterne",
      "lapin",
      "largeur",
      "larme",
      "laurier",
      "lavabo",
      "lavoir",
      "lecture",
      "le\u0301gal",
      "le\u0301ger",
      "le\u0301gume",
      "lessive",
      "lettre",
      "levier",
      "lexique",
      "le\u0301zard",
      "liasse",
      "libe\u0301rer",
      "libre",
      "licence",
      "licorne",
      "lie\u0300ge",
      "lie\u0300vre",
      "ligature",
      "ligoter",
      "ligue",
      "limer",
      "limite",
      "limonade",
      "limpide",
      "line\u0301aire",
      "lingot",
      "lionceau",
      "liquide",
      "lisie\u0300re",
      "lister",
      "lithium",
      "litige",
      "littoral",
      "livreur",
      "logique",
      "lointain",
      "loisir",
      "lombric",
      "loterie",
      "louer",
      "lourd",
      "loutre",
      "louve",
      "loyal",
      "lubie",
      "lucide",
      "lucratif",
      "lueur",
      "lugubre",
      "luisant",
      "lumie\u0300re",
      "lunaire",
      "lundi",
      "luron",
      "lutter",
      "luxueux",
      "machine",
      "magasin",
      "magenta",
      "magique",
      "maigre",
      "maillon",
      "maintien",
      "mairie",
      "maison",
      "majorer",
      "malaxer",
      "male\u0301fice",
      "malheur",
      "malice",
      "mallette",
      "mammouth",
      "mandater",
      "maniable",
      "manquant",
      "manteau",
      "manuel",
      "marathon",
      "marbre",
      "marchand",
      "mardi",
      "maritime",
      "marqueur",
      "marron",
      "marteler",
      "mascotte",
      "massif",
      "mate\u0301riel",
      "matie\u0300re",
      "matraque",
      "maudire",
      "maussade",
      "mauve",
      "maximal",
      "me\u0301chant",
      "me\u0301connu",
      "me\u0301daille",
      "me\u0301decin",
      "me\u0301diter",
      "me\u0301duse",
      "meilleur",
      "me\u0301lange",
      "me\u0301lodie",
      "membre",
      "me\u0301moire",
      "menacer",
      "mener",
      "menhir",
      "mensonge",
      "mentor",
      "mercredi",
      "me\u0301rite",
      "merle",
      "messager",
      "mesure",
      "me\u0301tal",
      "me\u0301te\u0301ore",
      "me\u0301thode",
      "me\u0301tier",
      "meuble",
      "miauler",
      "microbe",
      "miette",
      "mignon",
      "migrer",
      "milieu",
      "million",
      "mimique",
      "mince",
      "mine\u0301ral",
      "minimal",
      "minorer",
      "minute",
      "miracle",
      "miroiter",
      "missile",
      "mixte",
      "mobile",
      "moderne",
      "moelleux",
      "mondial",
      "moniteur",
      "monnaie",
      "monotone",
      "monstre",
      "montagne",
      "monument",
      "moqueur",
      "morceau",
      "morsure",
      "mortier",
      "moteur",
      "motif",
      "mouche",
      "moufle",
      "moulin",
      "mousson",
      "mouton",
      "mouvant",
      "multiple",
      "munition",
      "muraille",
      "mure\u0300ne",
      "murmure",
      "muscle",
      "muse\u0301um",
      "musicien",
      "mutation",
      "muter",
      "mutuel",
      "myriade",
      "myrtille",
      "myste\u0300re",
      "mythique",
      "nageur",
      "nappe",
      "narquois",
      "narrer",
      "natation",
      "nation",
      "nature",
      "naufrage",
      "nautique",
      "navire",
      "ne\u0301buleux",
      "nectar",
      "ne\u0301faste",
      "ne\u0301gation",
      "ne\u0301gliger",
      "ne\u0301gocier",
      "neige",
      "nerveux",
      "nettoyer",
      "neurone",
      "neutron",
      "neveu",
      "niche",
      "nickel",
      "nitrate",
      "niveau",
      "noble",
      "nocif",
      "nocturne",
      "noirceur",
      "noisette",
      "nomade",
      "nombreux",
      "nommer",
      "normatif",
      "notable",
      "notifier",
      "notoire",
      "nourrir",
      "nouveau",
      "novateur",
      "novembre",
      "novice",
      "nuage",
      "nuancer",
      "nuire",
      "nuisible",
      "nume\u0301ro",
      "nuptial",
      "nuque",
      "nutritif",
      "obe\u0301ir",
      "objectif",
      "obliger",
      "obscur",
      "observer",
      "obstacle",
      "obtenir",
      "obturer",
      "occasion",
      "occuper",
      "oce\u0301an",
      "octobre",
      "octroyer",
      "octupler",
      "oculaire",
      "odeur",
      "odorant",
      "offenser",
      "officier",
      "offrir",
      "ogive",
      "oiseau",
      "oisillon",
      "olfactif",
      "olivier",
      "ombrage",
      "omettre",
      "onctueux",
      "onduler",
      "one\u0301reux",
      "onirique",
      "opale",
      "opaque",
      "ope\u0301rer",
      "opinion",
      "opportun",
      "opprimer",
      "opter",
      "optique",
      "orageux",
      "orange",
      "orbite",
      "ordonner",
      "oreille",
      "organe",
      "orgueil",
      "orifice",
      "ornement",
      "orque",
      "ortie",
      "osciller",
      "osmose",
      "ossature",
      "otarie",
      "ouragan",
      "ourson",
      "outil",
      "outrager",
      "ouvrage",
      "ovation",
      "oxyde",
      "oxyge\u0300ne",
      "ozone",
      "paisible",
      "palace",
      "palmare\u0300s",
      "palourde",
      "palper",
      "panache",
      "panda",
      "pangolin",
      "paniquer",
      "panneau",
      "panorama",
      "pantalon",
      "papaye",
      "papier",
      "papoter",
      "papyrus",
      "paradoxe",
      "parcelle",
      "paresse",
      "parfumer",
      "parler",
      "parole",
      "parrain",
      "parsemer",
      "partager",
      "parure",
      "parvenir",
      "passion",
      "paste\u0300que",
      "paternel",
      "patience",
      "patron",
      "pavillon",
      "pavoiser",
      "payer",
      "paysage",
      "peigne",
      "peintre",
      "pelage",
      "pe\u0301lican",
      "pelle",
      "pelouse",
      "peluche",
      "pendule",
      "pe\u0301ne\u0301trer",
      "pe\u0301nible",
      "pensif",
      "pe\u0301nurie",
      "pe\u0301pite",
      "pe\u0301plum",
      "perdrix",
      "perforer",
      "pe\u0301riode",
      "permuter",
      "perplexe",
      "persil",
      "perte",
      "peser",
      "pe\u0301tale",
      "petit",
      "pe\u0301trir",
      "peuple",
      "pharaon",
      "phobie",
      "phoque",
      "photon",
      "phrase",
      "physique",
      "piano",
      "pictural",
      "pie\u0300ce",
      "pierre",
      "pieuvre",
      "pilote",
      "pinceau",
      "pipette",
      "piquer",
      "pirogue",
      "piscine",
      "piston",
      "pivoter",
      "pixel",
      "pizza",
      "placard",
      "plafond",
      "plaisir",
      "planer",
      "plaque",
      "plastron",
      "plateau",
      "pleurer",
      "plexus",
      "pliage",
      "plomb",
      "plonger",
      "pluie",
      "plumage",
      "pochette",
      "poe\u0301sie",
      "poe\u0300te",
      "pointe",
      "poirier",
      "poisson",
      "poivre",
      "polaire",
      "policier",
      "pollen",
      "polygone",
      "pommade",
      "pompier",
      "ponctuel",
      "ponde\u0301rer",
      "poney",
      "portique",
      "position",
      "posse\u0301der",
      "posture",
      "potager",
      "poteau",
      "potion",
      "pouce",
      "poulain",
      "poumon",
      "pourpre",
      "poussin",
      "pouvoir",
      "prairie",
      "pratique",
      "pre\u0301cieux",
      "pre\u0301dire",
      "pre\u0301fixe",
      "pre\u0301lude",
      "pre\u0301nom",
      "pre\u0301sence",
      "pre\u0301texte",
      "pre\u0301voir",
      "primitif",
      "prince",
      "prison",
      "priver",
      "proble\u0300me",
      "proce\u0301der",
      "prodige",
      "profond",
      "progre\u0300s",
      "proie",
      "projeter",
      "prologue",
      "promener",
      "propre",
      "prospe\u0300re",
      "prote\u0301ger",
      "prouesse",
      "proverbe",
      "prudence",
      "pruneau",
      "psychose",
      "public",
      "puceron",
      "puiser",
      "pulpe",
      "pulsar",
      "punaise",
      "punitif",
      "pupitre",
      "purifier",
      "puzzle",
      "pyramide",
      "quasar",
      "querelle",
      "question",
      "quie\u0301tude",
      "quitter",
      "quotient",
      "racine",
      "raconter",
      "radieux",
      "ragondin",
      "raideur",
      "raisin",
      "ralentir",
      "rallonge",
      "ramasser",
      "rapide",
      "rasage",
      "ratisser",
      "ravager",
      "ravin",
      "rayonner",
      "re\u0301actif",
      "re\u0301agir",
      "re\u0301aliser",
      "re\u0301animer",
      "recevoir",
      "re\u0301citer",
      "re\u0301clamer",
      "re\u0301colter",
      "recruter",
      "reculer",
      "recycler",
      "re\u0301diger",
      "redouter",
      "refaire",
      "re\u0301flexe",
      "re\u0301former",
      "refrain",
      "refuge",
      "re\u0301galien",
      "re\u0301gion",
      "re\u0301glage",
      "re\u0301gulier",
      "re\u0301ite\u0301rer",
      "rejeter",
      "rejouer",
      "relatif",
      "relever",
      "relief",
      "remarque",
      "reme\u0300de",
      "remise",
      "remonter",
      "remplir",
      "remuer",
      "renard",
      "renfort",
      "renifler",
      "renoncer",
      "rentrer",
      "renvoi",
      "replier",
      "reporter",
      "reprise",
      "reptile",
      "requin",
      "re\u0301serve",
      "re\u0301sineux",
      "re\u0301soudre",
      "respect",
      "rester",
      "re\u0301sultat",
      "re\u0301tablir",
      "retenir",
      "re\u0301ticule",
      "retomber",
      "retracer",
      "re\u0301union",
      "re\u0301ussir",
      "revanche",
      "revivre",
      "re\u0301volte",
      "re\u0301vulsif",
      "richesse",
      "rideau",
      "rieur",
      "rigide",
      "rigoler",
      "rincer",
      "riposter",
      "risible",
      "risque",
      "rituel",
      "rival",
      "rivie\u0300re",
      "rocheux",
      "romance",
      "rompre",
      "ronce",
      "rondin",
      "roseau",
      "rosier",
      "rotatif",
      "rotor",
      "rotule",
      "rouge",
      "rouille",
      "rouleau",
      "routine",
      "royaume",
      "ruban",
      "rubis",
      "ruche",
      "ruelle",
      "rugueux",
      "ruiner",
      "ruisseau",
      "ruser",
      "rustique",
      "rythme",
      "sabler",
      "saboter",
      "sabre",
      "sacoche",
      "safari",
      "sagesse",
      "saisir",
      "salade",
      "salive",
      "salon",
      "saluer",
      "samedi",
      "sanction",
      "sanglier",
      "sarcasme",
      "sardine",
      "saturer",
      "saugrenu",
      "saumon",
      "sauter",
      "sauvage",
      "savant",
      "savonner",
      "scalpel",
      "scandale",
      "sce\u0301le\u0301rat",
      "sce\u0301nario",
      "sceptre",
      "sche\u0301ma",
      "science",
      "scinder",
      "score",
      "scrutin",
      "sculpter",
      "se\u0301ance",
      "se\u0301cable",
      "se\u0301cher",
      "secouer",
      "se\u0301cre\u0301ter",
      "se\u0301datif",
      "se\u0301duire",
      "seigneur",
      "se\u0301jour",
      "se\u0301lectif",
      "semaine",
      "sembler",
      "semence",
      "se\u0301minal",
      "se\u0301nateur",
      "sensible",
      "sentence",
      "se\u0301parer",
      "se\u0301quence",
      "serein",
      "sergent",
      "se\u0301rieux",
      "serrure",
      "se\u0301rum",
      "service",
      "se\u0301same",
      "se\u0301vir",
      "sevrage",
      "sextuple",
      "side\u0301ral",
      "sie\u0300cle",
      "sie\u0301ger",
      "siffler",
      "sigle",
      "signal",
      "silence",
      "silicium",
      "simple",
      "since\u0300re",
      "sinistre",
      "siphon",
      "sirop",
      "sismique",
      "situer",
      "skier",
      "social",
      "socle",
      "sodium",
      "soigneux",
      "soldat",
      "soleil",
      "solitude",
      "soluble",
      "sombre",
      "sommeil",
      "somnoler",
      "sonde",
      "songeur",
      "sonnette",
      "sonore",
      "sorcier",
      "sortir",
      "sosie",
      "sottise",
      "soucieux",
      "soudure",
      "souffle",
      "soulever",
      "soupape",
      "source",
      "soutirer",
      "souvenir",
      "spacieux",
      "spatial",
      "spe\u0301cial",
      "sphe\u0300re",
      "spiral",
      "stable",
      "station",
      "sternum",
      "stimulus",
      "stipuler",
      "strict",
      "studieux",
      "stupeur",
      "styliste",
      "sublime",
      "substrat",
      "subtil",
      "subvenir",
      "succe\u0300s",
      "sucre",
      "suffixe",
      "sugge\u0301rer",
      "suiveur",
      "sulfate",
      "superbe",
      "supplier",
      "surface",
      "suricate",
      "surmener",
      "surprise",
      "sursaut",
      "survie",
      "suspect",
      "syllabe",
      "symbole",
      "syme\u0301trie",
      "synapse",
      "syntaxe",
      "syste\u0300me",
      "tabac",
      "tablier",
      "tactile",
      "tailler",
      "talent",
      "talisman",
      "talonner",
      "tambour",
      "tamiser",
      "tangible",
      "tapis",
      "taquiner",
      "tarder",
      "tarif",
      "tartine",
      "tasse",
      "tatami",
      "tatouage",
      "taupe",
      "taureau",
      "taxer",
      "te\u0301moin",
      "temporel",
      "tenaille",
      "tendre",
      "teneur",
      "tenir",
      "tension",
      "terminer",
      "terne",
      "terrible",
      "te\u0301tine",
      "texte",
      "the\u0300me",
      "the\u0301orie",
      "the\u0301rapie",
      "thorax",
      "tibia",
      "tie\u0300de",
      "timide",
      "tirelire",
      "tiroir",
      "tissu",
      "titane",
      "titre",
      "tituber",
      "toboggan",
      "tole\u0301rant",
      "tomate",
      "tonique",
      "tonneau",
      "toponyme",
      "torche",
      "tordre",
      "tornade",
      "torpille",
      "torrent",
      "torse",
      "tortue",
      "totem",
      "toucher",
      "tournage",
      "tousser",
      "toxine",
      "traction",
      "trafic",
      "tragique",
      "trahir",
      "train",
      "trancher",
      "travail",
      "tre\u0300fle",
      "tremper",
      "tre\u0301sor",
      "treuil",
      "triage",
      "tribunal",
      "tricoter",
      "trilogie",
      "triomphe",
      "tripler",
      "triturer",
      "trivial",
      "trombone",
      "tronc",
      "tropical",
      "troupeau",
      "tuile",
      "tulipe",
      "tumulte",
      "tunnel",
      "turbine",
      "tuteur",
      "tutoyer",
      "tuyau",
      "tympan",
      "typhon",
      "typique",
      "tyran",
      "ubuesque",
      "ultime",
      "ultrason",
      "unanime",
      "unifier",
      "union",
      "unique",
      "unitaire",
      "univers",
      "uranium",
      "urbain",
      "urticant",
      "usage",
      "usine",
      "usuel",
      "usure",
      "utile",
      "utopie",
      "vacarme",
      "vaccin",
      "vagabond",
      "vague",
      "vaillant",
      "vaincre",
      "vaisseau",
      "valable",
      "valise",
      "vallon",
      "valve",
      "vampire",
      "vanille",
      "vapeur",
      "varier",
      "vaseux",
      "vassal",
      "vaste",
      "vecteur",
      "vedette",
      "ve\u0301ge\u0301tal",
      "ve\u0301hicule",
      "veinard",
      "ve\u0301loce",
      "vendredi",
      "ve\u0301ne\u0301rer",
      "venger",
      "venimeux",
      "ventouse",
      "verdure",
      "ve\u0301rin",
      "vernir",
      "verrou",
      "verser",
      "vertu",
      "veston",
      "ve\u0301te\u0301ran",
      "ve\u0301tuste",
      "vexant",
      "vexer",
      "viaduc",
      "viande",
      "victoire",
      "vidange",
      "vide\u0301o",
      "vignette",
      "vigueur",
      "vilain",
      "village",
      "vinaigre",
      "violon",
      "vipe\u0300re",
      "virement",
      "virtuose",
      "virus",
      "visage",
      "viseur",
      "vision",
      "visqueux",
      "visuel",
      "vital",
      "vitesse",
      "viticole",
      "vitrine",
      "vivace",
      "vivipare",
      "vocation",
      "voguer",
      "voile",
      "voisin",
      "voiture",
      "volaille",
      "volcan",
      "voltiger",
      "volume",
      "vorace",
      "vortex",
      "voter",
      "vouloir",
      "voyage",
      "voyelle",
      "wagon",
      "xe\u0301non",
      "yacht",
      "ze\u0300bre",
      "ze\u0301nith",
      "zeste",
      "zoologie"
    ];
  }
});

// node_modules/bip39/src/wordlists/italian.json
var require_italian = __commonJS({
  "node_modules/bip39/src/wordlists/italian.json"(exports, module) {
    module.exports = [
      "abaco",
      "abbaglio",
      "abbinato",
      "abete",
      "abisso",
      "abolire",
      "abrasivo",
      "abrogato",
      "accadere",
      "accenno",
      "accusato",
      "acetone",
      "achille",
      "acido",
      "acqua",
      "acre",
      "acrilico",
      "acrobata",
      "acuto",
      "adagio",
      "addebito",
      "addome",
      "adeguato",
      "aderire",
      "adipe",
      "adottare",
      "adulare",
      "affabile",
      "affetto",
      "affisso",
      "affranto",
      "aforisma",
      "afoso",
      "africano",
      "agave",
      "agente",
      "agevole",
      "aggancio",
      "agire",
      "agitare",
      "agonismo",
      "agricolo",
      "agrumeto",
      "aguzzo",
      "alabarda",
      "alato",
      "albatro",
      "alberato",
      "albo",
      "albume",
      "alce",
      "alcolico",
      "alettone",
      "alfa",
      "algebra",
      "aliante",
      "alibi",
      "alimento",
      "allagato",
      "allegro",
      "allievo",
      "allodola",
      "allusivo",
      "almeno",
      "alogeno",
      "alpaca",
      "alpestre",
      "altalena",
      "alterno",
      "alticcio",
      "altrove",
      "alunno",
      "alveolo",
      "alzare",
      "amalgama",
      "amanita",
      "amarena",
      "ambito",
      "ambrato",
      "ameba",
      "america",
      "ametista",
      "amico",
      "ammasso",
      "ammenda",
      "ammirare",
      "ammonito",
      "amore",
      "ampio",
      "ampliare",
      "amuleto",
      "anacardo",
      "anagrafe",
      "analista",
      "anarchia",
      "anatra",
      "anca",
      "ancella",
      "ancora",
      "andare",
      "andrea",
      "anello",
      "angelo",
      "angolare",
      "angusto",
      "anima",
      "annegare",
      "annidato",
      "anno",
      "annuncio",
      "anonimo",
      "anticipo",
      "anzi",
      "apatico",
      "apertura",
      "apode",
      "apparire",
      "appetito",
      "appoggio",
      "approdo",
      "appunto",
      "aprile",
      "arabica",
      "arachide",
      "aragosta",
      "araldica",
      "arancio",
      "aratura",
      "arazzo",
      "arbitro",
      "archivio",
      "ardito",
      "arenile",
      "argento",
      "argine",
      "arguto",
      "aria",
      "armonia",
      "arnese",
      "arredato",
      "arringa",
      "arrosto",
      "arsenico",
      "arso",
      "artefice",
      "arzillo",
      "asciutto",
      "ascolto",
      "asepsi",
      "asettico",
      "asfalto",
      "asino",
      "asola",
      "aspirato",
      "aspro",
      "assaggio",
      "asse",
      "assoluto",
      "assurdo",
      "asta",
      "astenuto",
      "astice",
      "astratto",
      "atavico",
      "ateismo",
      "atomico",
      "atono",
      "attesa",
      "attivare",
      "attorno",
      "attrito",
      "attuale",
      "ausilio",
      "austria",
      "autista",
      "autonomo",
      "autunno",
      "avanzato",
      "avere",
      "avvenire",
      "avviso",
      "avvolgere",
      "azione",
      "azoto",
      "azzimo",
      "azzurro",
      "babele",
      "baccano",
      "bacino",
      "baco",
      "badessa",
      "badilata",
      "bagnato",
      "baita",
      "balcone",
      "baldo",
      "balena",
      "ballata",
      "balzano",
      "bambino",
      "bandire",
      "baraonda",
      "barbaro",
      "barca",
      "baritono",
      "barlume",
      "barocco",
      "basilico",
      "basso",
      "batosta",
      "battuto",
      "baule",
      "bava",
      "bavosa",
      "becco",
      "beffa",
      "belgio",
      "belva",
      "benda",
      "benevole",
      "benigno",
      "benzina",
      "bere",
      "berlina",
      "beta",
      "bibita",
      "bici",
      "bidone",
      "bifido",
      "biga",
      "bilancia",
      "bimbo",
      "binocolo",
      "biologo",
      "bipede",
      "bipolare",
      "birbante",
      "birra",
      "biscotto",
      "bisesto",
      "bisnonno",
      "bisonte",
      "bisturi",
      "bizzarro",
      "blando",
      "blatta",
      "bollito",
      "bonifico",
      "bordo",
      "bosco",
      "botanico",
      "bottino",
      "bozzolo",
      "braccio",
      "bradipo",
      "brama",
      "branca",
      "bravura",
      "bretella",
      "brevetto",
      "brezza",
      "briglia",
      "brillante",
      "brindare",
      "broccolo",
      "brodo",
      "bronzina",
      "brullo",
      "bruno",
      "bubbone",
      "buca",
      "budino",
      "buffone",
      "buio",
      "bulbo",
      "buono",
      "burlone",
      "burrasca",
      "bussola",
      "busta",
      "cadetto",
      "caduco",
      "calamaro",
      "calcolo",
      "calesse",
      "calibro",
      "calmo",
      "caloria",
      "cambusa",
      "camerata",
      "camicia",
      "cammino",
      "camola",
      "campale",
      "canapa",
      "candela",
      "cane",
      "canino",
      "canotto",
      "cantina",
      "capace",
      "capello",
      "capitolo",
      "capogiro",
      "cappero",
      "capra",
      "capsula",
      "carapace",
      "carcassa",
      "cardo",
      "carisma",
      "carovana",
      "carretto",
      "cartolina",
      "casaccio",
      "cascata",
      "caserma",
      "caso",
      "cassone",
      "castello",
      "casuale",
      "catasta",
      "catena",
      "catrame",
      "cauto",
      "cavillo",
      "cedibile",
      "cedrata",
      "cefalo",
      "celebre",
      "cellulare",
      "cena",
      "cenone",
      "centesimo",
      "ceramica",
      "cercare",
      "certo",
      "cerume",
      "cervello",
      "cesoia",
      "cespo",
      "ceto",
      "chela",
      "chiaro",
      "chicca",
      "chiedere",
      "chimera",
      "china",
      "chirurgo",
      "chitarra",
      "ciao",
      "ciclismo",
      "cifrare",
      "cigno",
      "cilindro",
      "ciottolo",
      "circa",
      "cirrosi",
      "citrico",
      "cittadino",
      "ciuffo",
      "civetta",
      "civile",
      "classico",
      "clinica",
      "cloro",
      "cocco",
      "codardo",
      "codice",
      "coerente",
      "cognome",
      "collare",
      "colmato",
      "colore",
      "colposo",
      "coltivato",
      "colza",
      "coma",
      "cometa",
      "commando",
      "comodo",
      "computer",
      "comune",
      "conciso",
      "condurre",
      "conferma",
      "congelare",
      "coniuge",
      "connesso",
      "conoscere",
      "consumo",
      "continuo",
      "convegno",
      "coperto",
      "copione",
      "coppia",
      "copricapo",
      "corazza",
      "cordata",
      "coricato",
      "cornice",
      "corolla",
      "corpo",
      "corredo",
      "corsia",
      "cortese",
      "cosmico",
      "costante",
      "cottura",
      "covato",
      "cratere",
      "cravatta",
      "creato",
      "credere",
      "cremoso",
      "crescita",
      "creta",
      "criceto",
      "crinale",
      "crisi",
      "critico",
      "croce",
      "cronaca",
      "crostata",
      "cruciale",
      "crusca",
      "cucire",
      "cuculo",
      "cugino",
      "cullato",
      "cupola",
      "curatore",
      "cursore",
      "curvo",
      "cuscino",
      "custode",
      "dado",
      "daino",
      "dalmata",
      "damerino",
      "daniela",
      "dannoso",
      "danzare",
      "datato",
      "davanti",
      "davvero",
      "debutto",
      "decennio",
      "deciso",
      "declino",
      "decollo",
      "decreto",
      "dedicato",
      "definito",
      "deforme",
      "degno",
      "delegare",
      "delfino",
      "delirio",
      "delta",
      "demenza",
      "denotato",
      "dentro",
      "deposito",
      "derapata",
      "derivare",
      "deroga",
      "descritto",
      "deserto",
      "desiderio",
      "desumere",
      "detersivo",
      "devoto",
      "diametro",
      "dicembre",
      "diedro",
      "difeso",
      "diffuso",
      "digerire",
      "digitale",
      "diluvio",
      "dinamico",
      "dinnanzi",
      "dipinto",
      "diploma",
      "dipolo",
      "diradare",
      "dire",
      "dirotto",
      "dirupo",
      "disagio",
      "discreto",
      "disfare",
      "disgelo",
      "disposto",
      "distanza",
      "disumano",
      "dito",
      "divano",
      "divelto",
      "dividere",
      "divorato",
      "doblone",
      "docente",
      "doganale",
      "dogma",
      "dolce",
      "domato",
      "domenica",
      "dominare",
      "dondolo",
      "dono",
      "dormire",
      "dote",
      "dottore",
      "dovuto",
      "dozzina",
      "drago",
      "druido",
      "dubbio",
      "dubitare",
      "ducale",
      "duna",
      "duomo",
      "duplice",
      "duraturo",
      "ebano",
      "eccesso",
      "ecco",
      "eclissi",
      "economia",
      "edera",
      "edicola",
      "edile",
      "editoria",
      "educare",
      "egemonia",
      "egli",
      "egoismo",
      "egregio",
      "elaborato",
      "elargire",
      "elegante",
      "elencato",
      "eletto",
      "elevare",
      "elfico",
      "elica",
      "elmo",
      "elsa",
      "eluso",
      "emanato",
      "emblema",
      "emesso",
      "emiro",
      "emotivo",
      "emozione",
      "empirico",
      "emulo",
      "endemico",
      "enduro",
      "energia",
      "enfasi",
      "enoteca",
      "entrare",
      "enzima",
      "epatite",
      "epilogo",
      "episodio",
      "epocale",
      "eppure",
      "equatore",
      "erario",
      "erba",
      "erboso",
      "erede",
      "eremita",
      "erigere",
      "ermetico",
      "eroe",
      "erosivo",
      "errante",
      "esagono",
      "esame",
      "esanime",
      "esaudire",
      "esca",
      "esempio",
      "esercito",
      "esibito",
      "esigente",
      "esistere",
      "esito",
      "esofago",
      "esortato",
      "esoso",
      "espanso",
      "espresso",
      "essenza",
      "esso",
      "esteso",
      "estimare",
      "estonia",
      "estroso",
      "esultare",
      "etilico",
      "etnico",
      "etrusco",
      "etto",
      "euclideo",
      "europa",
      "evaso",
      "evidenza",
      "evitato",
      "evoluto",
      "evviva",
      "fabbrica",
      "faccenda",
      "fachiro",
      "falco",
      "famiglia",
      "fanale",
      "fanfara",
      "fango",
      "fantasma",
      "fare",
      "farfalla",
      "farinoso",
      "farmaco",
      "fascia",
      "fastoso",
      "fasullo",
      "faticare",
      "fato",
      "favoloso",
      "febbre",
      "fecola",
      "fede",
      "fegato",
      "felpa",
      "feltro",
      "femmina",
      "fendere",
      "fenomeno",
      "fermento",
      "ferro",
      "fertile",
      "fessura",
      "festivo",
      "fetta",
      "feudo",
      "fiaba",
      "fiducia",
      "fifa",
      "figurato",
      "filo",
      "finanza",
      "finestra",
      "finire",
      "fiore",
      "fiscale",
      "fisico",
      "fiume",
      "flacone",
      "flamenco",
      "flebo",
      "flemma",
      "florido",
      "fluente",
      "fluoro",
      "fobico",
      "focaccia",
      "focoso",
      "foderato",
      "foglio",
      "folata",
      "folclore",
      "folgore",
      "fondente",
      "fonetico",
      "fonia",
      "fontana",
      "forbito",
      "forchetta",
      "foresta",
      "formica",
      "fornaio",
      "foro",
      "fortezza",
      "forzare",
      "fosfato",
      "fosso",
      "fracasso",
      "frana",
      "frassino",
      "fratello",
      "freccetta",
      "frenata",
      "fresco",
      "frigo",
      "frollino",
      "fronde",
      "frugale",
      "frutta",
      "fucilata",
      "fucsia",
      "fuggente",
      "fulmine",
      "fulvo",
      "fumante",
      "fumetto",
      "fumoso",
      "fune",
      "funzione",
      "fuoco",
      "furbo",
      "furgone",
      "furore",
      "fuso",
      "futile",
      "gabbiano",
      "gaffe",
      "galateo",
      "gallina",
      "galoppo",
      "gambero",
      "gamma",
      "garanzia",
      "garbo",
      "garofano",
      "garzone",
      "gasdotto",
      "gasolio",
      "gastrico",
      "gatto",
      "gaudio",
      "gazebo",
      "gazzella",
      "geco",
      "gelatina",
      "gelso",
      "gemello",
      "gemmato",
      "gene",
      "genitore",
      "gennaio",
      "genotipo",
      "gergo",
      "ghepardo",
      "ghiaccio",
      "ghisa",
      "giallo",
      "gilda",
      "ginepro",
      "giocare",
      "gioiello",
      "giorno",
      "giove",
      "girato",
      "girone",
      "gittata",
      "giudizio",
      "giurato",
      "giusto",
      "globulo",
      "glutine",
      "gnomo",
      "gobba",
      "golf",
      "gomito",
      "gommone",
      "gonfio",
      "gonna",
      "governo",
      "gracile",
      "grado",
      "grafico",
      "grammo",
      "grande",
      "grattare",
      "gravoso",
      "grazia",
      "greca",
      "gregge",
      "grifone",
      "grigio",
      "grinza",
      "grotta",
      "gruppo",
      "guadagno",
      "guaio",
      "guanto",
      "guardare",
      "gufo",
      "guidare",
      "ibernato",
      "icona",
      "identico",
      "idillio",
      "idolo",
      "idra",
      "idrico",
      "idrogeno",
      "igiene",
      "ignaro",
      "ignorato",
      "ilare",
      "illeso",
      "illogico",
      "illudere",
      "imballo",
      "imbevuto",
      "imbocco",
      "imbuto",
      "immane",
      "immerso",
      "immolato",
      "impacco",
      "impeto",
      "impiego",
      "importo",
      "impronta",
      "inalare",
      "inarcare",
      "inattivo",
      "incanto",
      "incendio",
      "inchino",
      "incisivo",
      "incluso",
      "incontro",
      "incrocio",
      "incubo",
      "indagine",
      "india",
      "indole",
      "inedito",
      "infatti",
      "infilare",
      "inflitto",
      "ingaggio",
      "ingegno",
      "inglese",
      "ingordo",
      "ingrosso",
      "innesco",
      "inodore",
      "inoltrare",
      "inondato",
      "insano",
      "insetto",
      "insieme",
      "insonnia",
      "insulina",
      "intasato",
      "intero",
      "intonaco",
      "intuito",
      "inumidire",
      "invalido",
      "invece",
      "invito",
      "iperbole",
      "ipnotico",
      "ipotesi",
      "ippica",
      "iride",
      "irlanda",
      "ironico",
      "irrigato",
      "irrorare",
      "isolato",
      "isotopo",
      "isterico",
      "istituto",
      "istrice",
      "italia",
      "iterare",
      "labbro",
      "labirinto",
      "lacca",
      "lacerato",
      "lacrima",
      "lacuna",
      "laddove",
      "lago",
      "lampo",
      "lancetta",
      "lanterna",
      "lardoso",
      "larga",
      "laringe",
      "lastra",
      "latenza",
      "latino",
      "lattuga",
      "lavagna",
      "lavoro",
      "legale",
      "leggero",
      "lembo",
      "lentezza",
      "lenza",
      "leone",
      "lepre",
      "lesivo",
      "lessato",
      "lesto",
      "letterale",
      "leva",
      "levigato",
      "libero",
      "lido",
      "lievito",
      "lilla",
      "limatura",
      "limitare",
      "limpido",
      "lineare",
      "lingua",
      "liquido",
      "lira",
      "lirica",
      "lisca",
      "lite",
      "litigio",
      "livrea",
      "locanda",
      "lode",
      "logica",
      "lombare",
      "londra",
      "longevo",
      "loquace",
      "lorenzo",
      "loto",
      "lotteria",
      "luce",
      "lucidato",
      "lumaca",
      "luminoso",
      "lungo",
      "lupo",
      "luppolo",
      "lusinga",
      "lusso",
      "lutto",
      "macabro",
      "macchina",
      "macero",
      "macinato",
      "madama",
      "magico",
      "maglia",
      "magnete",
      "magro",
      "maiolica",
      "malafede",
      "malgrado",
      "malinteso",
      "malsano",
      "malto",
      "malumore",
      "mana",
      "mancia",
      "mandorla",
      "mangiare",
      "manifesto",
      "mannaro",
      "manovra",
      "mansarda",
      "mantide",
      "manubrio",
      "mappa",
      "maratona",
      "marcire",
      "maretta",
      "marmo",
      "marsupio",
      "maschera",
      "massaia",
      "mastino",
      "materasso",
      "matricola",
      "mattone",
      "maturo",
      "mazurca",
      "meandro",
      "meccanico",
      "mecenate",
      "medesimo",
      "meditare",
      "mega",
      "melassa",
      "melis",
      "melodia",
      "meninge",
      "meno",
      "mensola",
      "mercurio",
      "merenda",
      "merlo",
      "meschino",
      "mese",
      "messere",
      "mestolo",
      "metallo",
      "metodo",
      "mettere",
      "miagolare",
      "mica",
      "micelio",
      "michele",
      "microbo",
      "midollo",
      "miele",
      "migliore",
      "milano",
      "milite",
      "mimosa",
      "minerale",
      "mini",
      "minore",
      "mirino",
      "mirtillo",
      "miscela",
      "missiva",
      "misto",
      "misurare",
      "mitezza",
      "mitigare",
      "mitra",
      "mittente",
      "mnemonico",
      "modello",
      "modifica",
      "modulo",
      "mogano",
      "mogio",
      "mole",
      "molosso",
      "monastero",
      "monco",
      "mondina",
      "monetario",
      "monile",
      "monotono",
      "monsone",
      "montato",
      "monviso",
      "mora",
      "mordere",
      "morsicato",
      "mostro",
      "motivato",
      "motosega",
      "motto",
      "movenza",
      "movimento",
      "mozzo",
      "mucca",
      "mucosa",
      "muffa",
      "mughetto",
      "mugnaio",
      "mulatto",
      "mulinello",
      "multiplo",
      "mummia",
      "munto",
      "muovere",
      "murale",
      "musa",
      "muscolo",
      "musica",
      "mutevole",
      "muto",
      "nababbo",
      "nafta",
      "nanometro",
      "narciso",
      "narice",
      "narrato",
      "nascere",
      "nastrare",
      "naturale",
      "nautica",
      "naviglio",
      "nebulosa",
      "necrosi",
      "negativo",
      "negozio",
      "nemmeno",
      "neofita",
      "neretto",
      "nervo",
      "nessuno",
      "nettuno",
      "neutrale",
      "neve",
      "nevrotico",
      "nicchia",
      "ninfa",
      "nitido",
      "nobile",
      "nocivo",
      "nodo",
      "nome",
      "nomina",
      "nordico",
      "normale",
      "norvegese",
      "nostrano",
      "notare",
      "notizia",
      "notturno",
      "novella",
      "nucleo",
      "nulla",
      "numero",
      "nuovo",
      "nutrire",
      "nuvola",
      "nuziale",
      "oasi",
      "obbedire",
      "obbligo",
      "obelisco",
      "oblio",
      "obolo",
      "obsoleto",
      "occasione",
      "occhio",
      "occidente",
      "occorrere",
      "occultare",
      "ocra",
      "oculato",
      "odierno",
      "odorare",
      "offerta",
      "offrire",
      "offuscato",
      "oggetto",
      "oggi",
      "ognuno",
      "olandese",
      "olfatto",
      "oliato",
      "oliva",
      "ologramma",
      "oltre",
      "omaggio",
      "ombelico",
      "ombra",
      "omega",
      "omissione",
      "ondoso",
      "onere",
      "onice",
      "onnivoro",
      "onorevole",
      "onta",
      "operato",
      "opinione",
      "opposto",
      "oracolo",
      "orafo",
      "ordine",
      "orecchino",
      "orefice",
      "orfano",
      "organico",
      "origine",
      "orizzonte",
      "orma",
      "ormeggio",
      "ornativo",
      "orologio",
      "orrendo",
      "orribile",
      "ortensia",
      "ortica",
      "orzata",
      "orzo",
      "osare",
      "oscurare",
      "osmosi",
      "ospedale",
      "ospite",
      "ossa",
      "ossidare",
      "ostacolo",
      "oste",
      "otite",
      "otre",
      "ottagono",
      "ottimo",
      "ottobre",
      "ovale",
      "ovest",
      "ovino",
      "oviparo",
      "ovocito",
      "ovunque",
      "ovviare",
      "ozio",
      "pacchetto",
      "pace",
      "pacifico",
      "padella",
      "padrone",
      "paese",
      "paga",
      "pagina",
      "palazzina",
      "palesare",
      "pallido",
      "palo",
      "palude",
      "pandoro",
      "pannello",
      "paolo",
      "paonazzo",
      "paprica",
      "parabola",
      "parcella",
      "parere",
      "pargolo",
      "pari",
      "parlato",
      "parola",
      "partire",
      "parvenza",
      "parziale",
      "passivo",
      "pasticca",
      "patacca",
      "patologia",
      "pattume",
      "pavone",
      "peccato",
      "pedalare",
      "pedonale",
      "peggio",
      "peloso",
      "penare",
      "pendice",
      "penisola",
      "pennuto",
      "penombra",
      "pensare",
      "pentola",
      "pepe",
      "pepita",
      "perbene",
      "percorso",
      "perdonato",
      "perforare",
      "pergamena",
      "periodo",
      "permesso",
      "perno",
      "perplesso",
      "persuaso",
      "pertugio",
      "pervaso",
      "pesatore",
      "pesista",
      "peso",
      "pestifero",
      "petalo",
      "pettine",
      "petulante",
      "pezzo",
      "piacere",
      "pianta",
      "piattino",
      "piccino",
      "picozza",
      "piega",
      "pietra",
      "piffero",
      "pigiama",
      "pigolio",
      "pigro",
      "pila",
      "pilifero",
      "pillola",
      "pilota",
      "pimpante",
      "pineta",
      "pinna",
      "pinolo",
      "pioggia",
      "piombo",
      "piramide",
      "piretico",
      "pirite",
      "pirolisi",
      "pitone",
      "pizzico",
      "placebo",
      "planare",
      "plasma",
      "platano",
      "plenario",
      "pochezza",
      "poderoso",
      "podismo",
      "poesia",
      "poggiare",
      "polenta",
      "poligono",
      "pollice",
      "polmonite",
      "polpetta",
      "polso",
      "poltrona",
      "polvere",
      "pomice",
      "pomodoro",
      "ponte",
      "popoloso",
      "porfido",
      "poroso",
      "porpora",
      "porre",
      "portata",
      "posa",
      "positivo",
      "possesso",
      "postulato",
      "potassio",
      "potere",
      "pranzo",
      "prassi",
      "pratica",
      "precluso",
      "predica",
      "prefisso",
      "pregiato",
      "prelievo",
      "premere",
      "prenotare",
      "preparato",
      "presenza",
      "pretesto",
      "prevalso",
      "prima",
      "principe",
      "privato",
      "problema",
      "procura",
      "produrre",
      "profumo",
      "progetto",
      "prolunga",
      "promessa",
      "pronome",
      "proposta",
      "proroga",
      "proteso",
      "prova",
      "prudente",
      "prugna",
      "prurito",
      "psiche",
      "pubblico",
      "pudica",
      "pugilato",
      "pugno",
      "pulce",
      "pulito",
      "pulsante",
      "puntare",
      "pupazzo",
      "pupilla",
      "puro",
      "quadro",
      "qualcosa",
      "quasi",
      "querela",
      "quota",
      "raccolto",
      "raddoppio",
      "radicale",
      "radunato",
      "raffica",
      "ragazzo",
      "ragione",
      "ragno",
      "ramarro",
      "ramingo",
      "ramo",
      "randagio",
      "rantolare",
      "rapato",
      "rapina",
      "rappreso",
      "rasatura",
      "raschiato",
      "rasente",
      "rassegna",
      "rastrello",
      "rata",
      "ravveduto",
      "reale",
      "recepire",
      "recinto",
      "recluta",
      "recondito",
      "recupero",
      "reddito",
      "redimere",
      "regalato",
      "registro",
      "regola",
      "regresso",
      "relazione",
      "remare",
      "remoto",
      "renna",
      "replica",
      "reprimere",
      "reputare",
      "resa",
      "residente",
      "responso",
      "restauro",
      "rete",
      "retina",
      "retorica",
      "rettifica",
      "revocato",
      "riassunto",
      "ribadire",
      "ribelle",
      "ribrezzo",
      "ricarica",
      "ricco",
      "ricevere",
      "riciclato",
      "ricordo",
      "ricreduto",
      "ridicolo",
      "ridurre",
      "rifasare",
      "riflesso",
      "riforma",
      "rifugio",
      "rigare",
      "rigettato",
      "righello",
      "rilassato",
      "rilevato",
      "rimanere",
      "rimbalzo",
      "rimedio",
      "rimorchio",
      "rinascita",
      "rincaro",
      "rinforzo",
      "rinnovo",
      "rinomato",
      "rinsavito",
      "rintocco",
      "rinuncia",
      "rinvenire",
      "riparato",
      "ripetuto",
      "ripieno",
      "riportare",
      "ripresa",
      "ripulire",
      "risata",
      "rischio",
      "riserva",
      "risibile",
      "riso",
      "rispetto",
      "ristoro",
      "risultato",
      "risvolto",
      "ritardo",
      "ritegno",
      "ritmico",
      "ritrovo",
      "riunione",
      "riva",
      "riverso",
      "rivincita",
      "rivolto",
      "rizoma",
      "roba",
      "robotico",
      "robusto",
      "roccia",
      "roco",
      "rodaggio",
      "rodere",
      "roditore",
      "rogito",
      "rollio",
      "romantico",
      "rompere",
      "ronzio",
      "rosolare",
      "rospo",
      "rotante",
      "rotondo",
      "rotula",
      "rovescio",
      "rubizzo",
      "rubrica",
      "ruga",
      "rullino",
      "rumine",
      "rumoroso",
      "ruolo",
      "rupe",
      "russare",
      "rustico",
      "sabato",
      "sabbiare",
      "sabotato",
      "sagoma",
      "salasso",
      "saldatura",
      "salgemma",
      "salivare",
      "salmone",
      "salone",
      "saltare",
      "saluto",
      "salvo",
      "sapere",
      "sapido",
      "saporito",
      "saraceno",
      "sarcasmo",
      "sarto",
      "sassoso",
      "satellite",
      "satira",
      "satollo",
      "saturno",
      "savana",
      "savio",
      "saziato",
      "sbadiglio",
      "sbalzo",
      "sbancato",
      "sbarra",
      "sbattere",
      "sbavare",
      "sbendare",
      "sbirciare",
      "sbloccato",
      "sbocciato",
      "sbrinare",
      "sbruffone",
      "sbuffare",
      "scabroso",
      "scadenza",
      "scala",
      "scambiare",
      "scandalo",
      "scapola",
      "scarso",
      "scatenare",
      "scavato",
      "scelto",
      "scenico",
      "scettro",
      "scheda",
      "schiena",
      "sciarpa",
      "scienza",
      "scindere",
      "scippo",
      "sciroppo",
      "scivolo",
      "sclerare",
      "scodella",
      "scolpito",
      "scomparto",
      "sconforto",
      "scoprire",
      "scorta",
      "scossone",
      "scozzese",
      "scriba",
      "scrollare",
      "scrutinio",
      "scuderia",
      "scultore",
      "scuola",
      "scuro",
      "scusare",
      "sdebitare",
      "sdoganare",
      "seccatura",
      "secondo",
      "sedano",
      "seggiola",
      "segnalato",
      "segregato",
      "seguito",
      "selciato",
      "selettivo",
      "sella",
      "selvaggio",
      "semaforo",
      "sembrare",
      "seme",
      "seminato",
      "sempre",
      "senso",
      "sentire",
      "sepolto",
      "sequenza",
      "serata",
      "serbato",
      "sereno",
      "serio",
      "serpente",
      "serraglio",
      "servire",
      "sestina",
      "setola",
      "settimana",
      "sfacelo",
      "sfaldare",
      "sfamato",
      "sfarzoso",
      "sfaticato",
      "sfera",
      "sfida",
      "sfilato",
      "sfinge",
      "sfocato",
      "sfoderare",
      "sfogo",
      "sfoltire",
      "sforzato",
      "sfratto",
      "sfruttato",
      "sfuggito",
      "sfumare",
      "sfuso",
      "sgabello",
      "sgarbato",
      "sgonfiare",
      "sgorbio",
      "sgrassato",
      "sguardo",
      "sibilo",
      "siccome",
      "sierra",
      "sigla",
      "signore",
      "silenzio",
      "sillaba",
      "simbolo",
      "simpatico",
      "simulato",
      "sinfonia",
      "singolo",
      "sinistro",
      "sino",
      "sintesi",
      "sinusoide",
      "sipario",
      "sisma",
      "sistole",
      "situato",
      "slitta",
      "slogatura",
      "sloveno",
      "smarrito",
      "smemorato",
      "smentito",
      "smeraldo",
      "smilzo",
      "smontare",
      "smottato",
      "smussato",
      "snellire",
      "snervato",
      "snodo",
      "sobbalzo",
      "sobrio",
      "soccorso",
      "sociale",
      "sodale",
      "soffitto",
      "sogno",
      "soldato",
      "solenne",
      "solido",
      "sollazzo",
      "solo",
      "solubile",
      "solvente",
      "somatico",
      "somma",
      "sonda",
      "sonetto",
      "sonnifero",
      "sopire",
      "soppeso",
      "sopra",
      "sorgere",
      "sorpasso",
      "sorriso",
      "sorso",
      "sorteggio",
      "sorvolato",
      "sospiro",
      "sosta",
      "sottile",
      "spada",
      "spalla",
      "spargere",
      "spatola",
      "spavento",
      "spazzola",
      "specie",
      "spedire",
      "spegnere",
      "spelatura",
      "speranza",
      "spessore",
      "spettrale",
      "spezzato",
      "spia",
      "spigoloso",
      "spillato",
      "spinoso",
      "spirale",
      "splendido",
      "sportivo",
      "sposo",
      "spranga",
      "sprecare",
      "spronato",
      "spruzzo",
      "spuntino",
      "squillo",
      "sradicare",
      "srotolato",
      "stabile",
      "stacco",
      "staffa",
      "stagnare",
      "stampato",
      "stantio",
      "starnuto",
      "stasera",
      "statuto",
      "stelo",
      "steppa",
      "sterzo",
      "stiletto",
      "stima",
      "stirpe",
      "stivale",
      "stizzoso",
      "stonato",
      "storico",
      "strappo",
      "stregato",
      "stridulo",
      "strozzare",
      "strutto",
      "stuccare",
      "stufo",
      "stupendo",
      "subentro",
      "succoso",
      "sudore",
      "suggerito",
      "sugo",
      "sultano",
      "suonare",
      "superbo",
      "supporto",
      "surgelato",
      "surrogato",
      "sussurro",
      "sutura",
      "svagare",
      "svedese",
      "sveglio",
      "svelare",
      "svenuto",
      "svezia",
      "sviluppo",
      "svista",
      "svizzera",
      "svolta",
      "svuotare",
      "tabacco",
      "tabulato",
      "tacciare",
      "taciturno",
      "tale",
      "talismano",
      "tampone",
      "tannino",
      "tara",
      "tardivo",
      "targato",
      "tariffa",
      "tarpare",
      "tartaruga",
      "tasto",
      "tattico",
      "taverna",
      "tavolata",
      "tazza",
      "teca",
      "tecnico",
      "telefono",
      "temerario",
      "tempo",
      "temuto",
      "tendone",
      "tenero",
      "tensione",
      "tentacolo",
      "teorema",
      "terme",
      "terrazzo",
      "terzetto",
      "tesi",
      "tesserato",
      "testato",
      "tetro",
      "tettoia",
      "tifare",
      "tigella",
      "timbro",
      "tinto",
      "tipico",
      "tipografo",
      "tiraggio",
      "tiro",
      "titanio",
      "titolo",
      "titubante",
      "tizio",
      "tizzone",
      "toccare",
      "tollerare",
      "tolto",
      "tombola",
      "tomo",
      "tonfo",
      "tonsilla",
      "topazio",
      "topologia",
      "toppa",
      "torba",
      "tornare",
      "torrone",
      "tortora",
      "toscano",
      "tossire",
      "tostatura",
      "totano",
      "trabocco",
      "trachea",
      "trafila",
      "tragedia",
      "tralcio",
      "tramonto",
      "transito",
      "trapano",
      "trarre",
      "trasloco",
      "trattato",
      "trave",
      "treccia",
      "tremolio",
      "trespolo",
      "tributo",
      "tricheco",
      "trifoglio",
      "trillo",
      "trincea",
      "trio",
      "tristezza",
      "triturato",
      "trivella",
      "tromba",
      "trono",
      "troppo",
      "trottola",
      "trovare",
      "truccato",
      "tubatura",
      "tuffato",
      "tulipano",
      "tumulto",
      "tunisia",
      "turbare",
      "turchino",
      "tuta",
      "tutela",
      "ubicato",
      "uccello",
      "uccisore",
      "udire",
      "uditivo",
      "uffa",
      "ufficio",
      "uguale",
      "ulisse",
      "ultimato",
      "umano",
      "umile",
      "umorismo",
      "uncinetto",
      "ungere",
      "ungherese",
      "unicorno",
      "unificato",
      "unisono",
      "unitario",
      "unte",
      "uovo",
      "upupa",
      "uragano",
      "urgenza",
      "urlo",
      "usanza",
      "usato",
      "uscito",
      "usignolo",
      "usuraio",
      "utensile",
      "utilizzo",
      "utopia",
      "vacante",
      "vaccinato",
      "vagabondo",
      "vagliato",
      "valanga",
      "valgo",
      "valico",
      "valletta",
      "valoroso",
      "valutare",
      "valvola",
      "vampata",
      "vangare",
      "vanitoso",
      "vano",
      "vantaggio",
      "vanvera",
      "vapore",
      "varano",
      "varcato",
      "variante",
      "vasca",
      "vedetta",
      "vedova",
      "veduto",
      "vegetale",
      "veicolo",
      "velcro",
      "velina",
      "velluto",
      "veloce",
      "venato",
      "vendemmia",
      "vento",
      "verace",
      "verbale",
      "vergogna",
      "verifica",
      "vero",
      "verruca",
      "verticale",
      "vescica",
      "vessillo",
      "vestale",
      "veterano",
      "vetrina",
      "vetusto",
      "viandante",
      "vibrante",
      "vicenda",
      "vichingo",
      "vicinanza",
      "vidimare",
      "vigilia",
      "vigneto",
      "vigore",
      "vile",
      "villano",
      "vimini",
      "vincitore",
      "viola",
      "vipera",
      "virgola",
      "virologo",
      "virulento",
      "viscoso",
      "visione",
      "vispo",
      "vissuto",
      "visura",
      "vita",
      "vitello",
      "vittima",
      "vivanda",
      "vivido",
      "viziare",
      "voce",
      "voga",
      "volatile",
      "volere",
      "volpe",
      "voragine",
      "vulcano",
      "zampogna",
      "zanna",
      "zappato",
      "zattera",
      "zavorra",
      "zefiro",
      "zelante",
      "zelo",
      "zenzero",
      "zerbino",
      "zibetto",
      "zinco",
      "zircone",
      "zitto",
      "zolla",
      "zotico",
      "zucchero",
      "zufolo",
      "zulu",
      "zuppa"
    ];
  }
});

// node_modules/bip39/src/wordlists/spanish.json
var require_spanish = __commonJS({
  "node_modules/bip39/src/wordlists/spanish.json"(exports, module) {
    module.exports = [
      "a\u0301baco",
      "abdomen",
      "abeja",
      "abierto",
      "abogado",
      "abono",
      "aborto",
      "abrazo",
      "abrir",
      "abuelo",
      "abuso",
      "acabar",
      "academia",
      "acceso",
      "accio\u0301n",
      "aceite",
      "acelga",
      "acento",
      "aceptar",
      "a\u0301cido",
      "aclarar",
      "acne\u0301",
      "acoger",
      "acoso",
      "activo",
      "acto",
      "actriz",
      "actuar",
      "acudir",
      "acuerdo",
      "acusar",
      "adicto",
      "admitir",
      "adoptar",
      "adorno",
      "aduana",
      "adulto",
      "ae\u0301reo",
      "afectar",
      "aficio\u0301n",
      "afinar",
      "afirmar",
      "a\u0301gil",
      "agitar",
      "agoni\u0301a",
      "agosto",
      "agotar",
      "agregar",
      "agrio",
      "agua",
      "agudo",
      "a\u0301guila",
      "aguja",
      "ahogo",
      "ahorro",
      "aire",
      "aislar",
      "ajedrez",
      "ajeno",
      "ajuste",
      "alacra\u0301n",
      "alambre",
      "alarma",
      "alba",
      "a\u0301lbum",
      "alcalde",
      "aldea",
      "alegre",
      "alejar",
      "alerta",
      "aleta",
      "alfiler",
      "alga",
      "algodo\u0301n",
      "aliado",
      "aliento",
      "alivio",
      "alma",
      "almeja",
      "almi\u0301bar",
      "altar",
      "alteza",
      "altivo",
      "alto",
      "altura",
      "alumno",
      "alzar",
      "amable",
      "amante",
      "amapola",
      "amargo",
      "amasar",
      "a\u0301mbar",
      "a\u0301mbito",
      "ameno",
      "amigo",
      "amistad",
      "amor",
      "amparo",
      "amplio",
      "ancho",
      "anciano",
      "ancla",
      "andar",
      "ande\u0301n",
      "anemia",
      "a\u0301ngulo",
      "anillo",
      "a\u0301nimo",
      "ani\u0301s",
      "anotar",
      "antena",
      "antiguo",
      "antojo",
      "anual",
      "anular",
      "anuncio",
      "an\u0303adir",
      "an\u0303ejo",
      "an\u0303o",
      "apagar",
      "aparato",
      "apetito",
      "apio",
      "aplicar",
      "apodo",
      "aporte",
      "apoyo",
      "aprender",
      "aprobar",
      "apuesta",
      "apuro",
      "arado",
      "aran\u0303a",
      "arar",
      "a\u0301rbitro",
      "a\u0301rbol",
      "arbusto",
      "archivo",
      "arco",
      "arder",
      "ardilla",
      "arduo",
      "a\u0301rea",
      "a\u0301rido",
      "aries",
      "armoni\u0301a",
      "arne\u0301s",
      "aroma",
      "arpa",
      "arpo\u0301n",
      "arreglo",
      "arroz",
      "arruga",
      "arte",
      "artista",
      "asa",
      "asado",
      "asalto",
      "ascenso",
      "asegurar",
      "aseo",
      "asesor",
      "asiento",
      "asilo",
      "asistir",
      "asno",
      "asombro",
      "a\u0301spero",
      "astilla",
      "astro",
      "astuto",
      "asumir",
      "asunto",
      "atajo",
      "ataque",
      "atar",
      "atento",
      "ateo",
      "a\u0301tico",
      "atleta",
      "a\u0301tomo",
      "atraer",
      "atroz",
      "atu\u0301n",
      "audaz",
      "audio",
      "auge",
      "aula",
      "aumento",
      "ausente",
      "autor",
      "aval",
      "avance",
      "avaro",
      "ave",
      "avellana",
      "avena",
      "avestruz",
      "avio\u0301n",
      "aviso",
      "ayer",
      "ayuda",
      "ayuno",
      "azafra\u0301n",
      "azar",
      "azote",
      "azu\u0301car",
      "azufre",
      "azul",
      "baba",
      "babor",
      "bache",
      "bahi\u0301a",
      "baile",
      "bajar",
      "balanza",
      "balco\u0301n",
      "balde",
      "bambu\u0301",
      "banco",
      "banda",
      "ban\u0303o",
      "barba",
      "barco",
      "barniz",
      "barro",
      "ba\u0301scula",
      "basto\u0301n",
      "basura",
      "batalla",
      "bateri\u0301a",
      "batir",
      "batuta",
      "bau\u0301l",
      "bazar",
      "bebe\u0301",
      "bebida",
      "bello",
      "besar",
      "beso",
      "bestia",
      "bicho",
      "bien",
      "bingo",
      "blanco",
      "bloque",
      "blusa",
      "boa",
      "bobina",
      "bobo",
      "boca",
      "bocina",
      "boda",
      "bodega",
      "boina",
      "bola",
      "bolero",
      "bolsa",
      "bomba",
      "bondad",
      "bonito",
      "bono",
      "bonsa\u0301i",
      "borde",
      "borrar",
      "bosque",
      "bote",
      "boti\u0301n",
      "bo\u0301veda",
      "bozal",
      "bravo",
      "brazo",
      "brecha",
      "breve",
      "brillo",
      "brinco",
      "brisa",
      "broca",
      "broma",
      "bronce",
      "brote",
      "bruja",
      "brusco",
      "bruto",
      "buceo",
      "bucle",
      "bueno",
      "buey",
      "bufanda",
      "bufo\u0301n",
      "bu\u0301ho",
      "buitre",
      "bulto",
      "burbuja",
      "burla",
      "burro",
      "buscar",
      "butaca",
      "buzo\u0301n",
      "caballo",
      "cabeza",
      "cabina",
      "cabra",
      "cacao",
      "cada\u0301ver",
      "cadena",
      "caer",
      "cafe\u0301",
      "cai\u0301da",
      "caima\u0301n",
      "caja",
      "cajo\u0301n",
      "cal",
      "calamar",
      "calcio",
      "caldo",
      "calidad",
      "calle",
      "calma",
      "calor",
      "calvo",
      "cama",
      "cambio",
      "camello",
      "camino",
      "campo",
      "ca\u0301ncer",
      "candil",
      "canela",
      "canguro",
      "canica",
      "canto",
      "can\u0303a",
      "can\u0303o\u0301n",
      "caoba",
      "caos",
      "capaz",
      "capita\u0301n",
      "capote",
      "captar",
      "capucha",
      "cara",
      "carbo\u0301n",
      "ca\u0301rcel",
      "careta",
      "carga",
      "carin\u0303o",
      "carne",
      "carpeta",
      "carro",
      "carta",
      "casa",
      "casco",
      "casero",
      "caspa",
      "castor",
      "catorce",
      "catre",
      "caudal",
      "causa",
      "cazo",
      "cebolla",
      "ceder",
      "cedro",
      "celda",
      "ce\u0301lebre",
      "celoso",
      "ce\u0301lula",
      "cemento",
      "ceniza",
      "centro",
      "cerca",
      "cerdo",
      "cereza",
      "cero",
      "cerrar",
      "certeza",
      "ce\u0301sped",
      "cetro",
      "chacal",
      "chaleco",
      "champu\u0301",
      "chancla",
      "chapa",
      "charla",
      "chico",
      "chiste",
      "chivo",
      "choque",
      "choza",
      "chuleta",
      "chupar",
      "ciclo\u0301n",
      "ciego",
      "cielo",
      "cien",
      "cierto",
      "cifra",
      "cigarro",
      "cima",
      "cinco",
      "cine",
      "cinta",
      "cipre\u0301s",
      "circo",
      "ciruela",
      "cisne",
      "cita",
      "ciudad",
      "clamor",
      "clan",
      "claro",
      "clase",
      "clave",
      "cliente",
      "clima",
      "cli\u0301nica",
      "cobre",
      "coccio\u0301n",
      "cochino",
      "cocina",
      "coco",
      "co\u0301digo",
      "codo",
      "cofre",
      "coger",
      "cohete",
      "coji\u0301n",
      "cojo",
      "cola",
      "colcha",
      "colegio",
      "colgar",
      "colina",
      "collar",
      "colmo",
      "columna",
      "combate",
      "comer",
      "comida",
      "co\u0301modo",
      "compra",
      "conde",
      "conejo",
      "conga",
      "conocer",
      "consejo",
      "contar",
      "copa",
      "copia",
      "corazo\u0301n",
      "corbata",
      "corcho",
      "cordo\u0301n",
      "corona",
      "correr",
      "coser",
      "cosmos",
      "costa",
      "cra\u0301neo",
      "cra\u0301ter",
      "crear",
      "crecer",
      "crei\u0301do",
      "crema",
      "cri\u0301a",
      "crimen",
      "cripta",
      "crisis",
      "cromo",
      "cro\u0301nica",
      "croqueta",
      "crudo",
      "cruz",
      "cuadro",
      "cuarto",
      "cuatro",
      "cubo",
      "cubrir",
      "cuchara",
      "cuello",
      "cuento",
      "cuerda",
      "cuesta",
      "cueva",
      "cuidar",
      "culebra",
      "culpa",
      "culto",
      "cumbre",
      "cumplir",
      "cuna",
      "cuneta",
      "cuota",
      "cupo\u0301n",
      "cu\u0301pula",
      "curar",
      "curioso",
      "curso",
      "curva",
      "cutis",
      "dama",
      "danza",
      "dar",
      "dardo",
      "da\u0301til",
      "deber",
      "de\u0301bil",
      "de\u0301cada",
      "decir",
      "dedo",
      "defensa",
      "definir",
      "dejar",
      "delfi\u0301n",
      "delgado",
      "delito",
      "demora",
      "denso",
      "dental",
      "deporte",
      "derecho",
      "derrota",
      "desayuno",
      "deseo",
      "desfile",
      "desnudo",
      "destino",
      "desvi\u0301o",
      "detalle",
      "detener",
      "deuda",
      "di\u0301a",
      "diablo",
      "diadema",
      "diamante",
      "diana",
      "diario",
      "dibujo",
      "dictar",
      "diente",
      "dieta",
      "diez",
      "difi\u0301cil",
      "digno",
      "dilema",
      "diluir",
      "dinero",
      "directo",
      "dirigir",
      "disco",
      "disen\u0303o",
      "disfraz",
      "diva",
      "divino",
      "doble",
      "doce",
      "dolor",
      "domingo",
      "don",
      "donar",
      "dorado",
      "dormir",
      "dorso",
      "dos",
      "dosis",
      "drago\u0301n",
      "droga",
      "ducha",
      "duda",
      "duelo",
      "duen\u0303o",
      "dulce",
      "du\u0301o",
      "duque",
      "durar",
      "dureza",
      "duro",
      "e\u0301bano",
      "ebrio",
      "echar",
      "eco",
      "ecuador",
      "edad",
      "edicio\u0301n",
      "edificio",
      "editor",
      "educar",
      "efecto",
      "eficaz",
      "eje",
      "ejemplo",
      "elefante",
      "elegir",
      "elemento",
      "elevar",
      "elipse",
      "e\u0301lite",
      "elixir",
      "elogio",
      "eludir",
      "embudo",
      "emitir",
      "emocio\u0301n",
      "empate",
      "empen\u0303o",
      "empleo",
      "empresa",
      "enano",
      "encargo",
      "enchufe",
      "enci\u0301a",
      "enemigo",
      "enero",
      "enfado",
      "enfermo",
      "engan\u0303o",
      "enigma",
      "enlace",
      "enorme",
      "enredo",
      "ensayo",
      "ensen\u0303ar",
      "entero",
      "entrar",
      "envase",
      "envi\u0301o",
      "e\u0301poca",
      "equipo",
      "erizo",
      "escala",
      "escena",
      "escolar",
      "escribir",
      "escudo",
      "esencia",
      "esfera",
      "esfuerzo",
      "espada",
      "espejo",
      "espi\u0301a",
      "esposa",
      "espuma",
      "esqui\u0301",
      "estar",
      "este",
      "estilo",
      "estufa",
      "etapa",
      "eterno",
      "e\u0301tica",
      "etnia",
      "evadir",
      "evaluar",
      "evento",
      "evitar",
      "exacto",
      "examen",
      "exceso",
      "excusa",
      "exento",
      "exigir",
      "exilio",
      "existir",
      "e\u0301xito",
      "experto",
      "explicar",
      "exponer",
      "extremo",
      "fa\u0301brica",
      "fa\u0301bula",
      "fachada",
      "fa\u0301cil",
      "factor",
      "faena",
      "faja",
      "falda",
      "fallo",
      "falso",
      "faltar",
      "fama",
      "familia",
      "famoso",
      "farao\u0301n",
      "farmacia",
      "farol",
      "farsa",
      "fase",
      "fatiga",
      "fauna",
      "favor",
      "fax",
      "febrero",
      "fecha",
      "feliz",
      "feo",
      "feria",
      "feroz",
      "fe\u0301rtil",
      "fervor",
      "festi\u0301n",
      "fiable",
      "fianza",
      "fiar",
      "fibra",
      "ficcio\u0301n",
      "ficha",
      "fideo",
      "fiebre",
      "fiel",
      "fiera",
      "fiesta",
      "figura",
      "fijar",
      "fijo",
      "fila",
      "filete",
      "filial",
      "filtro",
      "fin",
      "finca",
      "fingir",
      "finito",
      "firma",
      "flaco",
      "flauta",
      "flecha",
      "flor",
      "flota",
      "fluir",
      "flujo",
      "flu\u0301or",
      "fobia",
      "foca",
      "fogata",
      "fogo\u0301n",
      "folio",
      "folleto",
      "fondo",
      "forma",
      "forro",
      "fortuna",
      "forzar",
      "fosa",
      "foto",
      "fracaso",
      "fra\u0301gil",
      "franja",
      "frase",
      "fraude",
      "frei\u0301r",
      "freno",
      "fresa",
      "fri\u0301o",
      "frito",
      "fruta",
      "fuego",
      "fuente",
      "fuerza",
      "fuga",
      "fumar",
      "funcio\u0301n",
      "funda",
      "furgo\u0301n",
      "furia",
      "fusil",
      "fu\u0301tbol",
      "futuro",
      "gacela",
      "gafas",
      "gaita",
      "gajo",
      "gala",
      "galeri\u0301a",
      "gallo",
      "gamba",
      "ganar",
      "gancho",
      "ganga",
      "ganso",
      "garaje",
      "garza",
      "gasolina",
      "gastar",
      "gato",
      "gavila\u0301n",
      "gemelo",
      "gemir",
      "gen",
      "ge\u0301nero",
      "genio",
      "gente",
      "geranio",
      "gerente",
      "germen",
      "gesto",
      "gigante",
      "gimnasio",
      "girar",
      "giro",
      "glaciar",
      "globo",
      "gloria",
      "gol",
      "golfo",
      "goloso",
      "golpe",
      "goma",
      "gordo",
      "gorila",
      "gorra",
      "gota",
      "goteo",
      "gozar",
      "grada",
      "gra\u0301fico",
      "grano",
      "grasa",
      "gratis",
      "grave",
      "grieta",
      "grillo",
      "gripe",
      "gris",
      "grito",
      "grosor",
      "gru\u0301a",
      "grueso",
      "grumo",
      "grupo",
      "guante",
      "guapo",
      "guardia",
      "guerra",
      "gui\u0301a",
      "guin\u0303o",
      "guion",
      "guiso",
      "guitarra",
      "gusano",
      "gustar",
      "haber",
      "ha\u0301bil",
      "hablar",
      "hacer",
      "hacha",
      "hada",
      "hallar",
      "hamaca",
      "harina",
      "haz",
      "hazan\u0303a",
      "hebilla",
      "hebra",
      "hecho",
      "helado",
      "helio",
      "hembra",
      "herir",
      "hermano",
      "he\u0301roe",
      "hervir",
      "hielo",
      "hierro",
      "hi\u0301gado",
      "higiene",
      "hijo",
      "himno",
      "historia",
      "hocico",
      "hogar",
      "hoguera",
      "hoja",
      "hombre",
      "hongo",
      "honor",
      "honra",
      "hora",
      "hormiga",
      "horno",
      "hostil",
      "hoyo",
      "hueco",
      "huelga",
      "huerta",
      "hueso",
      "huevo",
      "huida",
      "huir",
      "humano",
      "hu\u0301medo",
      "humilde",
      "humo",
      "hundir",
      "huraca\u0301n",
      "hurto",
      "icono",
      "ideal",
      "idioma",
      "i\u0301dolo",
      "iglesia",
      "iglu\u0301",
      "igual",
      "ilegal",
      "ilusio\u0301n",
      "imagen",
      "ima\u0301n",
      "imitar",
      "impar",
      "imperio",
      "imponer",
      "impulso",
      "incapaz",
      "i\u0301ndice",
      "inerte",
      "infiel",
      "informe",
      "ingenio",
      "inicio",
      "inmenso",
      "inmune",
      "innato",
      "insecto",
      "instante",
      "intere\u0301s",
      "i\u0301ntimo",
      "intuir",
      "inu\u0301til",
      "invierno",
      "ira",
      "iris",
      "ironi\u0301a",
      "isla",
      "islote",
      "jabali\u0301",
      "jabo\u0301n",
      "jamo\u0301n",
      "jarabe",
      "jardi\u0301n",
      "jarra",
      "jaula",
      "jazmi\u0301n",
      "jefe",
      "jeringa",
      "jinete",
      "jornada",
      "joroba",
      "joven",
      "joya",
      "juerga",
      "jueves",
      "juez",
      "jugador",
      "jugo",
      "juguete",
      "juicio",
      "junco",
      "jungla",
      "junio",
      "juntar",
      "ju\u0301piter",
      "jurar",
      "justo",
      "juvenil",
      "juzgar",
      "kilo",
      "koala",
      "labio",
      "lacio",
      "lacra",
      "lado",
      "ladro\u0301n",
      "lagarto",
      "la\u0301grima",
      "laguna",
      "laico",
      "lamer",
      "la\u0301mina",
      "la\u0301mpara",
      "lana",
      "lancha",
      "langosta",
      "lanza",
      "la\u0301piz",
      "largo",
      "larva",
      "la\u0301stima",
      "lata",
      "la\u0301tex",
      "latir",
      "laurel",
      "lavar",
      "lazo",
      "leal",
      "leccio\u0301n",
      "leche",
      "lector",
      "leer",
      "legio\u0301n",
      "legumbre",
      "lejano",
      "lengua",
      "lento",
      "len\u0303a",
      "leo\u0301n",
      "leopardo",
      "lesio\u0301n",
      "letal",
      "letra",
      "leve",
      "leyenda",
      "libertad",
      "libro",
      "licor",
      "li\u0301der",
      "lidiar",
      "lienzo",
      "liga",
      "ligero",
      "lima",
      "li\u0301mite",
      "limo\u0301n",
      "limpio",
      "lince",
      "lindo",
      "li\u0301nea",
      "lingote",
      "lino",
      "linterna",
      "li\u0301quido",
      "liso",
      "lista",
      "litera",
      "litio",
      "litro",
      "llaga",
      "llama",
      "llanto",
      "llave",
      "llegar",
      "llenar",
      "llevar",
      "llorar",
      "llover",
      "lluvia",
      "lobo",
      "locio\u0301n",
      "loco",
      "locura",
      "lo\u0301gica",
      "logro",
      "lombriz",
      "lomo",
      "lonja",
      "lote",
      "lucha",
      "lucir",
      "lugar",
      "lujo",
      "luna",
      "lunes",
      "lupa",
      "lustro",
      "luto",
      "luz",
      "maceta",
      "macho",
      "madera",
      "madre",
      "maduro",
      "maestro",
      "mafia",
      "magia",
      "mago",
      "mai\u0301z",
      "maldad",
      "maleta",
      "malla",
      "malo",
      "mama\u0301",
      "mambo",
      "mamut",
      "manco",
      "mando",
      "manejar",
      "manga",
      "maniqui\u0301",
      "manjar",
      "mano",
      "manso",
      "manta",
      "man\u0303ana",
      "mapa",
      "ma\u0301quina",
      "mar",
      "marco",
      "marea",
      "marfil",
      "margen",
      "marido",
      "ma\u0301rmol",
      "marro\u0301n",
      "martes",
      "marzo",
      "masa",
      "ma\u0301scara",
      "masivo",
      "matar",
      "materia",
      "matiz",
      "matriz",
      "ma\u0301ximo",
      "mayor",
      "mazorca",
      "mecha",
      "medalla",
      "medio",
      "me\u0301dula",
      "mejilla",
      "mejor",
      "melena",
      "melo\u0301n",
      "memoria",
      "menor",
      "mensaje",
      "mente",
      "menu\u0301",
      "mercado",
      "merengue",
      "me\u0301rito",
      "mes",
      "meso\u0301n",
      "meta",
      "meter",
      "me\u0301todo",
      "metro",
      "mezcla",
      "miedo",
      "miel",
      "miembro",
      "miga",
      "mil",
      "milagro",
      "militar",
      "millo\u0301n",
      "mimo",
      "mina",
      "minero",
      "mi\u0301nimo",
      "minuto",
      "miope",
      "mirar",
      "misa",
      "miseria",
      "misil",
      "mismo",
      "mitad",
      "mito",
      "mochila",
      "mocio\u0301n",
      "moda",
      "modelo",
      "moho",
      "mojar",
      "molde",
      "moler",
      "molino",
      "momento",
      "momia",
      "monarca",
      "moneda",
      "monja",
      "monto",
      "mon\u0303o",
      "morada",
      "morder",
      "moreno",
      "morir",
      "morro",
      "morsa",
      "mortal",
      "mosca",
      "mostrar",
      "motivo",
      "mover",
      "mo\u0301vil",
      "mozo",
      "mucho",
      "mudar",
      "mueble",
      "muela",
      "muerte",
      "muestra",
      "mugre",
      "mujer",
      "mula",
      "muleta",
      "multa",
      "mundo",
      "mun\u0303eca",
      "mural",
      "muro",
      "mu\u0301sculo",
      "museo",
      "musgo",
      "mu\u0301sica",
      "muslo",
      "na\u0301car",
      "nacio\u0301n",
      "nadar",
      "naipe",
      "naranja",
      "nariz",
      "narrar",
      "nasal",
      "natal",
      "nativo",
      "natural",
      "na\u0301usea",
      "naval",
      "nave",
      "navidad",
      "necio",
      "ne\u0301ctar",
      "negar",
      "negocio",
      "negro",
      "neo\u0301n",
      "nervio",
      "neto",
      "neutro",
      "nevar",
      "nevera",
      "nicho",
      "nido",
      "niebla",
      "nieto",
      "nin\u0303ez",
      "nin\u0303o",
      "ni\u0301tido",
      "nivel",
      "nobleza",
      "noche",
      "no\u0301mina",
      "noria",
      "norma",
      "norte",
      "nota",
      "noticia",
      "novato",
      "novela",
      "novio",
      "nube",
      "nuca",
      "nu\u0301cleo",
      "nudillo",
      "nudo",
      "nuera",
      "nueve",
      "nuez",
      "nulo",
      "nu\u0301mero",
      "nutria",
      "oasis",
      "obeso",
      "obispo",
      "objeto",
      "obra",
      "obrero",
      "observar",
      "obtener",
      "obvio",
      "oca",
      "ocaso",
      "oce\u0301ano",
      "ochenta",
      "ocho",
      "ocio",
      "ocre",
      "octavo",
      "octubre",
      "oculto",
      "ocupar",
      "ocurrir",
      "odiar",
      "odio",
      "odisea",
      "oeste",
      "ofensa",
      "oferta",
      "oficio",
      "ofrecer",
      "ogro",
      "oi\u0301do",
      "oi\u0301r",
      "ojo",
      "ola",
      "oleada",
      "olfato",
      "olivo",
      "olla",
      "olmo",
      "olor",
      "olvido",
      "ombligo",
      "onda",
      "onza",
      "opaco",
      "opcio\u0301n",
      "o\u0301pera",
      "opinar",
      "oponer",
      "optar",
      "o\u0301ptica",
      "opuesto",
      "oracio\u0301n",
      "orador",
      "oral",
      "o\u0301rbita",
      "orca",
      "orden",
      "oreja",
      "o\u0301rgano",
      "orgi\u0301a",
      "orgullo",
      "oriente",
      "origen",
      "orilla",
      "oro",
      "orquesta",
      "oruga",
      "osadi\u0301a",
      "oscuro",
      "osezno",
      "oso",
      "ostra",
      "oton\u0303o",
      "otro",
      "oveja",
      "o\u0301vulo",
      "o\u0301xido",
      "oxi\u0301geno",
      "oyente",
      "ozono",
      "pacto",
      "padre",
      "paella",
      "pa\u0301gina",
      "pago",
      "pai\u0301s",
      "pa\u0301jaro",
      "palabra",
      "palco",
      "paleta",
      "pa\u0301lido",
      "palma",
      "paloma",
      "palpar",
      "pan",
      "panal",
      "pa\u0301nico",
      "pantera",
      "pan\u0303uelo",
      "papa\u0301",
      "papel",
      "papilla",
      "paquete",
      "parar",
      "parcela",
      "pared",
      "parir",
      "paro",
      "pa\u0301rpado",
      "parque",
      "pa\u0301rrafo",
      "parte",
      "pasar",
      "paseo",
      "pasio\u0301n",
      "paso",
      "pasta",
      "pata",
      "patio",
      "patria",
      "pausa",
      "pauta",
      "pavo",
      "payaso",
      "peato\u0301n",
      "pecado",
      "pecera",
      "pecho",
      "pedal",
      "pedir",
      "pegar",
      "peine",
      "pelar",
      "peldan\u0303o",
      "pelea",
      "peligro",
      "pellejo",
      "pelo",
      "peluca",
      "pena",
      "pensar",
      "pen\u0303o\u0301n",
      "peo\u0301n",
      "peor",
      "pepino",
      "pequen\u0303o",
      "pera",
      "percha",
      "perder",
      "pereza",
      "perfil",
      "perico",
      "perla",
      "permiso",
      "perro",
      "persona",
      "pesa",
      "pesca",
      "pe\u0301simo",
      "pestan\u0303a",
      "pe\u0301talo",
      "petro\u0301leo",
      "pez",
      "pezun\u0303a",
      "picar",
      "picho\u0301n",
      "pie",
      "piedra",
      "pierna",
      "pieza",
      "pijama",
      "pilar",
      "piloto",
      "pimienta",
      "pino",
      "pintor",
      "pinza",
      "pin\u0303a",
      "piojo",
      "pipa",
      "pirata",
      "pisar",
      "piscina",
      "piso",
      "pista",
      "pito\u0301n",
      "pizca",
      "placa",
      "plan",
      "plata",
      "playa",
      "plaza",
      "pleito",
      "pleno",
      "plomo",
      "pluma",
      "plural",
      "pobre",
      "poco",
      "poder",
      "podio",
      "poema",
      "poesi\u0301a",
      "poeta",
      "polen",
      "polici\u0301a",
      "pollo",
      "polvo",
      "pomada",
      "pomelo",
      "pomo",
      "pompa",
      "poner",
      "porcio\u0301n",
      "portal",
      "posada",
      "poseer",
      "posible",
      "poste",
      "potencia",
      "potro",
      "pozo",
      "prado",
      "precoz",
      "pregunta",
      "premio",
      "prensa",
      "preso",
      "previo",
      "primo",
      "pri\u0301ncipe",
      "prisio\u0301n",
      "privar",
      "proa",
      "probar",
      "proceso",
      "producto",
      "proeza",
      "profesor",
      "programa",
      "prole",
      "promesa",
      "pronto",
      "propio",
      "pro\u0301ximo",
      "prueba",
      "pu\u0301blico",
      "puchero",
      "pudor",
      "pueblo",
      "puerta",
      "puesto",
      "pulga",
      "pulir",
      "pulmo\u0301n",
      "pulpo",
      "pulso",
      "puma",
      "punto",
      "pun\u0303al",
      "pun\u0303o",
      "pupa",
      "pupila",
      "pure\u0301",
      "quedar",
      "queja",
      "quemar",
      "querer",
      "queso",
      "quieto",
      "qui\u0301mica",
      "quince",
      "quitar",
      "ra\u0301bano",
      "rabia",
      "rabo",
      "racio\u0301n",
      "radical",
      "rai\u0301z",
      "rama",
      "rampa",
      "rancho",
      "rango",
      "rapaz",
      "ra\u0301pido",
      "rapto",
      "rasgo",
      "raspa",
      "rato",
      "rayo",
      "raza",
      "razo\u0301n",
      "reaccio\u0301n",
      "realidad",
      "reban\u0303o",
      "rebote",
      "recaer",
      "receta",
      "rechazo",
      "recoger",
      "recreo",
      "recto",
      "recurso",
      "red",
      "redondo",
      "reducir",
      "reflejo",
      "reforma",
      "refra\u0301n",
      "refugio",
      "regalo",
      "regir",
      "regla",
      "regreso",
      "rehe\u0301n",
      "reino",
      "rei\u0301r",
      "reja",
      "relato",
      "relevo",
      "relieve",
      "relleno",
      "reloj",
      "remar",
      "remedio",
      "remo",
      "rencor",
      "rendir",
      "renta",
      "reparto",
      "repetir",
      "reposo",
      "reptil",
      "res",
      "rescate",
      "resina",
      "respeto",
      "resto",
      "resumen",
      "retiro",
      "retorno",
      "retrato",
      "reunir",
      "reve\u0301s",
      "revista",
      "rey",
      "rezar",
      "rico",
      "riego",
      "rienda",
      "riesgo",
      "rifa",
      "ri\u0301gido",
      "rigor",
      "rinco\u0301n",
      "rin\u0303o\u0301n",
      "ri\u0301o",
      "riqueza",
      "risa",
      "ritmo",
      "rito",
      "rizo",
      "roble",
      "roce",
      "rociar",
      "rodar",
      "rodeo",
      "rodilla",
      "roer",
      "rojizo",
      "rojo",
      "romero",
      "romper",
      "ron",
      "ronco",
      "ronda",
      "ropa",
      "ropero",
      "rosa",
      "rosca",
      "rostro",
      "rotar",
      "rubi\u0301",
      "rubor",
      "rudo",
      "rueda",
      "rugir",
      "ruido",
      "ruina",
      "ruleta",
      "rulo",
      "rumbo",
      "rumor",
      "ruptura",
      "ruta",
      "rutina",
      "sa\u0301bado",
      "saber",
      "sabio",
      "sable",
      "sacar",
      "sagaz",
      "sagrado",
      "sala",
      "saldo",
      "salero",
      "salir",
      "salmo\u0301n",
      "salo\u0301n",
      "salsa",
      "salto",
      "salud",
      "salvar",
      "samba",
      "sancio\u0301n",
      "sandi\u0301a",
      "sanear",
      "sangre",
      "sanidad",
      "sano",
      "santo",
      "sapo",
      "saque",
      "sardina",
      "sarte\u0301n",
      "sastre",
      "sata\u0301n",
      "sauna",
      "saxofo\u0301n",
      "seccio\u0301n",
      "seco",
      "secreto",
      "secta",
      "sed",
      "seguir",
      "seis",
      "sello",
      "selva",
      "semana",
      "semilla",
      "senda",
      "sensor",
      "sen\u0303al",
      "sen\u0303or",
      "separar",
      "sepia",
      "sequi\u0301a",
      "ser",
      "serie",
      "sermo\u0301n",
      "servir",
      "sesenta",
      "sesio\u0301n",
      "seta",
      "setenta",
      "severo",
      "sexo",
      "sexto",
      "sidra",
      "siesta",
      "siete",
      "siglo",
      "signo",
      "si\u0301laba",
      "silbar",
      "silencio",
      "silla",
      "si\u0301mbolo",
      "simio",
      "sirena",
      "sistema",
      "sitio",
      "situar",
      "sobre",
      "socio",
      "sodio",
      "sol",
      "solapa",
      "soldado",
      "soledad",
      "so\u0301lido",
      "soltar",
      "solucio\u0301n",
      "sombra",
      "sondeo",
      "sonido",
      "sonoro",
      "sonrisa",
      "sopa",
      "soplar",
      "soporte",
      "sordo",
      "sorpresa",
      "sorteo",
      "soste\u0301n",
      "so\u0301tano",
      "suave",
      "subir",
      "suceso",
      "sudor",
      "suegra",
      "suelo",
      "suen\u0303o",
      "suerte",
      "sufrir",
      "sujeto",
      "sulta\u0301n",
      "sumar",
      "superar",
      "suplir",
      "suponer",
      "supremo",
      "sur",
      "surco",
      "suren\u0303o",
      "surgir",
      "susto",
      "sutil",
      "tabaco",
      "tabique",
      "tabla",
      "tabu\u0301",
      "taco",
      "tacto",
      "tajo",
      "talar",
      "talco",
      "talento",
      "talla",
      "talo\u0301n",
      "taman\u0303o",
      "tambor",
      "tango",
      "tanque",
      "tapa",
      "tapete",
      "tapia",
      "tapo\u0301n",
      "taquilla",
      "tarde",
      "tarea",
      "tarifa",
      "tarjeta",
      "tarot",
      "tarro",
      "tarta",
      "tatuaje",
      "tauro",
      "taza",
      "tazo\u0301n",
      "teatro",
      "techo",
      "tecla",
      "te\u0301cnica",
      "tejado",
      "tejer",
      "tejido",
      "tela",
      "tele\u0301fono",
      "tema",
      "temor",
      "templo",
      "tenaz",
      "tender",
      "tener",
      "tenis",
      "tenso",
      "teori\u0301a",
      "terapia",
      "terco",
      "te\u0301rmino",
      "ternura",
      "terror",
      "tesis",
      "tesoro",
      "testigo",
      "tetera",
      "texto",
      "tez",
      "tibio",
      "tiburo\u0301n",
      "tiempo",
      "tienda",
      "tierra",
      "tieso",
      "tigre",
      "tijera",
      "tilde",
      "timbre",
      "ti\u0301mido",
      "timo",
      "tinta",
      "ti\u0301o",
      "ti\u0301pico",
      "tipo",
      "tira",
      "tiro\u0301n",
      "tita\u0301n",
      "ti\u0301tere",
      "ti\u0301tulo",
      "tiza",
      "toalla",
      "tobillo",
      "tocar",
      "tocino",
      "todo",
      "toga",
      "toldo",
      "tomar",
      "tono",
      "tonto",
      "topar",
      "tope",
      "toque",
      "to\u0301rax",
      "torero",
      "tormenta",
      "torneo",
      "toro",
      "torpedo",
      "torre",
      "torso",
      "tortuga",
      "tos",
      "tosco",
      "toser",
      "to\u0301xico",
      "trabajo",
      "tractor",
      "traer",
      "tra\u0301fico",
      "trago",
      "traje",
      "tramo",
      "trance",
      "trato",
      "trauma",
      "trazar",
      "tre\u0301bol",
      "tregua",
      "treinta",
      "tren",
      "trepar",
      "tres",
      "tribu",
      "trigo",
      "tripa",
      "triste",
      "triunfo",
      "trofeo",
      "trompa",
      "tronco",
      "tropa",
      "trote",
      "trozo",
      "truco",
      "trueno",
      "trufa",
      "tuberi\u0301a",
      "tubo",
      "tuerto",
      "tumba",
      "tumor",
      "tu\u0301nel",
      "tu\u0301nica",
      "turbina",
      "turismo",
      "turno",
      "tutor",
      "ubicar",
      "u\u0301lcera",
      "umbral",
      "unidad",
      "unir",
      "universo",
      "uno",
      "untar",
      "un\u0303a",
      "urbano",
      "urbe",
      "urgente",
      "urna",
      "usar",
      "usuario",
      "u\u0301til",
      "utopi\u0301a",
      "uva",
      "vaca",
      "vaci\u0301o",
      "vacuna",
      "vagar",
      "vago",
      "vaina",
      "vajilla",
      "vale",
      "va\u0301lido",
      "valle",
      "valor",
      "va\u0301lvula",
      "vampiro",
      "vara",
      "variar",
      "varo\u0301n",
      "vaso",
      "vecino",
      "vector",
      "vehi\u0301culo",
      "veinte",
      "vejez",
      "vela",
      "velero",
      "veloz",
      "vena",
      "vencer",
      "venda",
      "veneno",
      "vengar",
      "venir",
      "venta",
      "venus",
      "ver",
      "verano",
      "verbo",
      "verde",
      "vereda",
      "verja",
      "verso",
      "verter",
      "vi\u0301a",
      "viaje",
      "vibrar",
      "vicio",
      "vi\u0301ctima",
      "vida",
      "vi\u0301deo",
      "vidrio",
      "viejo",
      "viernes",
      "vigor",
      "vil",
      "villa",
      "vinagre",
      "vino",
      "vin\u0303edo",
      "violi\u0301n",
      "viral",
      "virgo",
      "virtud",
      "visor",
      "vi\u0301spera",
      "vista",
      "vitamina",
      "viudo",
      "vivaz",
      "vivero",
      "vivir",
      "vivo",
      "volca\u0301n",
      "volumen",
      "volver",
      "voraz",
      "votar",
      "voto",
      "voz",
      "vuelo",
      "vulgar",
      "yacer",
      "yate",
      "yegua",
      "yema",
      "yerno",
      "yeso",
      "yodo",
      "yoga",
      "yogur",
      "zafiro",
      "zanja",
      "zapato",
      "zarza",
      "zona",
      "zorro",
      "zumo",
      "zurdo"
    ];
  }
});

// node_modules/bip39/src/wordlists/japanese.json
var require_japanese = __commonJS({
  "node_modules/bip39/src/wordlists/japanese.json"(exports, module) {
    module.exports = [
      "\u3042\u3044\u3053\u304F\u3057\u3093",
      "\u3042\u3044\u3055\u3064",
      "\u3042\u3044\u305F\u3099",
      "\u3042\u304A\u305D\u3099\u3089",
      "\u3042\u304B\u3061\u3083\u3093",
      "\u3042\u304D\u308B",
      "\u3042\u3051\u304B\u3099\u305F",
      "\u3042\u3051\u308B",
      "\u3042\u3053\u304B\u3099\u308C\u308B",
      "\u3042\u3055\u3044",
      "\u3042\u3055\u3072",
      "\u3042\u3057\u3042\u3068",
      "\u3042\u3057\u3099\u308F\u3046",
      "\u3042\u3059\u3099\u304B\u308B",
      "\u3042\u3059\u3099\u304D",
      "\u3042\u305D\u3075\u3099",
      "\u3042\u305F\u3048\u308B",
      "\u3042\u305F\u305F\u3081\u308B",
      "\u3042\u305F\u308A\u307E\u3048",
      "\u3042\u305F\u308B",
      "\u3042\u3064\u3044",
      "\u3042\u3064\u304B\u3046",
      "\u3042\u3063\u3057\u3085\u304F",
      "\u3042\u3064\u307E\u308A",
      "\u3042\u3064\u3081\u308B",
      "\u3042\u3066\u306A",
      "\u3042\u3066\u306F\u307E\u308B",
      "\u3042\u3072\u308B",
      "\u3042\u3075\u3099\u3089",
      "\u3042\u3075\u3099\u308B",
      "\u3042\u3075\u308C\u308B",
      "\u3042\u307E\u3044",
      "\u3042\u307E\u3068\u3099",
      "\u3042\u307E\u3084\u304B\u3059",
      "\u3042\u307E\u308A",
      "\u3042\u307F\u3082\u306E",
      "\u3042\u3081\u308A\u304B",
      "\u3042\u3084\u307E\u308B",
      "\u3042\u3086\u3080",
      "\u3042\u3089\u3044\u304F\u3099\u307E",
      "\u3042\u3089\u3057",
      "\u3042\u3089\u3059\u3057\u3099",
      "\u3042\u3089\u305F\u3081\u308B",
      "\u3042\u3089\u3086\u308B",
      "\u3042\u3089\u308F\u3059",
      "\u3042\u308A\u304B\u3099\u3068\u3046",
      "\u3042\u308F\u305B\u308B",
      "\u3042\u308F\u3066\u308B",
      "\u3042\u3093\u3044",
      "\u3042\u3093\u304B\u3099\u3044",
      "\u3042\u3093\u3053",
      "\u3042\u3093\u305B\u3099\u3093",
      "\u3042\u3093\u3066\u3044",
      "\u3042\u3093\u306A\u3044",
      "\u3042\u3093\u307E\u308A",
      "\u3044\u3044\u305F\u3099\u3059",
      "\u3044\u304A\u3093",
      "\u3044\u304B\u3099\u3044",
      "\u3044\u304B\u3099\u304F",
      "\u3044\u304D\u304A\u3044",
      "\u3044\u304D\u306A\u308A",
      "\u3044\u304D\u3082\u306E",
      "\u3044\u304D\u308B",
      "\u3044\u304F\u3057\u3099",
      "\u3044\u304F\u3075\u3099\u3093",
      "\u3044\u3051\u306F\u3099\u306A",
      "\u3044\u3051\u3093",
      "\u3044\u3053\u3046",
      "\u3044\u3053\u304F",
      "\u3044\u3053\u3064",
      "\u3044\u3055\u307E\u3057\u3044",
      "\u3044\u3055\u3093",
      "\u3044\u3057\u304D",
      "\u3044\u3057\u3099\u3085\u3046",
      "\u3044\u3057\u3099\u3087\u3046",
      "\u3044\u3057\u3099\u308F\u308B",
      "\u3044\u3059\u3099\u307F",
      "\u3044\u3059\u3099\u308C",
      "\u3044\u305B\u3044",
      "\u3044\u305B\u3048\u3072\u3099",
      "\u3044\u305B\u304B\u3044",
      "\u3044\u305B\u304D",
      "\u3044\u305B\u3099\u3093",
      "\u3044\u305D\u3046\u308D\u3046",
      "\u3044\u305D\u304B\u3099\u3057\u3044",
      "\u3044\u305F\u3099\u3044",
      "\u3044\u305F\u3099\u304F",
      "\u3044\u305F\u3059\u3099\u3089",
      "\u3044\u305F\u307F",
      "\u3044\u305F\u308A\u3042",
      "\u3044\u3061\u304A\u3046",
      "\u3044\u3061\u3057\u3099",
      "\u3044\u3061\u3068\u3099",
      "\u3044\u3061\u306F\u3099",
      "\u3044\u3061\u3075\u3099",
      "\u3044\u3061\u308A\u3085\u3046",
      "\u3044\u3064\u304B",
      "\u3044\u3063\u3057\u3085\u3093",
      "\u3044\u3063\u305B\u3044",
      "\u3044\u3063\u305D\u3046",
      "\u3044\u3063\u305F\u3093",
      "\u3044\u3063\u3061",
      "\u3044\u3063\u3066\u3044",
      "\u3044\u3063\u307B\u309A\u3046",
      "\u3044\u3066\u3055\u3099",
      "\u3044\u3066\u3093",
      "\u3044\u3068\u3099\u3046",
      "\u3044\u3068\u3053",
      "\u3044\u306A\u3044",
      "\u3044\u306A\u304B",
      "\u3044\u306D\u3080\u308A",
      "\u3044\u306E\u3061",
      "\u3044\u306E\u308B",
      "\u3044\u306F\u3064",
      "\u3044\u306F\u3099\u308B",
      "\u3044\u306F\u3093",
      "\u3044\u3072\u3099\u304D",
      "\u3044\u3072\u3093",
      "\u3044\u3075\u304F",
      "\u3044\u3078\u3093",
      "\u3044\u307B\u3046",
      "\u3044\u307F\u3093",
      "\u3044\u3082\u3046\u3068",
      "\u3044\u3082\u305F\u308C",
      "\u3044\u3082\u308A",
      "\u3044\u3084\u304B\u3099\u308B",
      "\u3044\u3084\u3059",
      "\u3044\u3088\u304B\u3093",
      "\u3044\u3088\u304F",
      "\u3044\u3089\u3044",
      "\u3044\u3089\u3059\u3068",
      "\u3044\u308A\u304F\u3099\u3061",
      "\u3044\u308A\u3087\u3046",
      "\u3044\u308C\u3044",
      "\u3044\u308C\u3082\u306E",
      "\u3044\u308C\u308B",
      "\u3044\u308D\u3048\u3093\u3072\u309A\u3064",
      "\u3044\u308F\u3044",
      "\u3044\u308F\u3046",
      "\u3044\u308F\u304B\u3093",
      "\u3044\u308F\u306F\u3099",
      "\u3044\u308F\u3086\u308B",
      "\u3044\u3093\u3051\u3099\u3093\u307E\u3081",
      "\u3044\u3093\u3055\u3064",
      "\u3044\u3093\u3057\u3087\u3046",
      "\u3044\u3093\u3088\u3046",
      "\u3046\u3048\u304D",
      "\u3046\u3048\u308B",
      "\u3046\u304A\u3055\u3099",
      "\u3046\u304B\u3099\u3044",
      "\u3046\u304B\u3075\u3099",
      "\u3046\u304B\u3078\u3099\u308B",
      "\u3046\u304D\u308F",
      "\u3046\u304F\u3089\u3044\u306A",
      "\u3046\u304F\u308C\u308C",
      "\u3046\u3051\u305F\u307E\u308F\u308B",
      "\u3046\u3051\u3064\u3051",
      "\u3046\u3051\u3068\u308B",
      "\u3046\u3051\u3082\u3064",
      "\u3046\u3051\u308B",
      "\u3046\u3053\u3099\u304B\u3059",
      "\u3046\u3053\u3099\u304F",
      "\u3046\u3053\u3093",
      "\u3046\u3055\u304D\u3099",
      "\u3046\u3057\u306A\u3046",
      "\u3046\u3057\u308D\u304B\u3099\u307F",
      "\u3046\u3059\u3044",
      "\u3046\u3059\u304D\u3099",
      "\u3046\u3059\u304F\u3099\u3089\u3044",
      "\u3046\u3059\u3081\u308B",
      "\u3046\u305B\u3064",
      "\u3046\u3061\u3042\u308F\u305B",
      "\u3046\u3061\u304B\u3099\u308F",
      "\u3046\u3061\u304D",
      "\u3046\u3061\u3085\u3046",
      "\u3046\u3063\u304B\u308A",
      "\u3046\u3064\u304F\u3057\u3044",
      "\u3046\u3063\u305F\u3048\u308B",
      "\u3046\u3064\u308B",
      "\u3046\u3068\u3099\u3093",
      "\u3046\u306A\u304D\u3099",
      "\u3046\u306A\u3057\u3099",
      "\u3046\u306A\u3059\u3099\u304F",
      "\u3046\u306A\u308B",
      "\u3046\u306D\u308B",
      "\u3046\u306E\u3046",
      "\u3046\u3075\u3099\u3051\u3099",
      "\u3046\u3075\u3099\u3053\u3099\u3048",
      "\u3046\u307E\u308C\u308B",
      "\u3046\u3081\u308B",
      "\u3046\u3082\u3046",
      "\u3046\u3084\u307E\u3046",
      "\u3046\u3088\u304F",
      "\u3046\u3089\u304B\u3099\u3048\u3059",
      "\u3046\u3089\u304F\u3099\u3061",
      "\u3046\u3089\u306A\u3044",
      "\u3046\u308A\u3042\u3051\u3099",
      "\u3046\u308A\u304D\u308C",
      "\u3046\u308B\u3055\u3044",
      "\u3046\u308C\u3057\u3044",
      "\u3046\u308C\u3086\u304D",
      "\u3046\u308C\u308B",
      "\u3046\u308D\u3053",
      "\u3046\u308F\u304D",
      "\u3046\u308F\u3055",
      "\u3046\u3093\u3053\u3046",
      "\u3046\u3093\u3061\u3093",
      "\u3046\u3093\u3066\u3093",
      "\u3046\u3093\u3068\u3099\u3046",
      "\u3048\u3044\u3048\u3093",
      "\u3048\u3044\u304B\u3099",
      "\u3048\u3044\u304D\u3087\u3046",
      "\u3048\u3044\u3053\u3099",
      "\u3048\u3044\u305B\u3044",
      "\u3048\u3044\u3075\u3099\u3093",
      "\u3048\u3044\u3088\u3046",
      "\u3048\u3044\u308F",
      "\u3048\u304A\u308A",
      "\u3048\u304B\u3099\u304A",
      "\u3048\u304B\u3099\u304F",
      "\u3048\u304D\u305F\u3044",
      "\u3048\u304F\u305B\u308B",
      "\u3048\u3057\u3083\u304F",
      "\u3048\u3059\u3066",
      "\u3048\u3064\u3089\u3093",
      "\u3048\u306E\u304F\u3099",
      "\u3048\u307B\u3046\u307E\u304D",
      "\u3048\u307B\u3093",
      "\u3048\u307E\u304D",
      "\u3048\u3082\u3057\u3099",
      "\u3048\u3082\u306E",
      "\u3048\u3089\u3044",
      "\u3048\u3089\u3075\u3099",
      "\u3048\u308A\u3042",
      "\u3048\u3093\u3048\u3093",
      "\u3048\u3093\u304B\u3044",
      "\u3048\u3093\u304D\u3099",
      "\u3048\u3093\u3051\u3099\u304D",
      "\u3048\u3093\u3057\u3085\u3046",
      "\u3048\u3093\u305B\u3099\u3064",
      "\u3048\u3093\u305D\u304F",
      "\u3048\u3093\u3061\u3087\u3046",
      "\u3048\u3093\u3068\u3064",
      "\u304A\u3044\u304B\u3051\u308B",
      "\u304A\u3044\u3053\u3059",
      "\u304A\u3044\u3057\u3044",
      "\u304A\u3044\u3064\u304F",
      "\u304A\u3046\u3048\u3093",
      "\u304A\u3046\u3055\u307E",
      "\u304A\u3046\u3057\u3099",
      "\u304A\u3046\u305B\u3064",
      "\u304A\u3046\u305F\u3044",
      "\u304A\u3046\u3075\u304F",
      "\u304A\u3046\u3078\u3099\u3044",
      "\u304A\u3046\u3088\u3046",
      "\u304A\u3048\u308B",
      "\u304A\u304A\u3044",
      "\u304A\u304A\u3046",
      "\u304A\u304A\u3068\u3099\u304A\u308A",
      "\u304A\u304A\u3084",
      "\u304A\u304A\u3088\u305D",
      "\u304A\u304B\u3048\u308A",
      "\u304A\u304B\u3059\u3099",
      "\u304A\u304B\u3099\u3080",
      "\u304A\u304B\u308F\u308A",
      "\u304A\u304D\u3099\u306A\u3046",
      "\u304A\u304D\u308B",
      "\u304A\u304F\u3055\u307E",
      "\u304A\u304F\u3057\u3099\u3087\u3046",
      "\u304A\u304F\u308A\u304B\u3099\u306A",
      "\u304A\u304F\u308B",
      "\u304A\u304F\u308C\u308B",
      "\u304A\u3053\u3059",
      "\u304A\u3053\u306A\u3046",
      "\u304A\u3053\u308B",
      "\u304A\u3055\u3048\u308B",
      "\u304A\u3055\u306A\u3044",
      "\u304A\u3055\u3081\u308B",
      "\u304A\u3057\u3044\u308C",
      "\u304A\u3057\u3048\u308B",
      "\u304A\u3057\u3099\u304D\u3099",
      "\u304A\u3057\u3099\u3055\u3093",
      "\u304A\u3057\u3083\u308C",
      "\u304A\u305D\u3089\u304F",
      "\u304A\u305D\u308F\u308B",
      "\u304A\u305F\u304B\u3099\u3044",
      "\u304A\u305F\u304F",
      "\u304A\u305F\u3099\u3084\u304B",
      "\u304A\u3061\u3064\u304F",
      "\u304A\u3063\u3068",
      "\u304A\u3064\u308A",
      "\u304A\u3066\u3099\u304B\u3051",
      "\u304A\u3068\u3057\u3082\u306E",
      "\u304A\u3068\u306A\u3057\u3044",
      "\u304A\u3068\u3099\u308A",
      "\u304A\u3068\u3099\u308D\u304B\u3059",
      "\u304A\u306F\u3099\u3055\u3093",
      "\u304A\u307E\u3044\u308A",
      "\u304A\u3081\u3066\u3099\u3068\u3046",
      "\u304A\u3082\u3044\u3066\u3099",
      "\u304A\u3082\u3046",
      "\u304A\u3082\u305F\u3044",
      "\u304A\u3082\u3061\u3083",
      "\u304A\u3084\u3064",
      "\u304A\u3084\u3086\u3072\u3099",
      "\u304A\u3088\u307B\u3099\u3059",
      "\u304A\u3089\u3093\u305F\u3099",
      "\u304A\u308D\u3059",
      "\u304A\u3093\u304B\u3099\u304F",
      "\u304A\u3093\u3051\u3044",
      "\u304A\u3093\u3057\u3083",
      "\u304A\u3093\u305B\u3093",
      "\u304A\u3093\u305F\u3099\u3093",
      "\u304A\u3093\u3061\u3085\u3046",
      "\u304A\u3093\u3068\u3099\u3051\u3044",
      "\u304B\u3042\u3064",
      "\u304B\u3044\u304B\u3099",
      "\u304B\u3099\u3044\u304D",
      "\u304B\u3099\u3044\u3051\u3093",
      "\u304B\u3099\u3044\u3053\u3046",
      "\u304B\u3044\u3055\u3064",
      "\u304B\u3044\u3057\u3083",
      "\u304B\u3044\u3059\u3044\u3088\u304F",
      "\u304B\u3044\u305B\u3099\u3093",
      "\u304B\u3044\u305D\u3099\u3046\u3068\u3099",
      "\u304B\u3044\u3064\u3046",
      "\u304B\u3044\u3066\u3093",
      "\u304B\u3044\u3068\u3046",
      "\u304B\u3044\u3075\u304F",
      "\u304B\u3099\u3044\u3078\u304D",
      "\u304B\u3044\u307B\u3046",
      "\u304B\u3044\u3088\u3046",
      "\u304B\u3099\u3044\u3089\u3044",
      "\u304B\u3044\u308F",
      "\u304B\u3048\u308B",
      "\u304B\u304A\u308A",
      "\u304B\u304B\u3048\u308B",
      "\u304B\u304B\u3099\u304F",
      "\u304B\u304B\u3099\u3057",
      "\u304B\u304B\u3099\u307F",
      "\u304B\u304F\u3053\u3099",
      "\u304B\u304F\u3068\u304F",
      "\u304B\u3055\u3099\u308B",
      "\u304B\u3099\u305D\u3099\u3046",
      "\u304B\u305F\u3044",
      "\u304B\u305F\u3061",
      "\u304B\u3099\u3061\u3087\u3046",
      "\u304B\u3099\u3063\u304D\u3085\u3046",
      "\u304B\u3099\u3063\u3053\u3046",
      "\u304B\u3099\u3063\u3055\u3093",
      "\u304B\u3099\u3063\u3057\u3087\u3046",
      "\u304B\u306A\u3055\u3099\u308F\u3057",
      "\u304B\u306E\u3046",
      "\u304B\u3099\u306F\u304F",
      "\u304B\u3075\u3099\u304B",
      "\u304B\u307B\u3046",
      "\u304B\u307B\u3053\u3099",
      "\u304B\u307E\u3046",
      "\u304B\u307E\u307B\u3099\u3053",
      "\u304B\u3081\u308C\u304A\u3093",
      "\u304B\u3086\u3044",
      "\u304B\u3088\u3046\u3072\u3099",
      "\u304B\u3089\u3044",
      "\u304B\u308B\u3044",
      "\u304B\u308D\u3046",
      "\u304B\u308F\u304F",
      "\u304B\u308F\u3089",
      "\u304B\u3099\u3093\u304B",
      "\u304B\u3093\u3051\u3044",
      "\u304B\u3093\u3053\u3046",
      "\u304B\u3093\u3057\u3083",
      "\u304B\u3093\u305D\u3046",
      "\u304B\u3093\u305F\u3093",
      "\u304B\u3093\u3061",
      "\u304B\u3099\u3093\u306F\u3099\u308B",
      "\u304D\u3042\u3044",
      "\u304D\u3042\u3064",
      "\u304D\u3044\u308D",
      "\u304D\u3099\u3044\u3093",
      "\u304D\u3046\u3044",
      "\u304D\u3046\u3093",
      "\u304D\u3048\u308B",
      "\u304D\u304A\u3046",
      "\u304D\u304A\u304F",
      "\u304D\u304A\u3061",
      "\u304D\u304A\u3093",
      "\u304D\u304B\u3044",
      "\u304D\u304B\u304F",
      "\u304D\u304B\u3093\u3057\u3083",
      "\u304D\u304D\u3066",
      "\u304D\u304F\u306F\u3099\u308A",
      "\u304D\u304F\u3089\u3051\u3099",
      "\u304D\u3051\u3093\u305B\u3044",
      "\u304D\u3053\u3046",
      "\u304D\u3053\u3048\u308B",
      "\u304D\u3053\u304F",
      "\u304D\u3055\u3044",
      "\u304D\u3055\u304F",
      "\u304D\u3055\u307E",
      "\u304D\u3055\u3089\u304D\u3099",
      "\u304D\u3099\u3057\u3099\u304B\u304B\u3099\u304F",
      "\u304D\u3099\u3057\u304D",
      "\u304D\u3099\u3057\u3099\u305F\u3044\u3051\u3093",
      "\u304D\u3099\u3057\u3099\u306B\u3063\u3066\u3044",
      "\u304D\u3099\u3057\u3099\u3085\u3064\u3057\u3083",
      "\u304D\u3059\u3046",
      "\u304D\u305B\u3044",
      "\u304D\u305B\u304D",
      "\u304D\u305B\u3064",
      "\u304D\u305D\u3046",
      "\u304D\u305D\u3099\u304F",
      "\u304D\u305D\u3099\u3093",
      "\u304D\u305F\u3048\u308B",
      "\u304D\u3061\u3087\u3046",
      "\u304D\u3064\u3048\u3093",
      "\u304D\u3099\u3063\u3061\u308A",
      "\u304D\u3064\u3064\u304D",
      "\u304D\u3064\u306D",
      "\u304D\u3066\u3044",
      "\u304D\u3068\u3099\u3046",
      "\u304D\u3068\u3099\u304F",
      "\u304D\u306A\u3044",
      "\u304D\u306A\u304B\u3099",
      "\u304D\u306A\u3053",
      "\u304D\u306C\u3053\u3099\u3057",
      "\u304D\u306D\u3093",
      "\u304D\u306E\u3046",
      "\u304D\u306E\u3057\u305F",
      "\u304D\u306F\u304F",
      "\u304D\u3072\u3099\u3057\u3044",
      "\u304D\u3072\u3093",
      "\u304D\u3075\u304F",
      "\u304D\u3075\u3099\u3093",
      "\u304D\u307B\u3099\u3046",
      "\u304D\u307B\u3093",
      "\u304D\u307E\u308B",
      "\u304D\u307F\u3064",
      "\u304D\u3080\u3059\u3099\u304B\u3057\u3044",
      "\u304D\u3081\u308B",
      "\u304D\u3082\u305F\u3099\u3081\u3057",
      "\u304D\u3082\u3061",
      "\u304D\u3082\u306E",
      "\u304D\u3083\u304F",
      "\u304D\u3084\u304F",
      "\u304D\u3099\u3085\u3046\u306B\u304F",
      "\u304D\u3088\u3046",
      "\u304D\u3087\u3046\u308A\u3085\u3046",
      "\u304D\u3089\u3044",
      "\u304D\u3089\u304F",
      "\u304D\u308A\u3093",
      "\u304D\u308C\u3044",
      "\u304D\u308C\u3064",
      "\u304D\u308D\u304F",
      "\u304D\u3099\u308D\u3093",
      "\u304D\u308F\u3081\u308B",
      "\u304D\u3099\u3093\u3044\u308D",
      "\u304D\u3093\u304B\u304F\u3057\u3099",
      "\u304D\u3093\u3057\u3099\u3087",
      "\u304D\u3093\u3088\u3046\u3072\u3099",
      "\u304F\u3099\u3042\u3044",
      "\u304F\u3044\u3059\u3099",
      "\u304F\u3046\u304B\u3093",
      "\u304F\u3046\u304D",
      "\u304F\u3046\u304F\u3099\u3093",
      "\u304F\u3046\u3053\u3046",
      "\u304F\u3099\u3046\u305B\u3044",
      "\u304F\u3046\u305D\u3046",
      "\u304F\u3099\u3046\u305F\u3089",
      "\u304F\u3046\u3075\u304F",
      "\u304F\u3046\u307B\u3099",
      "\u304F\u304B\u3093",
      "\u304F\u304D\u3087\u3046",
      "\u304F\u3051\u3099\u3093",
      "\u304F\u3099\u3053\u3046",
      "\u304F\u3055\u3044",
      "\u304F\u3055\u304D",
      "\u304F\u3055\u306F\u3099\u306A",
      "\u304F\u3055\u308B",
      "\u304F\u3057\u3083\u307F",
      "\u304F\u3057\u3087\u3046",
      "\u304F\u3059\u306E\u304D",
      "\u304F\u3059\u308A\u3086\u3072\u3099",
      "\u304F\u305B\u3051\u3099",
      "\u304F\u305B\u3093",
      "\u304F\u3099\u305F\u3044\u3066\u304D",
      "\u304F\u305F\u3099\u3055\u308B",
      "\u304F\u305F\u3072\u3099\u308C\u308B",
      "\u304F\u3061\u3053\u307F",
      "\u304F\u3061\u3055\u304D",
      "\u304F\u3064\u3057\u305F",
      "\u304F\u3099\u3063\u3059\u308A",
      "\u304F\u3064\u308D\u304F\u3099",
      "\u304F\u3068\u3046\u3066\u3093",
      "\u304F\u3068\u3099\u304F",
      "\u304F\u306A\u3093",
      "\u304F\u306D\u304F\u306D",
      "\u304F\u306E\u3046",
      "\u304F\u3075\u3046",
      "\u304F\u307F\u3042\u308F\u305B",
      "\u304F\u307F\u305F\u3066\u308B",
      "\u304F\u3081\u308B",
      "\u304F\u3084\u304F\u3057\u3087",
      "\u304F\u3089\u3059",
      "\u304F\u3089\u3078\u3099\u308B",
      "\u304F\u308B\u307E",
      "\u304F\u308C\u308B",
      "\u304F\u308D\u3046",
      "\u304F\u308F\u3057\u3044",
      "\u304F\u3099\u3093\u304B\u3093",
      "\u304F\u3099\u3093\u3057\u3087\u304F",
      "\u304F\u3099\u3093\u305F\u3044",
      "\u304F\u3099\u3093\u3066",
      "\u3051\u3042\u306A",
      "\u3051\u3044\u304B\u304F",
      "\u3051\u3044\u3051\u3093",
      "\u3051\u3044\u3053",
      "\u3051\u3044\u3055\u3064",
      "\u3051\u3099\u3044\u3057\u3099\u3085\u3064",
      "\u3051\u3044\u305F\u3044",
      "\u3051\u3099\u3044\u306E\u3046\u3057\u3099\u3093",
      "\u3051\u3044\u308C\u304D",
      "\u3051\u3044\u308D",
      "\u3051\u304A\u3068\u3059",
      "\u3051\u304A\u308A\u3082\u306E",
      "\u3051\u3099\u304D\u304B",
      "\u3051\u3099\u304D\u3051\u3099\u3093",
      "\u3051\u3099\u304D\u305F\u3099\u3093",
      "\u3051\u3099\u304D\u3061\u3093",
      "\u3051\u3099\u304D\u3068\u3064",
      "\u3051\u3099\u304D\u306F",
      "\u3051\u3099\u304D\u3084\u304F",
      "\u3051\u3099\u3053\u3046",
      "\u3051\u3099\u3053\u304F\u3057\u3099\u3087\u3046",
      "\u3051\u3099\u3055\u3099\u3044",
      "\u3051\u3055\u304D",
      "\u3051\u3099\u3055\u3099\u3093",
      "\u3051\u3057\u304D",
      "\u3051\u3057\u3053\u3099\u3080",
      "\u3051\u3057\u3087\u3046",
      "\u3051\u3099\u3059\u3068",
      "\u3051\u305F\u306F\u3099",
      "\u3051\u3061\u3083\u3063\u3075\u309A",
      "\u3051\u3061\u3089\u3059",
      "\u3051\u3064\u3042\u3064",
      "\u3051\u3064\u3044",
      "\u3051\u3064\u3048\u304D",
      "\u3051\u3063\u3053\u3093",
      "\u3051\u3064\u3057\u3099\u3087",
      "\u3051\u3063\u305B\u304D",
      "\u3051\u3063\u3066\u3044",
      "\u3051\u3064\u307E\u3064",
      "\u3051\u3099\u3064\u3088\u3046\u3072\u3099",
      "\u3051\u3099\u3064\u308C\u3044",
      "\u3051\u3064\u308D\u3093",
      "\u3051\u3099\u3068\u3099\u304F",
      "\u3051\u3068\u306F\u3099\u3059",
      "\u3051\u3068\u308B",
      "\u3051\u306A\u3051\u3099",
      "\u3051\u306A\u3059",
      "\u3051\u306A\u307F",
      "\u3051\u306C\u304D",
      "\u3051\u3099\u306D\u3064",
      "\u3051\u306D\u3093",
      "\u3051\u306F\u3044",
      "\u3051\u3099\u3072\u3093",
      "\u3051\u3075\u3099\u304B\u3044",
      "\u3051\u3099\u307B\u3099\u304F",
      "\u3051\u307E\u308A",
      "\u3051\u307F\u304B\u308B",
      "\u3051\u3080\u3057",
      "\u3051\u3080\u308A",
      "\u3051\u3082\u306E",
      "\u3051\u3089\u3044",
      "\u3051\u308D\u3051\u308D",
      "\u3051\u308F\u3057\u3044",
      "\u3051\u3093\u3044",
      "\u3051\u3093\u3048\u3064",
      "\u3051\u3093\u304A",
      "\u3051\u3093\u304B",
      "\u3051\u3099\u3093\u304D",
      "\u3051\u3093\u3051\u3099\u3093",
      "\u3051\u3093\u3053\u3046",
      "\u3051\u3093\u3055\u304F",
      "\u3051\u3093\u3057\u3085\u3046",
      "\u3051\u3093\u3059\u3046",
      "\u3051\u3099\u3093\u305D\u3046",
      "\u3051\u3093\u3061\u304F",
      "\u3051\u3093\u3066\u3044",
      "\u3051\u3093\u3068\u3046",
      "\u3051\u3093\u306A\u3044",
      "\u3051\u3093\u306B\u3093",
      "\u3051\u3099\u3093\u3075\u3099\u3064",
      "\u3051\u3093\u307E",
      "\u3051\u3093\u307F\u3093",
      "\u3051\u3093\u3081\u3044",
      "\u3051\u3093\u3089\u3093",
      "\u3051\u3093\u308A",
      "\u3053\u3042\u304F\u307E",
      "\u3053\u3044\u306C",
      "\u3053\u3044\u3072\u3099\u3068",
      "\u3053\u3099\u3046\u3044",
      "\u3053\u3046\u3048\u3093",
      "\u3053\u3046\u304A\u3093",
      "\u3053\u3046\u304B\u3093",
      "\u3053\u3099\u3046\u304D\u3085\u3046",
      "\u3053\u3099\u3046\u3051\u3044",
      "\u3053\u3046\u3053\u3046",
      "\u3053\u3046\u3055\u3044",
      "\u3053\u3046\u3057\u3099",
      "\u3053\u3046\u3059\u3044",
      "\u3053\u3099\u3046\u305B\u3044",
      "\u3053\u3046\u305D\u304F",
      "\u3053\u3046\u305F\u3044",
      "\u3053\u3046\u3061\u3083",
      "\u3053\u3046\u3064\u3046",
      "\u3053\u3046\u3066\u3044",
      "\u3053\u3046\u3068\u3099\u3046",
      "\u3053\u3046\u306A\u3044",
      "\u3053\u3046\u306F\u3044",
      "\u3053\u3099\u3046\u307B\u3046",
      "\u3053\u3099\u3046\u307E\u3093",
      "\u3053\u3046\u3082\u304F",
      "\u3053\u3046\u308A\u3064",
      "\u3053\u3048\u308B",
      "\u3053\u304A\u308A",
      "\u3053\u3099\u304B\u3044",
      "\u3053\u3099\u304B\u3099\u3064",
      "\u3053\u3099\u304B\u3093",
      "\u3053\u304F\u3053\u3099",
      "\u3053\u304F\u3055\u3044",
      "\u3053\u304F\u3068\u3046",
      "\u3053\u304F\u306A\u3044",
      "\u3053\u304F\u306F\u304F",
      "\u3053\u304F\u3099\u307E",
      "\u3053\u3051\u3044",
      "\u3053\u3051\u308B",
      "\u3053\u3053\u306E\u304B",
      "\u3053\u3053\u308D",
      "\u3053\u3055\u3081",
      "\u3053\u3057\u3064",
      "\u3053\u3059\u3046",
      "\u3053\u305B\u3044",
      "\u3053\u305B\u304D",
      "\u3053\u305B\u3099\u3093",
      "\u3053\u305D\u305F\u3099\u3066",
      "\u3053\u305F\u3044",
      "\u3053\u305F\u3048\u308B",
      "\u3053\u305F\u3064",
      "\u3053\u3061\u3087\u3046",
      "\u3053\u3063\u304B",
      "\u3053\u3064\u3053\u3064",
      "\u3053\u3064\u306F\u3099\u3093",
      "\u3053\u3064\u3075\u3099",
      "\u3053\u3066\u3044",
      "\u3053\u3066\u3093",
      "\u3053\u3068\u304B\u3099\u3089",
      "\u3053\u3068\u3057",
      "\u3053\u3068\u306F\u3099",
      "\u3053\u3068\u308A",
      "\u3053\u306A\u3053\u3099\u306A",
      "\u3053\u306D\u3053\u306D",
      "\u3053\u306E\u307E\u307E",
      "\u3053\u306E\u307F",
      "\u3053\u306E\u3088",
      "\u3053\u3099\u306F\u3093",
      "\u3053\u3072\u3064\u3057\u3099",
      "\u3053\u3075\u3046",
      "\u3053\u3075\u3093",
      "\u3053\u307B\u3099\u308C\u308B",
      "\u3053\u3099\u307E\u3042\u3075\u3099\u3089",
      "\u3053\u307E\u304B\u3044",
      "\u3053\u3099\u307E\u3059\u308A",
      "\u3053\u307E\u3064\u306A",
      "\u3053\u307E\u308B",
      "\u3053\u3080\u304D\u3099\u3053",
      "\u3053\u3082\u3057\u3099",
      "\u3053\u3082\u3061",
      "\u3053\u3082\u306E",
      "\u3053\u3082\u3093",
      "\u3053\u3084\u304F",
      "\u3053\u3084\u307E",
      "\u3053\u3086\u3046",
      "\u3053\u3086\u3072\u3099",
      "\u3053\u3088\u3044",
      "\u3053\u3088\u3046",
      "\u3053\u308A\u308B",
      "\u3053\u308C\u304F\u3057\u3087\u3093",
      "\u3053\u308D\u3063\u3051",
      "\u3053\u308F\u3082\u3066",
      "\u3053\u308F\u308C\u308B",
      "\u3053\u3093\u3044\u3093",
      "\u3053\u3093\u304B\u3044",
      "\u3053\u3093\u304D",
      "\u3053\u3093\u3057\u3085\u3046",
      "\u3053\u3093\u3059\u3044",
      "\u3053\u3093\u305F\u3099\u3066",
      "\u3053\u3093\u3068\u3093",
      "\u3053\u3093\u306A\u3093",
      "\u3053\u3093\u3072\u3099\u306B",
      "\u3053\u3093\u307B\u309A\u3093",
      "\u3053\u3093\u307E\u3051",
      "\u3053\u3093\u3084",
      "\u3053\u3093\u308C\u3044",
      "\u3053\u3093\u308F\u304F",
      "\u3055\u3099\u3044\u3048\u304D",
      "\u3055\u3044\u304B\u3044",
      "\u3055\u3044\u304D\u3093",
      "\u3055\u3099\u3044\u3051\u3099\u3093",
      "\u3055\u3099\u3044\u3053",
      "\u3055\u3044\u3057\u3087",
      "\u3055\u3044\u305B\u3044",
      "\u3055\u3099\u3044\u305F\u304F",
      "\u3055\u3099\u3044\u3061\u3085\u3046",
      "\u3055\u3044\u3066\u304D",
      "\u3055\u3099\u3044\u308A\u3087\u3046",
      "\u3055\u3046\u306A",
      "\u3055\u304B\u3044\u3057",
      "\u3055\u304B\u3099\u3059",
      "\u3055\u304B\u306A",
      "\u3055\u304B\u307F\u3061",
      "\u3055\u304B\u3099\u308B",
      "\u3055\u304D\u3099\u3087\u3046",
      "\u3055\u304F\u3057",
      "\u3055\u304F\u3072\u3093",
      "\u3055\u304F\u3089",
      "\u3055\u3053\u304F",
      "\u3055\u3053\u3064",
      "\u3055\u3059\u3099\u304B\u308B",
      "\u3055\u3099\u305B\u304D",
      "\u3055\u305F\u3093",
      "\u3055\u3064\u3048\u3044",
      "\u3055\u3099\u3064\u304A\u3093",
      "\u3055\u3099\u3063\u304B",
      "\u3055\u3099\u3064\u304B\u3099\u304F",
      "\u3055\u3063\u304D\u3087\u304F",
      "\u3055\u3099\u3063\u3057",
      "\u3055\u3064\u3057\u3099\u3093",
      "\u3055\u3099\u3063\u305D\u3046",
      "\u3055\u3064\u305F\u306F\u3099",
      "\u3055\u3064\u307E\u3044\u3082",
      "\u3055\u3066\u3044",
      "\u3055\u3068\u3044\u3082",
      "\u3055\u3068\u3046",
      "\u3055\u3068\u304A\u3084",
      "\u3055\u3068\u3057",
      "\u3055\u3068\u308B",
      "\u3055\u306E\u3046",
      "\u3055\u306F\u3099\u304F",
      "\u3055\u3072\u3099\u3057\u3044",
      "\u3055\u3078\u3099\u3064",
      "\u3055\u307B\u3046",
      "\u3055\u307B\u3068\u3099",
      "\u3055\u307E\u3059",
      "\u3055\u307F\u3057\u3044",
      "\u3055\u307F\u305F\u3099\u308C",
      "\u3055\u3080\u3051",
      "\u3055\u3081\u308B",
      "\u3055\u3084\u3048\u3093\u3068\u3099\u3046",
      "\u3055\u3086\u3046",
      "\u3055\u3088\u3046",
      "\u3055\u3088\u304F",
      "\u3055\u3089\u305F\u3099",
      "\u3055\u3099\u308B\u305D\u306F\u3099",
      "\u3055\u308F\u3084\u304B",
      "\u3055\u308F\u308B",
      "\u3055\u3093\u3044\u3093",
      "\u3055\u3093\u304B",
      "\u3055\u3093\u304D\u3083\u304F",
      "\u3055\u3093\u3053\u3046",
      "\u3055\u3093\u3055\u3044",
      "\u3055\u3099\u3093\u3057\u3087",
      "\u3055\u3093\u3059\u3046",
      "\u3055\u3093\u305B\u3044",
      "\u3055\u3093\u305D",
      "\u3055\u3093\u3061",
      "\u3055\u3093\u307E",
      "\u3055\u3093\u307F",
      "\u3055\u3093\u3089\u3093",
      "\u3057\u3042\u3044",
      "\u3057\u3042\u3051\u3099",
      "\u3057\u3042\u3055\u3063\u3066",
      "\u3057\u3042\u308F\u305B",
      "\u3057\u3044\u304F",
      "\u3057\u3044\u3093",
      "\u3057\u3046\u3061",
      "\u3057\u3048\u3044",
      "\u3057\u304A\u3051",
      "\u3057\u304B\u3044",
      "\u3057\u304B\u304F",
      "\u3057\u3099\u304B\u3093",
      "\u3057\u3053\u3099\u3068",
      "\u3057\u3059\u3046",
      "\u3057\u3099\u305F\u3099\u3044",
      "\u3057\u305F\u3046\u3051",
      "\u3057\u305F\u304D\u3099",
      "\u3057\u305F\u3066",
      "\u3057\u305F\u307F",
      "\u3057\u3061\u3087\u3046",
      "\u3057\u3061\u308A\u3093",
      "\u3057\u3063\u304B\u308A",
      "\u3057\u3064\u3057\u3099",
      "\u3057\u3064\u3082\u3093",
      "\u3057\u3066\u3044",
      "\u3057\u3066\u304D",
      "\u3057\u3066\u3064",
      "\u3057\u3099\u3066\u3093",
      "\u3057\u3099\u3068\u3099\u3046",
      "\u3057\u306A\u304D\u3099\u308C",
      "\u3057\u306A\u3082\u306E",
      "\u3057\u306A\u3093",
      "\u3057\u306D\u307E",
      "\u3057\u306D\u3093",
      "\u3057\u306E\u304F\u3099",
      "\u3057\u306E\u3075\u3099",
      "\u3057\u306F\u3044",
      "\u3057\u306F\u3099\u304B\u308A",
      "\u3057\u306F\u3064",
      "\u3057\u306F\u3089\u3044",
      "\u3057\u306F\u3093",
      "\u3057\u3072\u3087\u3046",
      "\u3057\u3075\u304F",
      "\u3057\u3099\u3075\u3099\u3093",
      "\u3057\u3078\u3044",
      "\u3057\u307B\u3046",
      "\u3057\u307B\u3093",
      "\u3057\u307E\u3046",
      "\u3057\u307E\u308B",
      "\u3057\u307F\u3093",
      "\u3057\u3080\u3051\u308B",
      "\u3057\u3099\u3080\u3057\u3087",
      "\u3057\u3081\u3044",
      "\u3057\u3081\u308B",
      "\u3057\u3082\u3093",
      "\u3057\u3083\u3044\u3093",
      "\u3057\u3083\u3046\u3093",
      "\u3057\u3083\u304A\u3093",
      "\u3057\u3099\u3083\u304B\u3099\u3044\u3082",
      "\u3057\u3084\u304F\u3057\u3087",
      "\u3057\u3083\u304F\u307B\u3046",
      "\u3057\u3083\u3051\u3093",
      "\u3057\u3083\u3053",
      "\u3057\u3083\u3055\u3099\u3044",
      "\u3057\u3083\u3057\u3093",
      "\u3057\u3083\u305B\u3093",
      "\u3057\u3083\u305D\u3046",
      "\u3057\u3083\u305F\u3044",
      "\u3057\u3083\u3061\u3087\u3046",
      "\u3057\u3083\u3063\u304D\u3093",
      "\u3057\u3099\u3083\u307E",
      "\u3057\u3083\u308A\u3093",
      "\u3057\u3083\u308C\u3044",
      "\u3057\u3099\u3086\u3046",
      "\u3057\u3099\u3085\u3046\u3057\u3087",
      "\u3057\u3085\u304F\u306F\u304F",
      "\u3057\u3099\u3085\u3057\u3093",
      "\u3057\u3085\u3063\u305B\u304D",
      "\u3057\u3085\u307F",
      "\u3057\u3085\u3089\u306F\u3099",
      "\u3057\u3099\u3085\u3093\u306F\u3099\u3093",
      "\u3057\u3087\u3046\u304B\u3044",
      "\u3057\u3087\u304F\u305F\u304F",
      "\u3057\u3087\u3063\u3051\u3093",
      "\u3057\u3087\u3068\u3099\u3046",
      "\u3057\u3087\u3082\u3064",
      "\u3057\u3089\u305B\u308B",
      "\u3057\u3089\u3078\u3099\u308B",
      "\u3057\u3093\u304B",
      "\u3057\u3093\u3053\u3046",
      "\u3057\u3099\u3093\u3057\u3099\u3083",
      "\u3057\u3093\u305B\u3044\u3057\u3099",
      "\u3057\u3093\u3061\u304F",
      "\u3057\u3093\u308A\u3093",
      "\u3059\u3042\u3051\u3099",
      "\u3059\u3042\u3057",
      "\u3059\u3042\u306A",
      "\u3059\u3099\u3042\u3093",
      "\u3059\u3044\u3048\u3044",
      "\u3059\u3044\u304B",
      "\u3059\u3044\u3068\u3046",
      "\u3059\u3099\u3044\u3075\u3099\u3093",
      "\u3059\u3044\u3088\u3046\u3072\u3099",
      "\u3059\u3046\u304B\u3099\u304F",
      "\u3059\u3046\u3057\u3099\u3064",
      "\u3059\u3046\u305B\u3093",
      "\u3059\u304A\u3068\u3099\u308A",
      "\u3059\u304D\u307E",
      "\u3059\u304F\u3046",
      "\u3059\u304F\u306A\u3044",
      "\u3059\u3051\u308B",
      "\u3059\u3053\u3099\u3044",
      "\u3059\u3053\u3057",
      "\u3059\u3099\u3055\u3093",
      "\u3059\u3059\u3099\u3057\u3044",
      "\u3059\u3059\u3080",
      "\u3059\u3059\u3081\u308B",
      "\u3059\u3063\u304B\u308A",
      "\u3059\u3099\u3063\u3057\u308A",
      "\u3059\u3099\u3063\u3068",
      "\u3059\u3066\u304D",
      "\u3059\u3066\u308B",
      "\u3059\u306D\u308B",
      "\u3059\u306E\u3053",
      "\u3059\u306F\u305F\u3099",
      "\u3059\u306F\u3099\u3089\u3057\u3044",
      "\u3059\u3099\u3072\u3087\u3046",
      "\u3059\u3099\u3075\u3099\u306C\u308C",
      "\u3059\u3075\u3099\u308A",
      "\u3059\u3075\u308C",
      "\u3059\u3078\u3099\u3066",
      "\u3059\u3078\u3099\u308B",
      "\u3059\u3099\u307B\u3046",
      "\u3059\u307B\u3099\u3093",
      "\u3059\u307E\u3044",
      "\u3059\u3081\u3057",
      "\u3059\u3082\u3046",
      "\u3059\u3084\u304D",
      "\u3059\u3089\u3059\u3089",
      "\u3059\u308B\u3081",
      "\u3059\u308C\u3061\u304B\u3099\u3046",
      "\u3059\u308D\u3063\u3068",
      "\u3059\u308F\u308B",
      "\u3059\u3093\u305B\u3099\u3093",
      "\u3059\u3093\u307B\u309A\u3046",
      "\u305B\u3042\u3075\u3099\u3089",
      "\u305B\u3044\u304B\u3064",
      "\u305B\u3044\u3051\u3099\u3093",
      "\u305B\u3044\u3057\u3099",
      "\u305B\u3044\u3088\u3046",
      "\u305B\u304A\u3046",
      "\u305B\u304B\u3044\u304B\u3093",
      "\u305B\u304D\u306B\u3093",
      "\u305B\u304D\u3080",
      "\u305B\u304D\u3086",
      "\u305B\u304D\u3089\u3093\u3046\u3093",
      "\u305B\u3051\u3093",
      "\u305B\u3053\u3046",
      "\u305B\u3059\u3057\u3099",
      "\u305B\u305F\u3044",
      "\u305B\u305F\u3051",
      "\u305B\u3063\u304B\u304F",
      "\u305B\u3063\u304D\u3083\u304F",
      "\u305B\u3099\u3063\u304F",
      "\u305B\u3063\u3051\u3093",
      "\u305B\u3063\u3053\u3064",
      "\u305B\u3063\u3055\u305F\u304F\u307E",
      "\u305B\u3064\u305D\u3099\u304F",
      "\u305B\u3064\u305F\u3099\u3093",
      "\u305B\u3064\u3066\u3099\u3093",
      "\u305B\u3063\u306F\u309A\u3093",
      "\u305B\u3064\u3072\u3099",
      "\u305B\u3064\u3075\u3099\u3093",
      "\u305B\u3064\u3081\u3044",
      "\u305B\u3064\u308A\u3064",
      "\u305B\u306A\u304B",
      "\u305B\u306E\u3072\u3099",
      "\u305B\u306F\u306F\u3099",
      "\u305B\u3072\u3099\u308D",
      "\u305B\u307B\u3099\u306D",
      "\u305B\u307E\u3044",
      "\u305B\u307E\u308B",
      "\u305B\u3081\u308B",
      "\u305B\u3082\u305F\u308C",
      "\u305B\u308A\u3075",
      "\u305B\u3099\u3093\u3042\u304F",
      "\u305B\u3093\u3044",
      "\u305B\u3093\u3048\u3044",
      "\u305B\u3093\u304B",
      "\u305B\u3093\u304D\u3087",
      "\u305B\u3093\u304F",
      "\u305B\u3093\u3051\u3099\u3093",
      "\u305B\u3099\u3093\u3053\u3099",
      "\u305B\u3093\u3055\u3044",
      "\u305B\u3093\u3057\u3085",
      "\u305B\u3093\u3059\u3044",
      "\u305B\u3093\u305B\u3044",
      "\u305B\u3093\u305D\u3099",
      "\u305B\u3093\u305F\u304F",
      "\u305B\u3093\u3061\u3087\u3046",
      "\u305B\u3093\u3066\u3044",
      "\u305B\u3093\u3068\u3046",
      "\u305B\u3093\u306C\u304D",
      "\u305B\u3093\u306D\u3093",
      "\u305B\u3093\u306F\u309A\u3044",
      "\u305B\u3099\u3093\u3075\u3099",
      "\u305B\u3099\u3093\u307B\u309A\u3046",
      "\u305B\u3093\u3080",
      "\u305B\u3093\u3081\u3093\u3057\u3099\u3087",
      "\u305B\u3093\u3082\u3093",
      "\u305B\u3093\u3084\u304F",
      "\u305B\u3093\u3086\u3046",
      "\u305B\u3093\u3088\u3046",
      "\u305B\u3099\u3093\u3089",
      "\u305B\u3099\u3093\u308A\u3083\u304F",
      "\u305B\u3093\u308C\u3044",
      "\u305B\u3093\u308D",
      "\u305D\u3042\u304F",
      "\u305D\u3044\u3068\u3051\u3099\u308B",
      "\u305D\u3044\u306D",
      "\u305D\u3046\u304B\u3099\u3093\u304D\u3087\u3046",
      "\u305D\u3046\u304D",
      "\u305D\u3046\u3053\u3099",
      "\u305D\u3046\u3057\u3093",
      "\u305D\u3046\u305F\u3099\u3093",
      "\u305D\u3046\u306A\u3093",
      "\u305D\u3046\u3072\u3099",
      "\u305D\u3046\u3081\u3093",
      "\u305D\u3046\u308A",
      "\u305D\u3048\u3082\u306E",
      "\u305D\u3048\u3093",
      "\u305D\u304B\u3099\u3044",
      "\u305D\u3051\u3099\u304D",
      "\u305D\u3053\u3046",
      "\u305D\u3053\u305D\u3053",
      "\u305D\u3055\u3099\u3044",
      "\u305D\u3057\u306A",
      "\u305D\u305B\u3044",
      "\u305D\u305B\u3093",
      "\u305D\u305D\u304F\u3099",
      "\u305D\u305F\u3099\u3066\u308B",
      "\u305D\u3064\u3046",
      "\u305D\u3064\u3048\u3093",
      "\u305D\u3063\u304B\u3093",
      "\u305D\u3064\u304D\u3099\u3087\u3046",
      "\u305D\u3063\u3051\u3064",
      "\u305D\u3063\u3053\u3046",
      "\u305D\u3063\u305B\u3093",
      "\u305D\u3063\u3068",
      "\u305D\u3068\u304B\u3099\u308F",
      "\u305D\u3068\u3064\u3099\u3089",
      "\u305D\u306A\u3048\u308B",
      "\u305D\u306A\u305F",
      "\u305D\u3075\u307B\u3099",
      "\u305D\u307B\u3099\u304F",
      "\u305D\u307B\u3099\u308D",
      "\u305D\u307E\u3064",
      "\u305D\u307E\u308B",
      "\u305D\u3080\u304F",
      "\u305D\u3080\u308A\u3048",
      "\u305D\u3081\u308B",
      "\u305D\u3082\u305D\u3082",
      "\u305D\u3088\u304B\u305B\u3099",
      "\u305D\u3089\u307E\u3081",
      "\u305D\u308D\u3046",
      "\u305D\u3093\u304B\u3044",
      "\u305D\u3093\u3051\u3044",
      "\u305D\u3093\u3055\u3099\u3044",
      "\u305D\u3093\u3057\u3064",
      "\u305D\u3093\u305D\u3099\u304F",
      "\u305D\u3093\u3061\u3087\u3046",
      "\u305D\u3099\u3093\u3072\u3099",
      "\u305D\u3099\u3093\u3075\u3099\u3093",
      "\u305D\u3093\u307F\u3093",
      "\u305F\u3042\u3044",
      "\u305F\u3044\u3044\u3093",
      "\u305F\u3044\u3046\u3093",
      "\u305F\u3044\u3048\u304D",
      "\u305F\u3044\u304A\u3046",
      "\u305F\u3099\u3044\u304B\u3099\u304F",
      "\u305F\u3044\u304D",
      "\u305F\u3044\u304F\u3099\u3046",
      "\u305F\u3044\u3051\u3093",
      "\u305F\u3044\u3053",
      "\u305F\u3044\u3055\u3099\u3044",
      "\u305F\u3099\u3044\u3057\u3099\u3087\u3046\u3075\u3099",
      "\u305F\u3099\u3044\u3059\u304D",
      "\u305F\u3044\u305B\u3064",
      "\u305F\u3044\u305D\u3046",
      "\u305F\u3099\u3044\u305F\u3044",
      "\u305F\u3044\u3061\u3087\u3046",
      "\u305F\u3044\u3066\u3044",
      "\u305F\u3099\u3044\u3068\u3099\u3053\u308D",
      "\u305F\u3044\u306A\u3044",
      "\u305F\u3044\u306D\u3064",
      "\u305F\u3044\u306E\u3046",
      "\u305F\u3044\u306F\u3093",
      "\u305F\u3099\u3044\u3072\u3087\u3046",
      "\u305F\u3044\u3075\u3046",
      "\u305F\u3044\u3078\u3093",
      "\u305F\u3044\u307B",
      "\u305F\u3044\u307E\u3064\u306F\u3099\u306A",
      "\u305F\u3044\u307F\u3093\u304F\u3099",
      "\u305F\u3044\u3080",
      "\u305F\u3044\u3081\u3093",
      "\u305F\u3044\u3084\u304D",
      "\u305F\u3044\u3088\u3046",
      "\u305F\u3044\u3089",
      "\u305F\u3044\u308A\u3087\u304F",
      "\u305F\u3044\u308B",
      "\u305F\u3044\u308F\u3093",
      "\u305F\u3046\u3048",
      "\u305F\u3048\u308B",
      "\u305F\u304A\u3059",
      "\u305F\u304A\u308B",
      "\u305F\u304A\u308C\u308B",
      "\u305F\u304B\u3044",
      "\u305F\u304B\u306D",
      "\u305F\u304D\u3072\u3099",
      "\u305F\u304F\u3055\u3093",
      "\u305F\u3053\u304F",
      "\u305F\u3053\u3084\u304D",
      "\u305F\u3055\u3044",
      "\u305F\u3057\u3055\u3099\u3093",
      "\u305F\u3099\u3057\u3099\u3083\u308C",
      "\u305F\u3059\u3051\u308B",
      "\u305F\u3059\u3099\u3055\u308F\u308B",
      "\u305F\u305D\u304B\u3099\u308C",
      "\u305F\u305F\u304B\u3046",
      "\u305F\u305F\u304F",
      "\u305F\u305F\u3099\u3057\u3044",
      "\u305F\u305F\u307F",
      "\u305F\u3061\u306F\u3099\u306A",
      "\u305F\u3099\u3063\u304B\u3044",
      "\u305F\u3099\u3063\u304D\u3083\u304F",
      "\u305F\u3099\u3063\u3053",
      "\u305F\u3099\u3063\u3057\u3085\u3064",
      "\u305F\u3099\u3063\u305F\u3044",
      "\u305F\u3066\u308B",
      "\u305F\u3068\u3048\u308B",
      "\u305F\u306A\u306F\u3099\u305F",
      "\u305F\u306B\u3093",
      "\u305F\u306C\u304D",
      "\u305F\u306E\u3057\u307F",
      "\u305F\u306F\u3064",
      "\u305F\u3075\u3099\u3093",
      "\u305F\u3078\u3099\u308B",
      "\u305F\u307B\u3099\u3046",
      "\u305F\u307E\u3053\u3099",
      "\u305F\u307E\u308B",
      "\u305F\u3099\u3080\u308B",
      "\u305F\u3081\u3044\u304D",
      "\u305F\u3081\u3059",
      "\u305F\u3081\u308B",
      "\u305F\u3082\u3064",
      "\u305F\u3084\u3059\u3044",
      "\u305F\u3088\u308B",
      "\u305F\u3089\u3059",
      "\u305F\u308A\u304D\u307B\u3093\u304B\u3099\u3093",
      "\u305F\u308A\u3087\u3046",
      "\u305F\u308A\u308B",
      "\u305F\u308B\u3068",
      "\u305F\u308C\u308B",
      "\u305F\u308C\u3093\u3068",
      "\u305F\u308D\u3063\u3068",
      "\u305F\u308F\u3080\u308C\u308B",
      "\u305F\u3099\u3093\u3042\u3064",
      "\u305F\u3093\u3044",
      "\u305F\u3093\u304A\u3093",
      "\u305F\u3093\u304B",
      "\u305F\u3093\u304D",
      "\u305F\u3093\u3051\u3093",
      "\u305F\u3093\u3053\u3099",
      "\u305F\u3093\u3055\u3093",
      "\u305F\u3093\u3057\u3099\u3087\u3046\u3072\u3099",
      "\u305F\u3099\u3093\u305B\u3044",
      "\u305F\u3093\u305D\u304F",
      "\u305F\u3093\u305F\u3044",
      "\u305F\u3099\u3093\u3061",
      "\u305F\u3093\u3066\u3044",
      "\u305F\u3093\u3068\u3046",
      "\u305F\u3099\u3093\u306A",
      "\u305F\u3093\u306B\u3093",
      "\u305F\u3099\u3093\u306D\u3064",
      "\u305F\u3093\u306E\u3046",
      "\u305F\u3093\u3072\u309A\u3093",
      "\u305F\u3099\u3093\u307B\u3099\u3046",
      "\u305F\u3093\u307E\u3064",
      "\u305F\u3093\u3081\u3044",
      "\u305F\u3099\u3093\u308C\u3064",
      "\u305F\u3099\u3093\u308D",
      "\u305F\u3099\u3093\u308F",
      "\u3061\u3042\u3044",
      "\u3061\u3042\u3093",
      "\u3061\u3044\u304D",
      "\u3061\u3044\u3055\u3044",
      "\u3061\u3048\u3093",
      "\u3061\u304B\u3044",
      "\u3061\u304B\u3089",
      "\u3061\u304D\u3085\u3046",
      "\u3061\u304D\u3093",
      "\u3061\u3051\u3044\u3059\u3099",
      "\u3061\u3051\u3093",
      "\u3061\u3053\u304F",
      "\u3061\u3055\u3044",
      "\u3061\u3057\u304D",
      "\u3061\u3057\u308A\u3087\u3046",
      "\u3061\u305B\u3044",
      "\u3061\u305D\u3046",
      "\u3061\u305F\u3044",
      "\u3061\u305F\u3093",
      "\u3061\u3061\u304A\u3084",
      "\u3061\u3064\u3057\u3099\u3087",
      "\u3061\u3066\u304D",
      "\u3061\u3066\u3093",
      "\u3061\u306C\u304D",
      "\u3061\u306C\u308A",
      "\u3061\u306E\u3046",
      "\u3061\u3072\u3087\u3046",
      "\u3061\u3078\u3044\u305B\u3093",
      "\u3061\u307B\u3046",
      "\u3061\u307E\u305F",
      "\u3061\u307F\u3064",
      "\u3061\u307F\u3068\u3099\u308D",
      "\u3061\u3081\u3044\u3068\u3099",
      "\u3061\u3083\u3093\u3053\u306A\u3078\u3099",
      "\u3061\u3085\u3046\u3044",
      "\u3061\u3086\u308A\u3087\u304F",
      "\u3061\u3087\u3046\u3057",
      "\u3061\u3087\u3055\u304F\u3051\u3093",
      "\u3061\u3089\u3057",
      "\u3061\u3089\u307F",
      "\u3061\u308A\u304B\u3099\u307F",
      "\u3061\u308A\u3087\u3046",
      "\u3061\u308B\u3068\u3099",
      "\u3061\u308F\u308F",
      "\u3061\u3093\u305F\u3044",
      "\u3061\u3093\u3082\u304F",
      "\u3064\u3044\u304B",
      "\u3064\u3044\u305F\u3061",
      "\u3064\u3046\u304B",
      "\u3064\u3046\u3057\u3099\u3087\u3046",
      "\u3064\u3046\u306F\u3093",
      "\u3064\u3046\u308F",
      "\u3064\u304B\u3046",
      "\u3064\u304B\u308C\u308B",
      "\u3064\u304F\u306D",
      "\u3064\u304F\u308B",
      "\u3064\u3051\u306D",
      "\u3064\u3051\u308B",
      "\u3064\u3053\u3099\u3046",
      "\u3064\u305F\u3048\u308B",
      "\u3064\u3064\u3099\u304F",
      "\u3064\u3064\u3057\u3099",
      "\u3064\u3064\u3080",
      "\u3064\u3068\u3081\u308B",
      "\u3064\u306A\u304B\u3099\u308B",
      "\u3064\u306A\u307F",
      "\u3064\u306D\u3064\u3099\u306D",
      "\u3064\u306E\u308B",
      "\u3064\u3075\u3099\u3059",
      "\u3064\u307E\u3089\u306A\u3044",
      "\u3064\u307E\u308B",
      "\u3064\u307F\u304D",
      "\u3064\u3081\u305F\u3044",
      "\u3064\u3082\u308A",
      "\u3064\u3082\u308B",
      "\u3064\u3088\u3044",
      "\u3064\u308B\u307B\u3099",
      "\u3064\u308B\u307F\u304F",
      "\u3064\u308F\u3082\u306E",
      "\u3064\u308F\u308A",
      "\u3066\u3042\u3057",
      "\u3066\u3042\u3066",
      "\u3066\u3042\u307F",
      "\u3066\u3044\u304A\u3093",
      "\u3066\u3044\u304B",
      "\u3066\u3044\u304D",
      "\u3066\u3044\u3051\u3044",
      "\u3066\u3044\u3053\u304F",
      "\u3066\u3044\u3055\u3064",
      "\u3066\u3044\u3057",
      "\u3066\u3044\u305B\u3044",
      "\u3066\u3044\u305F\u3044",
      "\u3066\u3044\u3068\u3099",
      "\u3066\u3044\u306D\u3044",
      "\u3066\u3044\u3072\u3087\u3046",
      "\u3066\u3044\u3078\u3093",
      "\u3066\u3044\u307B\u3099\u3046",
      "\u3066\u3046\u3061",
      "\u3066\u304A\u304F\u308C",
      "\u3066\u304D\u3068\u3046",
      "\u3066\u304F\u3072\u3099",
      "\u3066\u3099\u3053\u307B\u3099\u3053",
      "\u3066\u3055\u304D\u3099\u3087\u3046",
      "\u3066\u3055\u3051\u3099",
      "\u3066\u3059\u308A",
      "\u3066\u305D\u3046",
      "\u3066\u3061\u304B\u3099\u3044",
      "\u3066\u3061\u3087\u3046",
      "\u3066\u3064\u304B\u3099\u304F",
      "\u3066\u3064\u3064\u3099\u304D",
      "\u3066\u3099\u3063\u306F\u309A",
      "\u3066\u3064\u307B\u3099\u3046",
      "\u3066\u3064\u3084",
      "\u3066\u3099\u306C\u304B\u3048",
      "\u3066\u306C\u304D",
      "\u3066\u306C\u304F\u3099\u3044",
      "\u3066\u306E\u3072\u3089",
      "\u3066\u306F\u3044",
      "\u3066\u3075\u3099\u304F\u308D",
      "\u3066\u3075\u305F\u3099",
      "\u3066\u307B\u3068\u3099\u304D",
      "\u3066\u307B\u3093",
      "\u3066\u307E\u3048",
      "\u3066\u307E\u304D\u3059\u3099\u3057",
      "\u3066\u307F\u3057\u3099\u304B",
      "\u3066\u307F\u3084\u3051\u3099",
      "\u3066\u3089\u3059",
      "\u3066\u308C\u3072\u3099",
      "\u3066\u308F\u3051",
      "\u3066\u308F\u305F\u3057",
      "\u3066\u3099\u3093\u3042\u3064",
      "\u3066\u3093\u3044\u3093",
      "\u3066\u3093\u304B\u3044",
      "\u3066\u3093\u304D",
      "\u3066\u3093\u304F\u3099",
      "\u3066\u3093\u3051\u3093",
      "\u3066\u3093\u3053\u3099\u304F",
      "\u3066\u3093\u3055\u3044",
      "\u3066\u3093\u3057",
      "\u3066\u3093\u3059\u3046",
      "\u3066\u3099\u3093\u3061",
      "\u3066\u3093\u3066\u304D",
      "\u3066\u3093\u3068\u3046",
      "\u3066\u3093\u306A\u3044",
      "\u3066\u3093\u3075\u309A\u3089",
      "\u3066\u3093\u307B\u3099\u3046\u305F\u3099\u3044",
      "\u3066\u3093\u3081\u3064",
      "\u3066\u3093\u3089\u3093\u304B\u3044",
      "\u3066\u3099\u3093\u308A\u3087\u304F",
      "\u3066\u3099\u3093\u308F",
      "\u3068\u3099\u3042\u3044",
      "\u3068\u3044\u308C",
      "\u3068\u3099\u3046\u304B\u3093",
      "\u3068\u3046\u304D\u3085\u3046",
      "\u3068\u3099\u3046\u304F\u3099",
      "\u3068\u3046\u3057",
      "\u3068\u3046\u3080\u304D\u3099",
      "\u3068\u304A\u3044",
      "\u3068\u304A\u304B",
      "\u3068\u304A\u304F",
      "\u3068\u304A\u3059",
      "\u3068\u304A\u308B",
      "\u3068\u304B\u3044",
      "\u3068\u304B\u3059",
      "\u3068\u304D\u304A\u308A",
      "\u3068\u304D\u3068\u3099\u304D",
      "\u3068\u304F\u3044",
      "\u3068\u304F\u3057\u3085\u3046",
      "\u3068\u304F\u3066\u3093",
      "\u3068\u304F\u306B",
      "\u3068\u304F\u3078\u3099\u3064",
      "\u3068\u3051\u3044",
      "\u3068\u3051\u308B",
      "\u3068\u3053\u3084",
      "\u3068\u3055\u304B",
      "\u3068\u3057\u3087\u304B\u3093",
      "\u3068\u305D\u3046",
      "\u3068\u305F\u3093",
      "\u3068\u3061\u3085\u3046",
      "\u3068\u3063\u304D\u3085\u3046",
      "\u3068\u3063\u304F\u3093",
      "\u3068\u3064\u305B\u3099\u3093",
      "\u3068\u3064\u306B\u3085\u3046",
      "\u3068\u3068\u3099\u3051\u308B",
      "\u3068\u3068\u306E\u3048\u308B",
      "\u3068\u306A\u3044",
      "\u3068\u306A\u3048\u308B",
      "\u3068\u306A\u308A",
      "\u3068\u306E\u3055\u307E",
      "\u3068\u306F\u3099\u3059",
      "\u3068\u3099\u3075\u3099\u304B\u3099\u308F",
      "\u3068\u307B\u3046",
      "\u3068\u307E\u308B",
      "\u3068\u3081\u308B",
      "\u3068\u3082\u305F\u3099\u3061",
      "\u3068\u3082\u308B",
      "\u3068\u3099\u3088\u3046\u3072\u3099",
      "\u3068\u3089\u3048\u308B",
      "\u3068\u3093\u304B\u3064",
      "\u3068\u3099\u3093\u3075\u3099\u308A",
      "\u306A\u3044\u304B\u304F",
      "\u306A\u3044\u3053\u3046",
      "\u306A\u3044\u3057\u3087",
      "\u306A\u3044\u3059",
      "\u306A\u3044\u305B\u3093",
      "\u306A\u3044\u305D\u3046",
      "\u306A\u304A\u3059",
      "\u306A\u304B\u3099\u3044",
      "\u306A\u304F\u3059",
      "\u306A\u3051\u3099\u308B",
      "\u306A\u3053\u3046\u3068\u3099",
      "\u306A\u3055\u3051",
      "\u306A\u305F\u3066\u3099\u3053\u3053",
      "\u306A\u3063\u3068\u3046",
      "\u306A\u3064\u3084\u3059\u307F",
      "\u306A\u306A\u304A\u3057",
      "\u306A\u306B\u3053\u3099\u3068",
      "\u306A\u306B\u3082\u306E",
      "\u306A\u306B\u308F",
      "\u306A\u306E\u304B",
      "\u306A\u3075\u305F\u3099",
      "\u306A\u307E\u3044\u304D",
      "\u306A\u307E\u3048",
      "\u306A\u307E\u307F",
      "\u306A\u307F\u305F\u3099",
      "\u306A\u3081\u3089\u304B",
      "\u306A\u3081\u308B",
      "\u306A\u3084\u3080",
      "\u306A\u3089\u3046",
      "\u306A\u3089\u3072\u3099",
      "\u306A\u3089\u3075\u3099",
      "\u306A\u308C\u308B",
      "\u306A\u308F\u3068\u3072\u3099",
      "\u306A\u308F\u306F\u3099\u308A",
      "\u306B\u3042\u3046",
      "\u306B\u3044\u304B\u3099\u305F",
      "\u306B\u3046\u3051",
      "\u306B\u304A\u3044",
      "\u306B\u304B\u3044",
      "\u306B\u304B\u3099\u3066",
      "\u306B\u304D\u3072\u3099",
      "\u306B\u304F\u3057\u307F",
      "\u306B\u304F\u307E\u3093",
      "\u306B\u3051\u3099\u308B",
      "\u306B\u3055\u3093\u304B\u305F\u3093\u305D",
      "\u306B\u3057\u304D",
      "\u306B\u305B\u3082\u306E",
      "\u306B\u3061\u3057\u3099\u3087\u3046",
      "\u306B\u3061\u3088\u3046\u3072\u3099",
      "\u306B\u3063\u304B",
      "\u306B\u3063\u304D",
      "\u306B\u3063\u3051\u3044",
      "\u306B\u3063\u3053\u3046",
      "\u306B\u3063\u3055\u3093",
      "\u306B\u3063\u3057\u3087\u304F",
      "\u306B\u3063\u3059\u3046",
      "\u306B\u3063\u305B\u304D",
      "\u306B\u3063\u3066\u3044",
      "\u306B\u306A\u3046",
      "\u306B\u307B\u3093",
      "\u306B\u307E\u3081",
      "\u306B\u3082\u3064",
      "\u306B\u3084\u308A",
      "\u306B\u3085\u3046\u3044\u3093",
      "\u306B\u308A\u3093\u3057\u3083",
      "\u306B\u308F\u3068\u308A",
      "\u306B\u3093\u3044",
      "\u306B\u3093\u304B",
      "\u306B\u3093\u304D",
      "\u306B\u3093\u3051\u3099\u3093",
      "\u306B\u3093\u3057\u304D",
      "\u306B\u3093\u3059\u3099\u3046",
      "\u306B\u3093\u305D\u3046",
      "\u306B\u3093\u305F\u3044",
      "\u306B\u3093\u3061",
      "\u306B\u3093\u3066\u3044",
      "\u306B\u3093\u306B\u304F",
      "\u306B\u3093\u3075\u309A",
      "\u306B\u3093\u307E\u308A",
      "\u306B\u3093\u3080",
      "\u306B\u3093\u3081\u3044",
      "\u306B\u3093\u3088\u3046",
      "\u306C\u3044\u304F\u304D\u3099",
      "\u306C\u304B\u3059",
      "\u306C\u304F\u3099\u3044\u3068\u308B",
      "\u306C\u304F\u3099\u3046",
      "\u306C\u304F\u3082\u308A",
      "\u306C\u3059\u3080",
      "\u306C\u307E\u3048\u3072\u3099",
      "\u306C\u3081\u308A",
      "\u306C\u3089\u3059",
      "\u306C\u3093\u3061\u3083\u304F",
      "\u306D\u3042\u3051\u3099",
      "\u306D\u3044\u304D",
      "\u306D\u3044\u308B",
      "\u306D\u3044\u308D",
      "\u306D\u304F\u3099\u305B",
      "\u306D\u304F\u305F\u3044",
      "\u306D\u304F\u3089",
      "\u306D\u3053\u305B\u3099",
      "\u306D\u3053\u3080",
      "\u306D\u3055\u3051\u3099",
      "\u306D\u3059\u3053\u3099\u3059",
      "\u306D\u305D\u3078\u3099\u308B",
      "\u306D\u305F\u3099\u3093",
      "\u306D\u3064\u3044",
      "\u306D\u3063\u3057\u3093",
      "\u306D\u3064\u305D\u3099\u3046",
      "\u306D\u3063\u305F\u3044\u304D\u3099\u3087",
      "\u306D\u3075\u3099\u305D\u304F",
      "\u306D\u3075\u305F\u3099",
      "\u306D\u307B\u3099\u3046",
      "\u306D\u307B\u308A\u306F\u307B\u308A",
      "\u306D\u307E\u304D",
      "\u306D\u307E\u308F\u3057",
      "\u306D\u307F\u307F",
      "\u306D\u3080\u3044",
      "\u306D\u3080\u305F\u3044",
      "\u306D\u3082\u3068",
      "\u306D\u3089\u3046",
      "\u306D\u308F\u3055\u3099",
      "\u306D\u3093\u3044\u308A",
      "\u306D\u3093\u304A\u3057",
      "\u306D\u3093\u304B\u3093",
      "\u306D\u3093\u304D\u3093",
      "\u306D\u3093\u304F\u3099",
      "\u306D\u3093\u3055\u3099",
      "\u306D\u3093\u3057",
      "\u306D\u3093\u3061\u3083\u304F",
      "\u306D\u3093\u3068\u3099",
      "\u306D\u3093\u3072\u309A",
      "\u306D\u3093\u3075\u3099\u3064",
      "\u306D\u3093\u307E\u3064",
      "\u306D\u3093\u308A\u3087\u3046",
      "\u306D\u3093\u308C\u3044",
      "\u306E\u3044\u3059\u3099",
      "\u306E\u304A\u3064\u3099\u307E",
      "\u306E\u304B\u3099\u3059",
      "\u306E\u304D\u306A\u307F",
      "\u306E\u3053\u304D\u3099\u308A",
      "\u306E\u3053\u3059",
      "\u306E\u3053\u308B",
      "\u306E\u305B\u308B",
      "\u306E\u305D\u3099\u304F",
      "\u306E\u305D\u3099\u3080",
      "\u306E\u305F\u307E\u3046",
      "\u306E\u3061\u307B\u3068\u3099",
      "\u306E\u3063\u304F",
      "\u306E\u306F\u3099\u3059",
      "\u306E\u306F\u3089",
      "\u306E\u3078\u3099\u308B",
      "\u306E\u307B\u3099\u308B",
      "\u306E\u307F\u3082\u306E",
      "\u306E\u3084\u307E",
      "\u306E\u3089\u3044\u306C",
      "\u306E\u3089\u306D\u3053",
      "\u306E\u308A\u3082\u306E",
      "\u306E\u308A\u3086\u304D",
      "\u306E\u308C\u3093",
      "\u306E\u3093\u304D",
      "\u306F\u3099\u3042\u3044",
      "\u306F\u3042\u304F",
      "\u306F\u3099\u3042\u3055\u3093",
      "\u306F\u3099\u3044\u304B",
      "\u306F\u3099\u3044\u304F",
      "\u306F\u3044\u3051\u3093",
      "\u306F\u3044\u3053\u3099",
      "\u306F\u3044\u3057\u3093",
      "\u306F\u3044\u3059\u3044",
      "\u306F\u3044\u305B\u3093",
      "\u306F\u3044\u305D\u3046",
      "\u306F\u3044\u3061",
      "\u306F\u3099\u3044\u306F\u3099\u3044",
      "\u306F\u3044\u308C\u3064",
      "\u306F\u3048\u308B",
      "\u306F\u304A\u308B",
      "\u306F\u304B\u3044",
      "\u306F\u3099\u304B\u308A",
      "\u306F\u304B\u308B",
      "\u306F\u304F\u3057\u3085",
      "\u306F\u3051\u3093",
      "\u306F\u3053\u3075\u3099",
      "\u306F\u3055\u307F",
      "\u306F\u3055\u3093",
      "\u306F\u3057\u3053\u3099",
      "\u306F\u3099\u3057\u3087",
      "\u306F\u3057\u308B",
      "\u306F\u305B\u308B",
      "\u306F\u309A\u305D\u3053\u3093",
      "\u306F\u305D\u3093",
      "\u306F\u305F\u3093",
      "\u306F\u3061\u307F\u3064",
      "\u306F\u3064\u304A\u3093",
      "\u306F\u3063\u304B\u304F",
      "\u306F\u3064\u3099\u304D",
      "\u306F\u3063\u304D\u308A",
      "\u306F\u3063\u304F\u3064",
      "\u306F\u3063\u3051\u3093",
      "\u306F\u3063\u3053\u3046",
      "\u306F\u3063\u3055\u3093",
      "\u306F\u3063\u3057\u3093",
      "\u306F\u3063\u305F\u3064",
      "\u306F\u3063\u3061\u3085\u3046",
      "\u306F\u3063\u3066\u3093",
      "\u306F\u3063\u3072\u309A\u3087\u3046",
      "\u306F\u3063\u307B\u309A\u3046",
      "\u306F\u306A\u3059",
      "\u306F\u306A\u3072\u3099",
      "\u306F\u306B\u304B\u3080",
      "\u306F\u3075\u3099\u3089\u3057",
      "\u306F\u307F\u304B\u3099\u304D",
      "\u306F\u3080\u304B\u3046",
      "\u306F\u3081\u3064",
      "\u306F\u3084\u3044",
      "\u306F\u3084\u3057",
      "\u306F\u3089\u3046",
      "\u306F\u308D\u3046\u3043\u3093",
      "\u306F\u308F\u3044",
      "\u306F\u3093\u3044",
      "\u306F\u3093\u3048\u3044",
      "\u306F\u3093\u304A\u3093",
      "\u306F\u3093\u304B\u304F",
      "\u306F\u3093\u304D\u3087\u3046",
      "\u306F\u3099\u3093\u304F\u3099\u307F",
      "\u306F\u3093\u3053",
      "\u306F\u3093\u3057\u3083",
      "\u306F\u3093\u3059\u3046",
      "\u306F\u3093\u305F\u3099\u3093",
      "\u306F\u309A\u3093\u3061",
      "\u306F\u309A\u3093\u3064",
      "\u306F\u3093\u3066\u3044",
      "\u306F\u3093\u3068\u3057",
      "\u306F\u3093\u306E\u3046",
      "\u306F\u3093\u306F\u309A",
      "\u306F\u3093\u3075\u3099\u3093",
      "\u306F\u3093\u3078\u309A\u3093",
      "\u306F\u3093\u307B\u3099\u3046\u304D",
      "\u306F\u3093\u3081\u3044",
      "\u306F\u3093\u3089\u3093",
      "\u306F\u3093\u308D\u3093",
      "\u3072\u3044\u304D",
      "\u3072\u3046\u3093",
      "\u3072\u3048\u308B",
      "\u3072\u304B\u304F",
      "\u3072\u304B\u308A",
      "\u3072\u304B\u308B",
      "\u3072\u304B\u3093",
      "\u3072\u304F\u3044",
      "\u3072\u3051\u3064",
      "\u3072\u3053\u3046\u304D",
      "\u3072\u3053\u304F",
      "\u3072\u3055\u3044",
      "\u3072\u3055\u3057\u3075\u3099\u308A",
      "\u3072\u3055\u3093",
      "\u3072\u3099\u3057\u3099\u3085\u3064\u304B\u3093",
      "\u3072\u3057\u3087",
      "\u3072\u305D\u304B",
      "\u3072\u305D\u3080",
      "\u3072\u305F\u3080\u304D",
      "\u3072\u305F\u3099\u308A",
      "\u3072\u305F\u308B",
      "\u3072\u3064\u304D\u3099",
      "\u3072\u3063\u3053\u3057",
      "\u3072\u3063\u3057",
      "\u3072\u3064\u3057\u3099\u3085\u3072\u3093",
      "\u3072\u3063\u3059",
      "\u3072\u3064\u305B\u3099\u3093",
      "\u3072\u309A\u3063\u305F\u308A",
      "\u3072\u309A\u3063\u3061\u308A",
      "\u3072\u3064\u3088\u3046",
      "\u3072\u3066\u3044",
      "\u3072\u3068\u3053\u3099\u307F",
      "\u3072\u306A\u307E\u3064\u308A",
      "\u3072\u306A\u3093",
      "\u3072\u306D\u308B",
      "\u3072\u306F\u3093",
      "\u3072\u3072\u3099\u304F",
      "\u3072\u3072\u3087\u3046",
      "\u3072\u307B\u3046",
      "\u3072\u307E\u308F\u308A",
      "\u3072\u307E\u3093",
      "\u3072\u307F\u3064",
      "\u3072\u3081\u3044",
      "\u3072\u3081\u3057\u3099\u3057",
      "\u3072\u3084\u3051",
      "\u3072\u3084\u3059",
      "\u3072\u3088\u3046",
      "\u3072\u3099\u3087\u3046\u304D",
      "\u3072\u3089\u304B\u3099\u306A",
      "\u3072\u3089\u304F",
      "\u3072\u308A\u3064",
      "\u3072\u308A\u3087\u3046",
      "\u3072\u308B\u307E",
      "\u3072\u308B\u3084\u3059\u307F",
      "\u3072\u308C\u3044",
      "\u3072\u308D\u3044",
      "\u3072\u308D\u3046",
      "\u3072\u308D\u304D",
      "\u3072\u308D\u3086\u304D",
      "\u3072\u3093\u304B\u304F",
      "\u3072\u3093\u3051\u3064",
      "\u3072\u3093\u3053\u3093",
      "\u3072\u3093\u3057\u3085",
      "\u3072\u3093\u305D\u3046",
      "\u3072\u309A\u3093\u3061",
      "\u3072\u3093\u306F\u309A\u3093",
      "\u3072\u3099\u3093\u307B\u3099\u3046",
      "\u3075\u3042\u3093",
      "\u3075\u3044\u3046\u3061",
      "\u3075\u3046\u3051\u3044",
      "\u3075\u3046\u305B\u3093",
      "\u3075\u309A\u3046\u305F\u308D\u3046",
      "\u3075\u3046\u3068\u3046",
      "\u3075\u3046\u3075",
      "\u3075\u3048\u308B",
      "\u3075\u304A\u3093",
      "\u3075\u304B\u3044",
      "\u3075\u304D\u3093",
      "\u3075\u304F\u3055\u3099\u3064",
      "\u3075\u304F\u3075\u3099\u304F\u308D",
      "\u3075\u3053\u3046",
      "\u3075\u3055\u3044",
      "\u3075\u3057\u304D\u3099",
      "\u3075\u3057\u3099\u307F",
      "\u3075\u3059\u307E",
      "\u3075\u305B\u3044",
      "\u3075\u305B\u304F\u3099",
      "\u3075\u305D\u304F",
      "\u3075\u3099\u305F\u306B\u304F",
      "\u3075\u305F\u3093",
      "\u3075\u3061\u3087\u3046",
      "\u3075\u3064\u3046",
      "\u3075\u3064\u304B",
      "\u3075\u3063\u304B\u3064",
      "\u3075\u3063\u304D",
      "\u3075\u3063\u3053\u304F",
      "\u3075\u3099\u3068\u3099\u3046",
      "\u3075\u3068\u308B",
      "\u3075\u3068\u3093",
      "\u3075\u306E\u3046",
      "\u3075\u306F\u3044",
      "\u3075\u3072\u3087\u3046",
      "\u3075\u3078\u3093",
      "\u3075\u307E\u3093",
      "\u3075\u307F\u3093",
      "\u3075\u3081\u3064",
      "\u3075\u3081\u3093",
      "\u3075\u3088\u3046",
      "\u3075\u308A\u3053",
      "\u3075\u308A\u308B",
      "\u3075\u308B\u3044",
      "\u3075\u3093\u3044\u304D",
      "\u3075\u3099\u3093\u304B\u3099\u304F",
      "\u3075\u3099\u3093\u304F\u3099",
      "\u3075\u3093\u3057\u3064",
      "\u3075\u3099\u3093\u305B\u304D",
      "\u3075\u3093\u305D\u3046",
      "\u3075\u3099\u3093\u307B\u309A\u3046",
      "\u3078\u3044\u3042\u3093",
      "\u3078\u3044\u304A\u3093",
      "\u3078\u3044\u304B\u3099\u3044",
      "\u3078\u3044\u304D",
      "\u3078\u3044\u3051\u3099\u3093",
      "\u3078\u3044\u3053\u3046",
      "\u3078\u3044\u3055",
      "\u3078\u3044\u3057\u3083",
      "\u3078\u3044\u305B\u3064",
      "\u3078\u3044\u305D",
      "\u3078\u3044\u305F\u304F",
      "\u3078\u3044\u3066\u3093",
      "\u3078\u3044\u306D\u3064",
      "\u3078\u3044\u308F",
      "\u3078\u304D\u304B\u3099",
      "\u3078\u3053\u3080",
      "\u3078\u3099\u306B\u3044\u308D",
      "\u3078\u3099\u306B\u3057\u3087\u3046\u304B\u3099",
      "\u3078\u3089\u3059",
      "\u3078\u3093\u304B\u3093",
      "\u3078\u3099\u3093\u304D\u3087\u3046",
      "\u3078\u3099\u3093\u3053\u3099\u3057",
      "\u3078\u3093\u3055\u3044",
      "\u3078\u3093\u305F\u3044",
      "\u3078\u3099\u3093\u308A",
      "\u307B\u3042\u3093",
      "\u307B\u3044\u304F",
      "\u307B\u3099\u3046\u304D\u3099\u3087",
      "\u307B\u3046\u3053\u304F",
      "\u307B\u3046\u305D\u3046",
      "\u307B\u3046\u307B\u3046",
      "\u307B\u3046\u3082\u3093",
      "\u307B\u3046\u308A\u3064",
      "\u307B\u3048\u308B",
      "\u307B\u304A\u3093",
      "\u307B\u304B\u3093",
      "\u307B\u304D\u3087\u3046",
      "\u307B\u3099\u304D\u3093",
      "\u307B\u304F\u308D",
      "\u307B\u3051\u3064",
      "\u307B\u3051\u3093",
      "\u307B\u3053\u3046",
      "\u307B\u3053\u308B",
      "\u307B\u3057\u3044",
      "\u307B\u3057\u3064",
      "\u307B\u3057\u3085",
      "\u307B\u3057\u3087\u3046",
      "\u307B\u305B\u3044",
      "\u307B\u305D\u3044",
      "\u307B\u305D\u304F",
      "\u307B\u305F\u3066",
      "\u307B\u305F\u308B",
      "\u307B\u309A\u3061\u3075\u3099\u304F\u308D",
      "\u307B\u3063\u304D\u3087\u304F",
      "\u307B\u3063\u3055",
      "\u307B\u3063\u305F\u3093",
      "\u307B\u3068\u3093\u3068\u3099",
      "\u307B\u3081\u308B",
      "\u307B\u3093\u3044",
      "\u307B\u3093\u304D",
      "\u307B\u3093\u3051",
      "\u307B\u3093\u3057\u3064",
      "\u307B\u3093\u3084\u304F",
      "\u307E\u3044\u306B\u3061",
      "\u307E\u304B\u3044",
      "\u307E\u304B\u305B\u308B",
      "\u307E\u304B\u3099\u308B",
      "\u307E\u3051\u308B",
      "\u307E\u3053\u3068",
      "\u307E\u3055\u3064",
      "\u307E\u3057\u3099\u3081",
      "\u307E\u3059\u304F",
      "\u307E\u305B\u3099\u308B",
      "\u307E\u3064\u308A",
      "\u307E\u3068\u3081",
      "\u307E\u306A\u3075\u3099",
      "\u307E\u306C\u3051",
      "\u307E\u306D\u304F",
      "\u307E\u307B\u3046",
      "\u307E\u3082\u308B",
      "\u307E\u3086\u3051\u3099",
      "\u307E\u3088\u3046",
      "\u307E\u308D\u3084\u304B",
      "\u307E\u308F\u3059",
      "\u307E\u308F\u308A",
      "\u307E\u308F\u308B",
      "\u307E\u3093\u304B\u3099",
      "\u307E\u3093\u304D\u3064",
      "\u307E\u3093\u305D\u3099\u304F",
      "\u307E\u3093\u306A\u304B",
      "\u307F\u3044\u3089",
      "\u307F\u3046\u3061",
      "\u307F\u3048\u308B",
      "\u307F\u304B\u3099\u304F",
      "\u307F\u304B\u305F",
      "\u307F\u304B\u3093",
      "\u307F\u3051\u3093",
      "\u307F\u3053\u3093",
      "\u307F\u3057\u3099\u304B\u3044",
      "\u307F\u3059\u3044",
      "\u307F\u3059\u3048\u308B",
      "\u307F\u305B\u308B",
      "\u307F\u3063\u304B",
      "\u307F\u3064\u304B\u308B",
      "\u307F\u3064\u3051\u308B",
      "\u307F\u3066\u3044",
      "\u307F\u3068\u3081\u308B",
      "\u307F\u306A\u3068",
      "\u307F\u306A\u307F\u304B\u3055\u3044",
      "\u307F\u306D\u3089\u308B",
      "\u307F\u306E\u3046",
      "\u307F\u306E\u304B\u3099\u3059",
      "\u307F\u307B\u3093",
      "\u307F\u3082\u3068",
      "\u307F\u3084\u3051\u3099",
      "\u307F\u3089\u3044",
      "\u307F\u308A\u3087\u304F",
      "\u307F\u308F\u304F",
      "\u307F\u3093\u304B",
      "\u307F\u3093\u305D\u3099\u304F",
      "\u3080\u3044\u304B",
      "\u3080\u3048\u304D",
      "\u3080\u3048\u3093",
      "\u3080\u304B\u3044",
      "\u3080\u304B\u3046",
      "\u3080\u304B\u3048",
      "\u3080\u304B\u3057",
      "\u3080\u304D\u3099\u3061\u3083",
      "\u3080\u3051\u308B",
      "\u3080\u3051\u3099\u3093",
      "\u3080\u3055\u307B\u3099\u308B",
      "\u3080\u3057\u3042\u3064\u3044",
      "\u3080\u3057\u306F\u3099",
      "\u3080\u3057\u3099\u3085\u3093",
      "\u3080\u3057\u308D",
      "\u3080\u3059\u3046",
      "\u3080\u3059\u3053",
      "\u3080\u3059\u3075\u3099",
      "\u3080\u3059\u3081",
      "\u3080\u305B\u308B",
      "\u3080\u305B\u3093",
      "\u3080\u3061\u3085\u3046",
      "\u3080\u306A\u3057\u3044",
      "\u3080\u306E\u3046",
      "\u3080\u3084\u307F",
      "\u3080\u3088\u3046",
      "\u3080\u3089\u3055\u304D",
      "\u3080\u308A\u3087\u3046",
      "\u3080\u308D\u3093",
      "\u3081\u3044\u3042\u3093",
      "\u3081\u3044\u3046\u3093",
      "\u3081\u3044\u3048\u3093",
      "\u3081\u3044\u304B\u304F",
      "\u3081\u3044\u304D\u3087\u304F",
      "\u3081\u3044\u3055\u3044",
      "\u3081\u3044\u3057",
      "\u3081\u3044\u305D\u3046",
      "\u3081\u3044\u3075\u3099\u3064",
      "\u3081\u3044\u308C\u3044",
      "\u3081\u3044\u308F\u304F",
      "\u3081\u304F\u3099\u307E\u308C\u308B",
      "\u3081\u3055\u3099\u3059",
      "\u3081\u3057\u305F",
      "\u3081\u3059\u3099\u3089\u3057\u3044",
      "\u3081\u305F\u3099\u3064",
      "\u3081\u307E\u3044",
      "\u3081\u3084\u3059",
      "\u3081\u3093\u304D\u3087",
      "\u3081\u3093\u305B\u304D",
      "\u3081\u3093\u3068\u3099\u3046",
      "\u3082\u3046\u3057\u3042\u3051\u3099\u308B",
      "\u3082\u3046\u3068\u3099\u3046\u3051\u3093",
      "\u3082\u3048\u308B",
      "\u3082\u304F\u3057",
      "\u3082\u304F\u3066\u304D",
      "\u3082\u304F\u3088\u3046\u3072\u3099",
      "\u3082\u3061\u308D\u3093",
      "\u3082\u3068\u3099\u308B",
      "\u3082\u3089\u3046",
      "\u3082\u3093\u304F",
      "\u3082\u3093\u305F\u3099\u3044",
      "\u3084\u304A\u3084",
      "\u3084\u3051\u308B",
      "\u3084\u3055\u3044",
      "\u3084\u3055\u3057\u3044",
      "\u3084\u3059\u3044",
      "\u3084\u3059\u305F\u308D\u3046",
      "\u3084\u3059\u307F",
      "\u3084\u305B\u308B",
      "\u3084\u305D\u3046",
      "\u3084\u305F\u3044",
      "\u3084\u3061\u3093",
      "\u3084\u3063\u3068",
      "\u3084\u3063\u306F\u309A\u308A",
      "\u3084\u3075\u3099\u308B",
      "\u3084\u3081\u308B",
      "\u3084\u3084\u3053\u3057\u3044",
      "\u3084\u3088\u3044",
      "\u3084\u308F\u3089\u304B\u3044",
      "\u3086\u3046\u304D",
      "\u3086\u3046\u3072\u3099\u3093\u304D\u3087\u304F",
      "\u3086\u3046\u3078\u3099",
      "\u3086\u3046\u3081\u3044",
      "\u3086\u3051\u3064",
      "\u3086\u3057\u3085\u3064",
      "\u3086\u305B\u3093",
      "\u3086\u305D\u3046",
      "\u3086\u305F\u304B",
      "\u3086\u3061\u3083\u304F",
      "\u3086\u3066\u3099\u308B",
      "\u3086\u306B\u3085\u3046",
      "\u3086\u3072\u3099\u308F",
      "\u3086\u3089\u3044",
      "\u3086\u308C\u308B",
      "\u3088\u3046\u3044",
      "\u3088\u3046\u304B",
      "\u3088\u3046\u304D\u3085\u3046",
      "\u3088\u3046\u3057\u3099",
      "\u3088\u3046\u3059",
      "\u3088\u3046\u3061\u3048\u3093",
      "\u3088\u304B\u305B\u3099",
      "\u3088\u304B\u3093",
      "\u3088\u304D\u3093",
      "\u3088\u304F\u305B\u3044",
      "\u3088\u304F\u307B\u3099\u3046",
      "\u3088\u3051\u3044",
      "\u3088\u3053\u3099\u308C\u308B",
      "\u3088\u3055\u3093",
      "\u3088\u3057\u3085\u3046",
      "\u3088\u305D\u3046",
      "\u3088\u305D\u304F",
      "\u3088\u3063\u304B",
      "\u3088\u3066\u3044",
      "\u3088\u3068\u3099\u304B\u3099\u308F\u304F",
      "\u3088\u306D\u3064",
      "\u3088\u3084\u304F",
      "\u3088\u3086\u3046",
      "\u3088\u308D\u3053\u3075\u3099",
      "\u3088\u308D\u3057\u3044",
      "\u3089\u3044\u3046",
      "\u3089\u304F\u304B\u3099\u304D",
      "\u3089\u304F\u3053\u3099",
      "\u3089\u304F\u3055\u3064",
      "\u3089\u304F\u305F\u3099",
      "\u3089\u3057\u3093\u306F\u3099\u3093",
      "\u3089\u305B\u3093",
      "\u3089\u305D\u3099\u304F",
      "\u3089\u305F\u3044",
      "\u3089\u3063\u304B",
      "\u3089\u308C\u3064",
      "\u308A\u3048\u304D",
      "\u308A\u304B\u3044",
      "\u308A\u304D\u3055\u304F",
      "\u308A\u304D\u305B\u3064",
      "\u308A\u304F\u304F\u3099\u3093",
      "\u308A\u304F\u3064",
      "\u308A\u3051\u3093",
      "\u308A\u3053\u3046",
      "\u308A\u305B\u3044",
      "\u308A\u305D\u3046",
      "\u308A\u305D\u304F",
      "\u308A\u3066\u3093",
      "\u308A\u306D\u3093",
      "\u308A\u3086\u3046",
      "\u308A\u3085\u3046\u304B\u3099\u304F",
      "\u308A\u3088\u3046",
      "\u308A\u3087\u3046\u308A",
      "\u308A\u3087\u304B\u3093",
      "\u308A\u3087\u304F\u3061\u3083",
      "\u308A\u3087\u3053\u3046",
      "\u308A\u308A\u304F",
      "\u308A\u308C\u304D",
      "\u308A\u308D\u3093",
      "\u308A\u3093\u3053\u3099",
      "\u308B\u3044\u3051\u3044",
      "\u308B\u3044\u3055\u3044",
      "\u308B\u3044\u3057\u3099",
      "\u308B\u3044\u305B\u304D",
      "\u308B\u3059\u306F\u3099\u3093",
      "\u308B\u308A\u304B\u3099\u308F\u3089",
      "\u308C\u3044\u304B\u3093",
      "\u308C\u3044\u304D\u3099",
      "\u308C\u3044\u305B\u3044",
      "\u308C\u3044\u305D\u3099\u3046\u3053",
      "\u308C\u3044\u3068\u3046",
      "\u308C\u3044\u307B\u3099\u3046",
      "\u308C\u304D\u3057",
      "\u308C\u304D\u305F\u3099\u3044",
      "\u308C\u3093\u3042\u3044",
      "\u308C\u3093\u3051\u3044",
      "\u308C\u3093\u3053\u3093",
      "\u308C\u3093\u3055\u3044",
      "\u308C\u3093\u3057\u3085\u3046",
      "\u308C\u3093\u305D\u3099\u304F",
      "\u308C\u3093\u3089\u304F",
      "\u308D\u3046\u304B",
      "\u308D\u3046\u3053\u3099",
      "\u308D\u3046\u3057\u3099\u3093",
      "\u308D\u3046\u305D\u304F",
      "\u308D\u304F\u304B\u3099",
      "\u308D\u3053\u3064",
      "\u308D\u3057\u3099\u3046\u3089",
      "\u308D\u3057\u3085\u3064",
      "\u308D\u305B\u3093",
      "\u308D\u3066\u3093",
      "\u308D\u3081\u3093",
      "\u308D\u308C\u3064",
      "\u308D\u3093\u304D\u3099",
      "\u308D\u3093\u306F\u309A",
      "\u308D\u3093\u3075\u3099\u3093",
      "\u308D\u3093\u308A",
      "\u308F\u304B\u3059",
      "\u308F\u304B\u3081",
      "\u308F\u304B\u3084\u307E",
      "\u308F\u304B\u308C\u308B",
      "\u308F\u3057\u3064",
      "\u308F\u3057\u3099\u307E\u3057",
      "\u308F\u3059\u308C\u3082\u306E",
      "\u308F\u3089\u3046",
      "\u308F\u308C\u308B"
    ];
  }
});

// node_modules/bip39/src/wordlists/portuguese.json
var require_portuguese = __commonJS({
  "node_modules/bip39/src/wordlists/portuguese.json"(exports, module) {
    module.exports = [
      "abacate",
      "abaixo",
      "abalar",
      "abater",
      "abduzir",
      "abelha",
      "aberto",
      "abismo",
      "abotoar",
      "abranger",
      "abreviar",
      "abrigar",
      "abrupto",
      "absinto",
      "absoluto",
      "absurdo",
      "abutre",
      "acabado",
      "acalmar",
      "acampar",
      "acanhar",
      "acaso",
      "aceitar",
      "acelerar",
      "acenar",
      "acervo",
      "acessar",
      "acetona",
      "achatar",
      "acidez",
      "acima",
      "acionado",
      "acirrar",
      "aclamar",
      "aclive",
      "acolhida",
      "acomodar",
      "acoplar",
      "acordar",
      "acumular",
      "acusador",
      "adaptar",
      "adega",
      "adentro",
      "adepto",
      "adequar",
      "aderente",
      "adesivo",
      "adeus",
      "adiante",
      "aditivo",
      "adjetivo",
      "adjunto",
      "admirar",
      "adorar",
      "adquirir",
      "adubo",
      "adverso",
      "advogado",
      "aeronave",
      "afastar",
      "aferir",
      "afetivo",
      "afinador",
      "afivelar",
      "aflito",
      "afluente",
      "afrontar",
      "agachar",
      "agarrar",
      "agasalho",
      "agenciar",
      "agilizar",
      "agiota",
      "agitado",
      "agora",
      "agradar",
      "agreste",
      "agrupar",
      "aguardar",
      "agulha",
      "ajoelhar",
      "ajudar",
      "ajustar",
      "alameda",
      "alarme",
      "alastrar",
      "alavanca",
      "albergue",
      "albino",
      "alcatra",
      "aldeia",
      "alecrim",
      "alegria",
      "alertar",
      "alface",
      "alfinete",
      "algum",
      "alheio",
      "aliar",
      "alicate",
      "alienar",
      "alinhar",
      "aliviar",
      "almofada",
      "alocar",
      "alpiste",
      "alterar",
      "altitude",
      "alucinar",
      "alugar",
      "aluno",
      "alusivo",
      "alvo",
      "amaciar",
      "amador",
      "amarelo",
      "amassar",
      "ambas",
      "ambiente",
      "ameixa",
      "amenizar",
      "amido",
      "amistoso",
      "amizade",
      "amolador",
      "amontoar",
      "amoroso",
      "amostra",
      "amparar",
      "ampliar",
      "ampola",
      "anagrama",
      "analisar",
      "anarquia",
      "anatomia",
      "andaime",
      "anel",
      "anexo",
      "angular",
      "animar",
      "anjo",
      "anomalia",
      "anotado",
      "ansioso",
      "anterior",
      "anuidade",
      "anunciar",
      "anzol",
      "apagador",
      "apalpar",
      "apanhado",
      "apego",
      "apelido",
      "apertada",
      "apesar",
      "apetite",
      "apito",
      "aplauso",
      "aplicada",
      "apoio",
      "apontar",
      "aposta",
      "aprendiz",
      "aprovar",
      "aquecer",
      "arame",
      "aranha",
      "arara",
      "arcada",
      "ardente",
      "areia",
      "arejar",
      "arenito",
      "aresta",
      "argiloso",
      "argola",
      "arma",
      "arquivo",
      "arraial",
      "arrebate",
      "arriscar",
      "arroba",
      "arrumar",
      "arsenal",
      "arterial",
      "artigo",
      "arvoredo",
      "asfaltar",
      "asilado",
      "aspirar",
      "assador",
      "assinar",
      "assoalho",
      "assunto",
      "astral",
      "atacado",
      "atadura",
      "atalho",
      "atarefar",
      "atear",
      "atender",
      "aterro",
      "ateu",
      "atingir",
      "atirador",
      "ativo",
      "atoleiro",
      "atracar",
      "atrevido",
      "atriz",
      "atual",
      "atum",
      "auditor",
      "aumentar",
      "aura",
      "aurora",
      "autismo",
      "autoria",
      "autuar",
      "avaliar",
      "avante",
      "avaria",
      "avental",
      "avesso",
      "aviador",
      "avisar",
      "avulso",
      "axila",
      "azarar",
      "azedo",
      "azeite",
      "azulejo",
      "babar",
      "babosa",
      "bacalhau",
      "bacharel",
      "bacia",
      "bagagem",
      "baiano",
      "bailar",
      "baioneta",
      "bairro",
      "baixista",
      "bajular",
      "baleia",
      "baliza",
      "balsa",
      "banal",
      "bandeira",
      "banho",
      "banir",
      "banquete",
      "barato",
      "barbado",
      "baronesa",
      "barraca",
      "barulho",
      "baseado",
      "bastante",
      "batata",
      "batedor",
      "batida",
      "batom",
      "batucar",
      "baunilha",
      "beber",
      "beijo",
      "beirada",
      "beisebol",
      "beldade",
      "beleza",
      "belga",
      "beliscar",
      "bendito",
      "bengala",
      "benzer",
      "berimbau",
      "berlinda",
      "berro",
      "besouro",
      "bexiga",
      "bezerro",
      "bico",
      "bicudo",
      "bienal",
      "bifocal",
      "bifurcar",
      "bigorna",
      "bilhete",
      "bimestre",
      "bimotor",
      "biologia",
      "biombo",
      "biosfera",
      "bipolar",
      "birrento",
      "biscoito",
      "bisneto",
      "bispo",
      "bissexto",
      "bitola",
      "bizarro",
      "blindado",
      "bloco",
      "bloquear",
      "boato",
      "bobagem",
      "bocado",
      "bocejo",
      "bochecha",
      "boicotar",
      "bolada",
      "boletim",
      "bolha",
      "bolo",
      "bombeiro",
      "bonde",
      "boneco",
      "bonita",
      "borbulha",
      "borda",
      "boreal",
      "borracha",
      "bovino",
      "boxeador",
      "branco",
      "brasa",
      "braveza",
      "breu",
      "briga",
      "brilho",
      "brincar",
      "broa",
      "brochura",
      "bronzear",
      "broto",
      "bruxo",
      "bucha",
      "budismo",
      "bufar",
      "bule",
      "buraco",
      "busca",
      "busto",
      "buzina",
      "cabana",
      "cabelo",
      "cabide",
      "cabo",
      "cabrito",
      "cacau",
      "cacetada",
      "cachorro",
      "cacique",
      "cadastro",
      "cadeado",
      "cafezal",
      "caiaque",
      "caipira",
      "caixote",
      "cajado",
      "caju",
      "calafrio",
      "calcular",
      "caldeira",
      "calibrar",
      "calmante",
      "calota",
      "camada",
      "cambista",
      "camisa",
      "camomila",
      "campanha",
      "camuflar",
      "canavial",
      "cancelar",
      "caneta",
      "canguru",
      "canhoto",
      "canivete",
      "canoa",
      "cansado",
      "cantar",
      "canudo",
      "capacho",
      "capela",
      "capinar",
      "capotar",
      "capricho",
      "captador",
      "capuz",
      "caracol",
      "carbono",
      "cardeal",
      "careca",
      "carimbar",
      "carneiro",
      "carpete",
      "carreira",
      "cartaz",
      "carvalho",
      "casaco",
      "casca",
      "casebre",
      "castelo",
      "casulo",
      "catarata",
      "cativar",
      "caule",
      "causador",
      "cautelar",
      "cavalo",
      "caverna",
      "cebola",
      "cedilha",
      "cegonha",
      "celebrar",
      "celular",
      "cenoura",
      "censo",
      "centeio",
      "cercar",
      "cerrado",
      "certeiro",
      "cerveja",
      "cetim",
      "cevada",
      "chacota",
      "chaleira",
      "chamado",
      "chapada",
      "charme",
      "chatice",
      "chave",
      "chefe",
      "chegada",
      "cheiro",
      "cheque",
      "chicote",
      "chifre",
      "chinelo",
      "chocalho",
      "chover",
      "chumbo",
      "chutar",
      "chuva",
      "cicatriz",
      "ciclone",
      "cidade",
      "cidreira",
      "ciente",
      "cigana",
      "cimento",
      "cinto",
      "cinza",
      "ciranda",
      "circuito",
      "cirurgia",
      "citar",
      "clareza",
      "clero",
      "clicar",
      "clone",
      "clube",
      "coado",
      "coagir",
      "cobaia",
      "cobertor",
      "cobrar",
      "cocada",
      "coelho",
      "coentro",
      "coeso",
      "cogumelo",
      "coibir",
      "coifa",
      "coiote",
      "colar",
      "coleira",
      "colher",
      "colidir",
      "colmeia",
      "colono",
      "coluna",
      "comando",
      "combinar",
      "comentar",
      "comitiva",
      "comover",
      "complexo",
      "comum",
      "concha",
      "condor",
      "conectar",
      "confuso",
      "congelar",
      "conhecer",
      "conjugar",
      "consumir",
      "contrato",
      "convite",
      "cooperar",
      "copeiro",
      "copiador",
      "copo",
      "coquetel",
      "coragem",
      "cordial",
      "corneta",
      "coronha",
      "corporal",
      "correio",
      "cortejo",
      "coruja",
      "corvo",
      "cosseno",
      "costela",
      "cotonete",
      "couro",
      "couve",
      "covil",
      "cozinha",
      "cratera",
      "cravo",
      "creche",
      "credor",
      "creme",
      "crer",
      "crespo",
      "criada",
      "criminal",
      "crioulo",
      "crise",
      "criticar",
      "crosta",
      "crua",
      "cruzeiro",
      "cubano",
      "cueca",
      "cuidado",
      "cujo",
      "culatra",
      "culminar",
      "culpar",
      "cultura",
      "cumprir",
      "cunhado",
      "cupido",
      "curativo",
      "curral",
      "cursar",
      "curto",
      "cuspir",
      "custear",
      "cutelo",
      "damasco",
      "datar",
      "debater",
      "debitar",
      "deboche",
      "debulhar",
      "decalque",
      "decimal",
      "declive",
      "decote",
      "decretar",
      "dedal",
      "dedicado",
      "deduzir",
      "defesa",
      "defumar",
      "degelo",
      "degrau",
      "degustar",
      "deitado",
      "deixar",
      "delator",
      "delegado",
      "delinear",
      "delonga",
      "demanda",
      "demitir",
      "demolido",
      "dentista",
      "depenado",
      "depilar",
      "depois",
      "depressa",
      "depurar",
      "deriva",
      "derramar",
      "desafio",
      "desbotar",
      "descanso",
      "desenho",
      "desfiado",
      "desgaste",
      "desigual",
      "deslize",
      "desmamar",
      "desova",
      "despesa",
      "destaque",
      "desviar",
      "detalhar",
      "detentor",
      "detonar",
      "detrito",
      "deusa",
      "dever",
      "devido",
      "devotado",
      "dezena",
      "diagrama",
      "dialeto",
      "didata",
      "difuso",
      "digitar",
      "dilatado",
      "diluente",
      "diminuir",
      "dinastia",
      "dinheiro",
      "diocese",
      "direto",
      "discreta",
      "disfarce",
      "disparo",
      "disquete",
      "dissipar",
      "distante",
      "ditador",
      "diurno",
      "diverso",
      "divisor",
      "divulgar",
      "dizer",
      "dobrador",
      "dolorido",
      "domador",
      "dominado",
      "donativo",
      "donzela",
      "dormente",
      "dorsal",
      "dosagem",
      "dourado",
      "doutor",
      "drenagem",
      "drible",
      "drogaria",
      "duelar",
      "duende",
      "dueto",
      "duplo",
      "duquesa",
      "durante",
      "duvidoso",
      "eclodir",
      "ecoar",
      "ecologia",
      "edificar",
      "edital",
      "educado",
      "efeito",
      "efetivar",
      "ejetar",
      "elaborar",
      "eleger",
      "eleitor",
      "elenco",
      "elevador",
      "eliminar",
      "elogiar",
      "embargo",
      "embolado",
      "embrulho",
      "embutido",
      "emenda",
      "emergir",
      "emissor",
      "empatia",
      "empenho",
      "empinado",
      "empolgar",
      "emprego",
      "empurrar",
      "emulador",
      "encaixe",
      "encenado",
      "enchente",
      "encontro",
      "endeusar",
      "endossar",
      "enfaixar",
      "enfeite",
      "enfim",
      "engajado",
      "engenho",
      "englobar",
      "engomado",
      "engraxar",
      "enguia",
      "enjoar",
      "enlatar",
      "enquanto",
      "enraizar",
      "enrolado",
      "enrugar",
      "ensaio",
      "enseada",
      "ensino",
      "ensopado",
      "entanto",
      "enteado",
      "entidade",
      "entortar",
      "entrada",
      "entulho",
      "envergar",
      "enviado",
      "envolver",
      "enxame",
      "enxerto",
      "enxofre",
      "enxuto",
      "epiderme",
      "equipar",
      "ereto",
      "erguido",
      "errata",
      "erva",
      "ervilha",
      "esbanjar",
      "esbelto",
      "escama",
      "escola",
      "escrita",
      "escuta",
      "esfinge",
      "esfolar",
      "esfregar",
      "esfumado",
      "esgrima",
      "esmalte",
      "espanto",
      "espelho",
      "espiga",
      "esponja",
      "espreita",
      "espumar",
      "esquerda",
      "estaca",
      "esteira",
      "esticar",
      "estofado",
      "estrela",
      "estudo",
      "esvaziar",
      "etanol",
      "etiqueta",
      "euforia",
      "europeu",
      "evacuar",
      "evaporar",
      "evasivo",
      "eventual",
      "evidente",
      "evoluir",
      "exagero",
      "exalar",
      "examinar",
      "exato",
      "exausto",
      "excesso",
      "excitar",
      "exclamar",
      "executar",
      "exemplo",
      "exibir",
      "exigente",
      "exonerar",
      "expandir",
      "expelir",
      "expirar",
      "explanar",
      "exposto",
      "expresso",
      "expulsar",
      "externo",
      "extinto",
      "extrato",
      "fabricar",
      "fabuloso",
      "faceta",
      "facial",
      "fada",
      "fadiga",
      "faixa",
      "falar",
      "falta",
      "familiar",
      "fandango",
      "fanfarra",
      "fantoche",
      "fardado",
      "farelo",
      "farinha",
      "farofa",
      "farpa",
      "fartura",
      "fatia",
      "fator",
      "favorita",
      "faxina",
      "fazenda",
      "fechado",
      "feijoada",
      "feirante",
      "felino",
      "feminino",
      "fenda",
      "feno",
      "fera",
      "feriado",
      "ferrugem",
      "ferver",
      "festejar",
      "fetal",
      "feudal",
      "fiapo",
      "fibrose",
      "ficar",
      "ficheiro",
      "figurado",
      "fileira",
      "filho",
      "filme",
      "filtrar",
      "firmeza",
      "fisgada",
      "fissura",
      "fita",
      "fivela",
      "fixador",
      "fixo",
      "flacidez",
      "flamingo",
      "flanela",
      "flechada",
      "flora",
      "flutuar",
      "fluxo",
      "focal",
      "focinho",
      "fofocar",
      "fogo",
      "foguete",
      "foice",
      "folgado",
      "folheto",
      "forjar",
      "formiga",
      "forno",
      "forte",
      "fosco",
      "fossa",
      "fragata",
      "fralda",
      "frango",
      "frasco",
      "fraterno",
      "freira",
      "frente",
      "fretar",
      "frieza",
      "friso",
      "fritura",
      "fronha",
      "frustrar",
      "fruteira",
      "fugir",
      "fulano",
      "fuligem",
      "fundar",
      "fungo",
      "funil",
      "furador",
      "furioso",
      "futebol",
      "gabarito",
      "gabinete",
      "gado",
      "gaiato",
      "gaiola",
      "gaivota",
      "galega",
      "galho",
      "galinha",
      "galocha",
      "ganhar",
      "garagem",
      "garfo",
      "gargalo",
      "garimpo",
      "garoupa",
      "garrafa",
      "gasoduto",
      "gasto",
      "gata",
      "gatilho",
      "gaveta",
      "gazela",
      "gelado",
      "geleia",
      "gelo",
      "gemada",
      "gemer",
      "gemido",
      "generoso",
      "gengiva",
      "genial",
      "genoma",
      "genro",
      "geologia",
      "gerador",
      "germinar",
      "gesso",
      "gestor",
      "ginasta",
      "gincana",
      "gingado",
      "girafa",
      "girino",
      "glacial",
      "glicose",
      "global",
      "glorioso",
      "goela",
      "goiaba",
      "golfe",
      "golpear",
      "gordura",
      "gorjeta",
      "gorro",
      "gostoso",
      "goteira",
      "governar",
      "gracejo",
      "gradual",
      "grafite",
      "gralha",
      "grampo",
      "granada",
      "gratuito",
      "graveto",
      "graxa",
      "grego",
      "grelhar",
      "greve",
      "grilo",
      "grisalho",
      "gritaria",
      "grosso",
      "grotesco",
      "grudado",
      "grunhido",
      "gruta",
      "guache",
      "guarani",
      "guaxinim",
      "guerrear",
      "guiar",
      "guincho",
      "guisado",
      "gula",
      "guloso",
      "guru",
      "habitar",
      "harmonia",
      "haste",
      "haver",
      "hectare",
      "herdar",
      "heresia",
      "hesitar",
      "hiato",
      "hibernar",
      "hidratar",
      "hiena",
      "hino",
      "hipismo",
      "hipnose",
      "hipoteca",
      "hoje",
      "holofote",
      "homem",
      "honesto",
      "honrado",
      "hormonal",
      "hospedar",
      "humorado",
      "iate",
      "ideia",
      "idoso",
      "ignorado",
      "igreja",
      "iguana",
      "ileso",
      "ilha",
      "iludido",
      "iluminar",
      "ilustrar",
      "imagem",
      "imediato",
      "imenso",
      "imersivo",
      "iminente",
      "imitador",
      "imortal",
      "impacto",
      "impedir",
      "implante",
      "impor",
      "imprensa",
      "impune",
      "imunizar",
      "inalador",
      "inapto",
      "inativo",
      "incenso",
      "inchar",
      "incidir",
      "incluir",
      "incolor",
      "indeciso",
      "indireto",
      "indutor",
      "ineficaz",
      "inerente",
      "infantil",
      "infestar",
      "infinito",
      "inflamar",
      "informal",
      "infrator",
      "ingerir",
      "inibido",
      "inicial",
      "inimigo",
      "injetar",
      "inocente",
      "inodoro",
      "inovador",
      "inox",
      "inquieto",
      "inscrito",
      "inseto",
      "insistir",
      "inspetor",
      "instalar",
      "insulto",
      "intacto",
      "integral",
      "intimar",
      "intocado",
      "intriga",
      "invasor",
      "inverno",
      "invicto",
      "invocar",
      "iogurte",
      "iraniano",
      "ironizar",
      "irreal",
      "irritado",
      "isca",
      "isento",
      "isolado",
      "isqueiro",
      "italiano",
      "janeiro",
      "jangada",
      "janta",
      "jararaca",
      "jardim",
      "jarro",
      "jasmim",
      "jato",
      "javali",
      "jazida",
      "jejum",
      "joaninha",
      "joelhada",
      "jogador",
      "joia",
      "jornal",
      "jorrar",
      "jovem",
      "juba",
      "judeu",
      "judoca",
      "juiz",
      "julgador",
      "julho",
      "jurado",
      "jurista",
      "juro",
      "justa",
      "labareda",
      "laboral",
      "lacre",
      "lactante",
      "ladrilho",
      "lagarta",
      "lagoa",
      "laje",
      "lamber",
      "lamentar",
      "laminar",
      "lampejo",
      "lanche",
      "lapidar",
      "lapso",
      "laranja",
      "lareira",
      "largura",
      "lasanha",
      "lastro",
      "lateral",
      "latido",
      "lavanda",
      "lavoura",
      "lavrador",
      "laxante",
      "lazer",
      "lealdade",
      "lebre",
      "legado",
      "legendar",
      "legista",
      "leigo",
      "leiloar",
      "leitura",
      "lembrete",
      "leme",
      "lenhador",
      "lentilha",
      "leoa",
      "lesma",
      "leste",
      "letivo",
      "letreiro",
      "levar",
      "leveza",
      "levitar",
      "liberal",
      "libido",
      "liderar",
      "ligar",
      "ligeiro",
      "limitar",
      "limoeiro",
      "limpador",
      "linda",
      "linear",
      "linhagem",
      "liquidez",
      "listagem",
      "lisura",
      "litoral",
      "livro",
      "lixa",
      "lixeira",
      "locador",
      "locutor",
      "lojista",
      "lombo",
      "lona",
      "longe",
      "lontra",
      "lorde",
      "lotado",
      "loteria",
      "loucura",
      "lousa",
      "louvar",
      "luar",
      "lucidez",
      "lucro",
      "luneta",
      "lustre",
      "lutador",
      "luva",
      "macaco",
      "macete",
      "machado",
      "macio",
      "madeira",
      "madrinha",
      "magnata",
      "magreza",
      "maior",
      "mais",
      "malandro",
      "malha",
      "malote",
      "maluco",
      "mamilo",
      "mamoeiro",
      "mamute",
      "manada",
      "mancha",
      "mandato",
      "manequim",
      "manhoso",
      "manivela",
      "manobrar",
      "mansa",
      "manter",
      "manusear",
      "mapeado",
      "maquinar",
      "marcador",
      "maresia",
      "marfim",
      "margem",
      "marinho",
      "marmita",
      "maroto",
      "marquise",
      "marreco",
      "martelo",
      "marujo",
      "mascote",
      "masmorra",
      "massagem",
      "mastigar",
      "matagal",
      "materno",
      "matinal",
      "matutar",
      "maxilar",
      "medalha",
      "medida",
      "medusa",
      "megafone",
      "meiga",
      "melancia",
      "melhor",
      "membro",
      "memorial",
      "menino",
      "menos",
      "mensagem",
      "mental",
      "merecer",
      "mergulho",
      "mesada",
      "mesclar",
      "mesmo",
      "mesquita",
      "mestre",
      "metade",
      "meteoro",
      "metragem",
      "mexer",
      "mexicano",
      "micro",
      "migalha",
      "migrar",
      "milagre",
      "milenar",
      "milhar",
      "mimado",
      "minerar",
      "minhoca",
      "ministro",
      "minoria",
      "miolo",
      "mirante",
      "mirtilo",
      "misturar",
      "mocidade",
      "moderno",
      "modular",
      "moeda",
      "moer",
      "moinho",
      "moita",
      "moldura",
      "moleza",
      "molho",
      "molinete",
      "molusco",
      "montanha",
      "moqueca",
      "morango",
      "morcego",
      "mordomo",
      "morena",
      "mosaico",
      "mosquete",
      "mostarda",
      "motel",
      "motim",
      "moto",
      "motriz",
      "muda",
      "muito",
      "mulata",
      "mulher",
      "multar",
      "mundial",
      "munido",
      "muralha",
      "murcho",
      "muscular",
      "museu",
      "musical",
      "nacional",
      "nadador",
      "naja",
      "namoro",
      "narina",
      "narrado",
      "nascer",
      "nativa",
      "natureza",
      "navalha",
      "navegar",
      "navio",
      "neblina",
      "nebuloso",
      "negativa",
      "negociar",
      "negrito",
      "nervoso",
      "neta",
      "neural",
      "nevasca",
      "nevoeiro",
      "ninar",
      "ninho",
      "nitidez",
      "nivelar",
      "nobreza",
      "noite",
      "noiva",
      "nomear",
      "nominal",
      "nordeste",
      "nortear",
      "notar",
      "noticiar",
      "noturno",
      "novelo",
      "novilho",
      "novo",
      "nublado",
      "nudez",
      "numeral",
      "nupcial",
      "nutrir",
      "nuvem",
      "obcecado",
      "obedecer",
      "objetivo",
      "obrigado",
      "obscuro",
      "obstetra",
      "obter",
      "obturar",
      "ocidente",
      "ocioso",
      "ocorrer",
      "oculista",
      "ocupado",
      "ofegante",
      "ofensiva",
      "oferenda",
      "oficina",
      "ofuscado",
      "ogiva",
      "olaria",
      "oleoso",
      "olhar",
      "oliveira",
      "ombro",
      "omelete",
      "omisso",
      "omitir",
      "ondulado",
      "oneroso",
      "ontem",
      "opcional",
      "operador",
      "oponente",
      "oportuno",
      "oposto",
      "orar",
      "orbitar",
      "ordem",
      "ordinal",
      "orfanato",
      "orgasmo",
      "orgulho",
      "oriental",
      "origem",
      "oriundo",
      "orla",
      "ortodoxo",
      "orvalho",
      "oscilar",
      "ossada",
      "osso",
      "ostentar",
      "otimismo",
      "ousadia",
      "outono",
      "outubro",
      "ouvido",
      "ovelha",
      "ovular",
      "oxidar",
      "oxigenar",
      "pacato",
      "paciente",
      "pacote",
      "pactuar",
      "padaria",
      "padrinho",
      "pagar",
      "pagode",
      "painel",
      "pairar",
      "paisagem",
      "palavra",
      "palestra",
      "palheta",
      "palito",
      "palmada",
      "palpitar",
      "pancada",
      "panela",
      "panfleto",
      "panqueca",
      "pantanal",
      "papagaio",
      "papelada",
      "papiro",
      "parafina",
      "parcial",
      "pardal",
      "parede",
      "partida",
      "pasmo",
      "passado",
      "pastel",
      "patamar",
      "patente",
      "patinar",
      "patrono",
      "paulada",
      "pausar",
      "peculiar",
      "pedalar",
      "pedestre",
      "pediatra",
      "pedra",
      "pegada",
      "peitoral",
      "peixe",
      "pele",
      "pelicano",
      "penca",
      "pendurar",
      "peneira",
      "penhasco",
      "pensador",
      "pente",
      "perceber",
      "perfeito",
      "pergunta",
      "perito",
      "permitir",
      "perna",
      "perplexo",
      "persiana",
      "pertence",
      "peruca",
      "pescado",
      "pesquisa",
      "pessoa",
      "petiscar",
      "piada",
      "picado",
      "piedade",
      "pigmento",
      "pilastra",
      "pilhado",
      "pilotar",
      "pimenta",
      "pincel",
      "pinguim",
      "pinha",
      "pinote",
      "pintar",
      "pioneiro",
      "pipoca",
      "piquete",
      "piranha",
      "pires",
      "pirueta",
      "piscar",
      "pistola",
      "pitanga",
      "pivete",
      "planta",
      "plaqueta",
      "platina",
      "plebeu",
      "plumagem",
      "pluvial",
      "pneu",
      "poda",
      "poeira",
      "poetisa",
      "polegada",
      "policiar",
      "poluente",
      "polvilho",
      "pomar",
      "pomba",
      "ponderar",
      "pontaria",
      "populoso",
      "porta",
      "possuir",
      "postal",
      "pote",
      "poupar",
      "pouso",
      "povoar",
      "praia",
      "prancha",
      "prato",
      "praxe",
      "prece",
      "predador",
      "prefeito",
      "premiar",
      "prensar",
      "preparar",
      "presilha",
      "pretexto",
      "prevenir",
      "prezar",
      "primata",
      "princesa",
      "prisma",
      "privado",
      "processo",
      "produto",
      "profeta",
      "proibido",
      "projeto",
      "prometer",
      "propagar",
      "prosa",
      "protetor",
      "provador",
      "publicar",
      "pudim",
      "pular",
      "pulmonar",
      "pulseira",
      "punhal",
      "punir",
      "pupilo",
      "pureza",
      "puxador",
      "quadra",
      "quantia",
      "quarto",
      "quase",
      "quebrar",
      "queda",
      "queijo",
      "quente",
      "querido",
      "quimono",
      "quina",
      "quiosque",
      "rabanada",
      "rabisco",
      "rachar",
      "racionar",
      "radial",
      "raiar",
      "rainha",
      "raio",
      "raiva",
      "rajada",
      "ralado",
      "ramal",
      "ranger",
      "ranhura",
      "rapadura",
      "rapel",
      "rapidez",
      "raposa",
      "raquete",
      "raridade",
      "rasante",
      "rascunho",
      "rasgar",
      "raspador",
      "rasteira",
      "rasurar",
      "ratazana",
      "ratoeira",
      "realeza",
      "reanimar",
      "reaver",
      "rebaixar",
      "rebelde",
      "rebolar",
      "recado",
      "recente",
      "recheio",
      "recibo",
      "recordar",
      "recrutar",
      "recuar",
      "rede",
      "redimir",
      "redonda",
      "reduzida",
      "reenvio",
      "refinar",
      "refletir",
      "refogar",
      "refresco",
      "refugiar",
      "regalia",
      "regime",
      "regra",
      "reinado",
      "reitor",
      "rejeitar",
      "relativo",
      "remador",
      "remendo",
      "remorso",
      "renovado",
      "reparo",
      "repelir",
      "repleto",
      "repolho",
      "represa",
      "repudiar",
      "requerer",
      "resenha",
      "resfriar",
      "resgatar",
      "residir",
      "resolver",
      "respeito",
      "ressaca",
      "restante",
      "resumir",
      "retalho",
      "reter",
      "retirar",
      "retomada",
      "retratar",
      "revelar",
      "revisor",
      "revolta",
      "riacho",
      "rica",
      "rigidez",
      "rigoroso",
      "rimar",
      "ringue",
      "risada",
      "risco",
      "risonho",
      "robalo",
      "rochedo",
      "rodada",
      "rodeio",
      "rodovia",
      "roedor",
      "roleta",
      "romano",
      "roncar",
      "rosado",
      "roseira",
      "rosto",
      "rota",
      "roteiro",
      "rotina",
      "rotular",
      "rouco",
      "roupa",
      "roxo",
      "rubro",
      "rugido",
      "rugoso",
      "ruivo",
      "rumo",
      "rupestre",
      "russo",
      "sabor",
      "saciar",
      "sacola",
      "sacudir",
      "sadio",
      "safira",
      "saga",
      "sagrada",
      "saibro",
      "salada",
      "saleiro",
      "salgado",
      "saliva",
      "salpicar",
      "salsicha",
      "saltar",
      "salvador",
      "sambar",
      "samurai",
      "sanar",
      "sanfona",
      "sangue",
      "sanidade",
      "sapato",
      "sarda",
      "sargento",
      "sarjeta",
      "saturar",
      "saudade",
      "saxofone",
      "sazonal",
      "secar",
      "secular",
      "seda",
      "sedento",
      "sediado",
      "sedoso",
      "sedutor",
      "segmento",
      "segredo",
      "segundo",
      "seiva",
      "seleto",
      "selvagem",
      "semanal",
      "semente",
      "senador",
      "senhor",
      "sensual",
      "sentado",
      "separado",
      "sereia",
      "seringa",
      "serra",
      "servo",
      "setembro",
      "setor",
      "sigilo",
      "silhueta",
      "silicone",
      "simetria",
      "simpatia",
      "simular",
      "sinal",
      "sincero",
      "singular",
      "sinopse",
      "sintonia",
      "sirene",
      "siri",
      "situado",
      "soberano",
      "sobra",
      "socorro",
      "sogro",
      "soja",
      "solda",
      "soletrar",
      "solteiro",
      "sombrio",
      "sonata",
      "sondar",
      "sonegar",
      "sonhador",
      "sono",
      "soprano",
      "soquete",
      "sorrir",
      "sorteio",
      "sossego",
      "sotaque",
      "soterrar",
      "sovado",
      "sozinho",
      "suavizar",
      "subida",
      "submerso",
      "subsolo",
      "subtrair",
      "sucata",
      "sucesso",
      "suco",
      "sudeste",
      "sufixo",
      "sugador",
      "sugerir",
      "sujeito",
      "sulfato",
      "sumir",
      "suor",
      "superior",
      "suplicar",
      "suposto",
      "suprimir",
      "surdina",
      "surfista",
      "surpresa",
      "surreal",
      "surtir",
      "suspiro",
      "sustento",
      "tabela",
      "tablete",
      "tabuada",
      "tacho",
      "tagarela",
      "talher",
      "talo",
      "talvez",
      "tamanho",
      "tamborim",
      "tampa",
      "tangente",
      "tanto",
      "tapar",
      "tapioca",
      "tardio",
      "tarefa",
      "tarja",
      "tarraxa",
      "tatuagem",
      "taurino",
      "taxativo",
      "taxista",
      "teatral",
      "tecer",
      "tecido",
      "teclado",
      "tedioso",
      "teia",
      "teimar",
      "telefone",
      "telhado",
      "tempero",
      "tenente",
      "tensor",
      "tentar",
      "termal",
      "terno",
      "terreno",
      "tese",
      "tesoura",
      "testado",
      "teto",
      "textura",
      "texugo",
      "tiara",
      "tigela",
      "tijolo",
      "timbrar",
      "timidez",
      "tingido",
      "tinteiro",
      "tiragem",
      "titular",
      "toalha",
      "tocha",
      "tolerar",
      "tolice",
      "tomada",
      "tomilho",
      "tonel",
      "tontura",
      "topete",
      "tora",
      "torcido",
      "torneio",
      "torque",
      "torrada",
      "torto",
      "tostar",
      "touca",
      "toupeira",
      "toxina",
      "trabalho",
      "tracejar",
      "tradutor",
      "trafegar",
      "trajeto",
      "trama",
      "trancar",
      "trapo",
      "traseiro",
      "tratador",
      "travar",
      "treino",
      "tremer",
      "trepidar",
      "trevo",
      "triagem",
      "tribo",
      "triciclo",
      "tridente",
      "trilogia",
      "trindade",
      "triplo",
      "triturar",
      "triunfal",
      "trocar",
      "trombeta",
      "trova",
      "trunfo",
      "truque",
      "tubular",
      "tucano",
      "tudo",
      "tulipa",
      "tupi",
      "turbo",
      "turma",
      "turquesa",
      "tutelar",
      "tutorial",
      "uivar",
      "umbigo",
      "unha",
      "unidade",
      "uniforme",
      "urologia",
      "urso",
      "urtiga",
      "urubu",
      "usado",
      "usina",
      "usufruir",
      "vacina",
      "vadiar",
      "vagaroso",
      "vaidoso",
      "vala",
      "valente",
      "validade",
      "valores",
      "vantagem",
      "vaqueiro",
      "varanda",
      "vareta",
      "varrer",
      "vascular",
      "vasilha",
      "vassoura",
      "vazar",
      "vazio",
      "veado",
      "vedar",
      "vegetar",
      "veicular",
      "veleiro",
      "velhice",
      "veludo",
      "vencedor",
      "vendaval",
      "venerar",
      "ventre",
      "verbal",
      "verdade",
      "vereador",
      "vergonha",
      "vermelho",
      "verniz",
      "versar",
      "vertente",
      "vespa",
      "vestido",
      "vetorial",
      "viaduto",
      "viagem",
      "viajar",
      "viatura",
      "vibrador",
      "videira",
      "vidraria",
      "viela",
      "viga",
      "vigente",
      "vigiar",
      "vigorar",
      "vilarejo",
      "vinco",
      "vinheta",
      "vinil",
      "violeta",
      "virada",
      "virtude",
      "visitar",
      "visto",
      "vitral",
      "viveiro",
      "vizinho",
      "voador",
      "voar",
      "vogal",
      "volante",
      "voleibol",
      "voltagem",
      "volumoso",
      "vontade",
      "vulto",
      "vuvuzela",
      "xadrez",
      "xarope",
      "xeque",
      "xeretar",
      "xerife",
      "xingar",
      "zangado",
      "zarpar",
      "zebu",
      "zelador",
      "zombar",
      "zoologia",
      "zumbido"
    ];
  }
});

// node_modules/bip39/src/wordlists/english.json
var require_english = __commonJS({
  "node_modules/bip39/src/wordlists/english.json"(exports, module) {
    module.exports = [
      "abandon",
      "ability",
      "able",
      "about",
      "above",
      "absent",
      "absorb",
      "abstract",
      "absurd",
      "abuse",
      "access",
      "accident",
      "account",
      "accuse",
      "achieve",
      "acid",
      "acoustic",
      "acquire",
      "across",
      "act",
      "action",
      "actor",
      "actress",
      "actual",
      "adapt",
      "add",
      "addict",
      "address",
      "adjust",
      "admit",
      "adult",
      "advance",
      "advice",
      "aerobic",
      "affair",
      "afford",
      "afraid",
      "again",
      "age",
      "agent",
      "agree",
      "ahead",
      "aim",
      "air",
      "airport",
      "aisle",
      "alarm",
      "album",
      "alcohol",
      "alert",
      "alien",
      "all",
      "alley",
      "allow",
      "almost",
      "alone",
      "alpha",
      "already",
      "also",
      "alter",
      "always",
      "amateur",
      "amazing",
      "among",
      "amount",
      "amused",
      "analyst",
      "anchor",
      "ancient",
      "anger",
      "angle",
      "angry",
      "animal",
      "ankle",
      "announce",
      "annual",
      "another",
      "answer",
      "antenna",
      "antique",
      "anxiety",
      "any",
      "apart",
      "apology",
      "appear",
      "apple",
      "approve",
      "april",
      "arch",
      "arctic",
      "area",
      "arena",
      "argue",
      "arm",
      "armed",
      "armor",
      "army",
      "around",
      "arrange",
      "arrest",
      "arrive",
      "arrow",
      "art",
      "artefact",
      "artist",
      "artwork",
      "ask",
      "aspect",
      "assault",
      "asset",
      "assist",
      "assume",
      "asthma",
      "athlete",
      "atom",
      "attack",
      "attend",
      "attitude",
      "attract",
      "auction",
      "audit",
      "august",
      "aunt",
      "author",
      "auto",
      "autumn",
      "average",
      "avocado",
      "avoid",
      "awake",
      "aware",
      "away",
      "awesome",
      "awful",
      "awkward",
      "axis",
      "baby",
      "bachelor",
      "bacon",
      "badge",
      "bag",
      "balance",
      "balcony",
      "ball",
      "bamboo",
      "banana",
      "banner",
      "bar",
      "barely",
      "bargain",
      "barrel",
      "base",
      "basic",
      "basket",
      "battle",
      "beach",
      "bean",
      "beauty",
      "because",
      "become",
      "beef",
      "before",
      "begin",
      "behave",
      "behind",
      "believe",
      "below",
      "belt",
      "bench",
      "benefit",
      "best",
      "betray",
      "better",
      "between",
      "beyond",
      "bicycle",
      "bid",
      "bike",
      "bind",
      "biology",
      "bird",
      "birth",
      "bitter",
      "black",
      "blade",
      "blame",
      "blanket",
      "blast",
      "bleak",
      "bless",
      "blind",
      "blood",
      "blossom",
      "blouse",
      "blue",
      "blur",
      "blush",
      "board",
      "boat",
      "body",
      "boil",
      "bomb",
      "bone",
      "bonus",
      "book",
      "boost",
      "border",
      "boring",
      "borrow",
      "boss",
      "bottom",
      "bounce",
      "box",
      "boy",
      "bracket",
      "brain",
      "brand",
      "brass",
      "brave",
      "bread",
      "breeze",
      "brick",
      "bridge",
      "brief",
      "bright",
      "bring",
      "brisk",
      "broccoli",
      "broken",
      "bronze",
      "broom",
      "brother",
      "brown",
      "brush",
      "bubble",
      "buddy",
      "budget",
      "buffalo",
      "build",
      "bulb",
      "bulk",
      "bullet",
      "bundle",
      "bunker",
      "burden",
      "burger",
      "burst",
      "bus",
      "business",
      "busy",
      "butter",
      "buyer",
      "buzz",
      "cabbage",
      "cabin",
      "cable",
      "cactus",
      "cage",
      "cake",
      "call",
      "calm",
      "camera",
      "camp",
      "can",
      "canal",
      "cancel",
      "candy",
      "cannon",
      "canoe",
      "canvas",
      "canyon",
      "capable",
      "capital",
      "captain",
      "car",
      "carbon",
      "card",
      "cargo",
      "carpet",
      "carry",
      "cart",
      "case",
      "cash",
      "casino",
      "castle",
      "casual",
      "cat",
      "catalog",
      "catch",
      "category",
      "cattle",
      "caught",
      "cause",
      "caution",
      "cave",
      "ceiling",
      "celery",
      "cement",
      "census",
      "century",
      "cereal",
      "certain",
      "chair",
      "chalk",
      "champion",
      "change",
      "chaos",
      "chapter",
      "charge",
      "chase",
      "chat",
      "cheap",
      "check",
      "cheese",
      "chef",
      "cherry",
      "chest",
      "chicken",
      "chief",
      "child",
      "chimney",
      "choice",
      "choose",
      "chronic",
      "chuckle",
      "chunk",
      "churn",
      "cigar",
      "cinnamon",
      "circle",
      "citizen",
      "city",
      "civil",
      "claim",
      "clap",
      "clarify",
      "claw",
      "clay",
      "clean",
      "clerk",
      "clever",
      "click",
      "client",
      "cliff",
      "climb",
      "clinic",
      "clip",
      "clock",
      "clog",
      "close",
      "cloth",
      "cloud",
      "clown",
      "club",
      "clump",
      "cluster",
      "clutch",
      "coach",
      "coast",
      "coconut",
      "code",
      "coffee",
      "coil",
      "coin",
      "collect",
      "color",
      "column",
      "combine",
      "come",
      "comfort",
      "comic",
      "common",
      "company",
      "concert",
      "conduct",
      "confirm",
      "congress",
      "connect",
      "consider",
      "control",
      "convince",
      "cook",
      "cool",
      "copper",
      "copy",
      "coral",
      "core",
      "corn",
      "correct",
      "cost",
      "cotton",
      "couch",
      "country",
      "couple",
      "course",
      "cousin",
      "cover",
      "coyote",
      "crack",
      "cradle",
      "craft",
      "cram",
      "crane",
      "crash",
      "crater",
      "crawl",
      "crazy",
      "cream",
      "credit",
      "creek",
      "crew",
      "cricket",
      "crime",
      "crisp",
      "critic",
      "crop",
      "cross",
      "crouch",
      "crowd",
      "crucial",
      "cruel",
      "cruise",
      "crumble",
      "crunch",
      "crush",
      "cry",
      "crystal",
      "cube",
      "culture",
      "cup",
      "cupboard",
      "curious",
      "current",
      "curtain",
      "curve",
      "cushion",
      "custom",
      "cute",
      "cycle",
      "dad",
      "damage",
      "damp",
      "dance",
      "danger",
      "daring",
      "dash",
      "daughter",
      "dawn",
      "day",
      "deal",
      "debate",
      "debris",
      "decade",
      "december",
      "decide",
      "decline",
      "decorate",
      "decrease",
      "deer",
      "defense",
      "define",
      "defy",
      "degree",
      "delay",
      "deliver",
      "demand",
      "demise",
      "denial",
      "dentist",
      "deny",
      "depart",
      "depend",
      "deposit",
      "depth",
      "deputy",
      "derive",
      "describe",
      "desert",
      "design",
      "desk",
      "despair",
      "destroy",
      "detail",
      "detect",
      "develop",
      "device",
      "devote",
      "diagram",
      "dial",
      "diamond",
      "diary",
      "dice",
      "diesel",
      "diet",
      "differ",
      "digital",
      "dignity",
      "dilemma",
      "dinner",
      "dinosaur",
      "direct",
      "dirt",
      "disagree",
      "discover",
      "disease",
      "dish",
      "dismiss",
      "disorder",
      "display",
      "distance",
      "divert",
      "divide",
      "divorce",
      "dizzy",
      "doctor",
      "document",
      "dog",
      "doll",
      "dolphin",
      "domain",
      "donate",
      "donkey",
      "donor",
      "door",
      "dose",
      "double",
      "dove",
      "draft",
      "dragon",
      "drama",
      "drastic",
      "draw",
      "dream",
      "dress",
      "drift",
      "drill",
      "drink",
      "drip",
      "drive",
      "drop",
      "drum",
      "dry",
      "duck",
      "dumb",
      "dune",
      "during",
      "dust",
      "dutch",
      "duty",
      "dwarf",
      "dynamic",
      "eager",
      "eagle",
      "early",
      "earn",
      "earth",
      "easily",
      "east",
      "easy",
      "echo",
      "ecology",
      "economy",
      "edge",
      "edit",
      "educate",
      "effort",
      "egg",
      "eight",
      "either",
      "elbow",
      "elder",
      "electric",
      "elegant",
      "element",
      "elephant",
      "elevator",
      "elite",
      "else",
      "embark",
      "embody",
      "embrace",
      "emerge",
      "emotion",
      "employ",
      "empower",
      "empty",
      "enable",
      "enact",
      "end",
      "endless",
      "endorse",
      "enemy",
      "energy",
      "enforce",
      "engage",
      "engine",
      "enhance",
      "enjoy",
      "enlist",
      "enough",
      "enrich",
      "enroll",
      "ensure",
      "enter",
      "entire",
      "entry",
      "envelope",
      "episode",
      "equal",
      "equip",
      "era",
      "erase",
      "erode",
      "erosion",
      "error",
      "erupt",
      "escape",
      "essay",
      "essence",
      "estate",
      "eternal",
      "ethics",
      "evidence",
      "evil",
      "evoke",
      "evolve",
      "exact",
      "example",
      "excess",
      "exchange",
      "excite",
      "exclude",
      "excuse",
      "execute",
      "exercise",
      "exhaust",
      "exhibit",
      "exile",
      "exist",
      "exit",
      "exotic",
      "expand",
      "expect",
      "expire",
      "explain",
      "expose",
      "express",
      "extend",
      "extra",
      "eye",
      "eyebrow",
      "fabric",
      "face",
      "faculty",
      "fade",
      "faint",
      "faith",
      "fall",
      "false",
      "fame",
      "family",
      "famous",
      "fan",
      "fancy",
      "fantasy",
      "farm",
      "fashion",
      "fat",
      "fatal",
      "father",
      "fatigue",
      "fault",
      "favorite",
      "feature",
      "february",
      "federal",
      "fee",
      "feed",
      "feel",
      "female",
      "fence",
      "festival",
      "fetch",
      "fever",
      "few",
      "fiber",
      "fiction",
      "field",
      "figure",
      "file",
      "film",
      "filter",
      "final",
      "find",
      "fine",
      "finger",
      "finish",
      "fire",
      "firm",
      "first",
      "fiscal",
      "fish",
      "fit",
      "fitness",
      "fix",
      "flag",
      "flame",
      "flash",
      "flat",
      "flavor",
      "flee",
      "flight",
      "flip",
      "float",
      "flock",
      "floor",
      "flower",
      "fluid",
      "flush",
      "fly",
      "foam",
      "focus",
      "fog",
      "foil",
      "fold",
      "follow",
      "food",
      "foot",
      "force",
      "forest",
      "forget",
      "fork",
      "fortune",
      "forum",
      "forward",
      "fossil",
      "foster",
      "found",
      "fox",
      "fragile",
      "frame",
      "frequent",
      "fresh",
      "friend",
      "fringe",
      "frog",
      "front",
      "frost",
      "frown",
      "frozen",
      "fruit",
      "fuel",
      "fun",
      "funny",
      "furnace",
      "fury",
      "future",
      "gadget",
      "gain",
      "galaxy",
      "gallery",
      "game",
      "gap",
      "garage",
      "garbage",
      "garden",
      "garlic",
      "garment",
      "gas",
      "gasp",
      "gate",
      "gather",
      "gauge",
      "gaze",
      "general",
      "genius",
      "genre",
      "gentle",
      "genuine",
      "gesture",
      "ghost",
      "giant",
      "gift",
      "giggle",
      "ginger",
      "giraffe",
      "girl",
      "give",
      "glad",
      "glance",
      "glare",
      "glass",
      "glide",
      "glimpse",
      "globe",
      "gloom",
      "glory",
      "glove",
      "glow",
      "glue",
      "goat",
      "goddess",
      "gold",
      "good",
      "goose",
      "gorilla",
      "gospel",
      "gossip",
      "govern",
      "gown",
      "grab",
      "grace",
      "grain",
      "grant",
      "grape",
      "grass",
      "gravity",
      "great",
      "green",
      "grid",
      "grief",
      "grit",
      "grocery",
      "group",
      "grow",
      "grunt",
      "guard",
      "guess",
      "guide",
      "guilt",
      "guitar",
      "gun",
      "gym",
      "habit",
      "hair",
      "half",
      "hammer",
      "hamster",
      "hand",
      "happy",
      "harbor",
      "hard",
      "harsh",
      "harvest",
      "hat",
      "have",
      "hawk",
      "hazard",
      "head",
      "health",
      "heart",
      "heavy",
      "hedgehog",
      "height",
      "hello",
      "helmet",
      "help",
      "hen",
      "hero",
      "hidden",
      "high",
      "hill",
      "hint",
      "hip",
      "hire",
      "history",
      "hobby",
      "hockey",
      "hold",
      "hole",
      "holiday",
      "hollow",
      "home",
      "honey",
      "hood",
      "hope",
      "horn",
      "horror",
      "horse",
      "hospital",
      "host",
      "hotel",
      "hour",
      "hover",
      "hub",
      "huge",
      "human",
      "humble",
      "humor",
      "hundred",
      "hungry",
      "hunt",
      "hurdle",
      "hurry",
      "hurt",
      "husband",
      "hybrid",
      "ice",
      "icon",
      "idea",
      "identify",
      "idle",
      "ignore",
      "ill",
      "illegal",
      "illness",
      "image",
      "imitate",
      "immense",
      "immune",
      "impact",
      "impose",
      "improve",
      "impulse",
      "inch",
      "include",
      "income",
      "increase",
      "index",
      "indicate",
      "indoor",
      "industry",
      "infant",
      "inflict",
      "inform",
      "inhale",
      "inherit",
      "initial",
      "inject",
      "injury",
      "inmate",
      "inner",
      "innocent",
      "input",
      "inquiry",
      "insane",
      "insect",
      "inside",
      "inspire",
      "install",
      "intact",
      "interest",
      "into",
      "invest",
      "invite",
      "involve",
      "iron",
      "island",
      "isolate",
      "issue",
      "item",
      "ivory",
      "jacket",
      "jaguar",
      "jar",
      "jazz",
      "jealous",
      "jeans",
      "jelly",
      "jewel",
      "job",
      "join",
      "joke",
      "journey",
      "joy",
      "judge",
      "juice",
      "jump",
      "jungle",
      "junior",
      "junk",
      "just",
      "kangaroo",
      "keen",
      "keep",
      "ketchup",
      "key",
      "kick",
      "kid",
      "kidney",
      "kind",
      "kingdom",
      "kiss",
      "kit",
      "kitchen",
      "kite",
      "kitten",
      "kiwi",
      "knee",
      "knife",
      "knock",
      "know",
      "lab",
      "label",
      "labor",
      "ladder",
      "lady",
      "lake",
      "lamp",
      "language",
      "laptop",
      "large",
      "later",
      "latin",
      "laugh",
      "laundry",
      "lava",
      "law",
      "lawn",
      "lawsuit",
      "layer",
      "lazy",
      "leader",
      "leaf",
      "learn",
      "leave",
      "lecture",
      "left",
      "leg",
      "legal",
      "legend",
      "leisure",
      "lemon",
      "lend",
      "length",
      "lens",
      "leopard",
      "lesson",
      "letter",
      "level",
      "liar",
      "liberty",
      "library",
      "license",
      "life",
      "lift",
      "light",
      "like",
      "limb",
      "limit",
      "link",
      "lion",
      "liquid",
      "list",
      "little",
      "live",
      "lizard",
      "load",
      "loan",
      "lobster",
      "local",
      "lock",
      "logic",
      "lonely",
      "long",
      "loop",
      "lottery",
      "loud",
      "lounge",
      "love",
      "loyal",
      "lucky",
      "luggage",
      "lumber",
      "lunar",
      "lunch",
      "luxury",
      "lyrics",
      "machine",
      "mad",
      "magic",
      "magnet",
      "maid",
      "mail",
      "main",
      "major",
      "make",
      "mammal",
      "man",
      "manage",
      "mandate",
      "mango",
      "mansion",
      "manual",
      "maple",
      "marble",
      "march",
      "margin",
      "marine",
      "market",
      "marriage",
      "mask",
      "mass",
      "master",
      "match",
      "material",
      "math",
      "matrix",
      "matter",
      "maximum",
      "maze",
      "meadow",
      "mean",
      "measure",
      "meat",
      "mechanic",
      "medal",
      "media",
      "melody",
      "melt",
      "member",
      "memory",
      "mention",
      "menu",
      "mercy",
      "merge",
      "merit",
      "merry",
      "mesh",
      "message",
      "metal",
      "method",
      "middle",
      "midnight",
      "milk",
      "million",
      "mimic",
      "mind",
      "minimum",
      "minor",
      "minute",
      "miracle",
      "mirror",
      "misery",
      "miss",
      "mistake",
      "mix",
      "mixed",
      "mixture",
      "mobile",
      "model",
      "modify",
      "mom",
      "moment",
      "monitor",
      "monkey",
      "monster",
      "month",
      "moon",
      "moral",
      "more",
      "morning",
      "mosquito",
      "mother",
      "motion",
      "motor",
      "mountain",
      "mouse",
      "move",
      "movie",
      "much",
      "muffin",
      "mule",
      "multiply",
      "muscle",
      "museum",
      "mushroom",
      "music",
      "must",
      "mutual",
      "myself",
      "mystery",
      "myth",
      "naive",
      "name",
      "napkin",
      "narrow",
      "nasty",
      "nation",
      "nature",
      "near",
      "neck",
      "need",
      "negative",
      "neglect",
      "neither",
      "nephew",
      "nerve",
      "nest",
      "net",
      "network",
      "neutral",
      "never",
      "news",
      "next",
      "nice",
      "night",
      "noble",
      "noise",
      "nominee",
      "noodle",
      "normal",
      "north",
      "nose",
      "notable",
      "note",
      "nothing",
      "notice",
      "novel",
      "now",
      "nuclear",
      "number",
      "nurse",
      "nut",
      "oak",
      "obey",
      "object",
      "oblige",
      "obscure",
      "observe",
      "obtain",
      "obvious",
      "occur",
      "ocean",
      "october",
      "odor",
      "off",
      "offer",
      "office",
      "often",
      "oil",
      "okay",
      "old",
      "olive",
      "olympic",
      "omit",
      "once",
      "one",
      "onion",
      "online",
      "only",
      "open",
      "opera",
      "opinion",
      "oppose",
      "option",
      "orange",
      "orbit",
      "orchard",
      "order",
      "ordinary",
      "organ",
      "orient",
      "original",
      "orphan",
      "ostrich",
      "other",
      "outdoor",
      "outer",
      "output",
      "outside",
      "oval",
      "oven",
      "over",
      "own",
      "owner",
      "oxygen",
      "oyster",
      "ozone",
      "pact",
      "paddle",
      "page",
      "pair",
      "palace",
      "palm",
      "panda",
      "panel",
      "panic",
      "panther",
      "paper",
      "parade",
      "parent",
      "park",
      "parrot",
      "party",
      "pass",
      "patch",
      "path",
      "patient",
      "patrol",
      "pattern",
      "pause",
      "pave",
      "payment",
      "peace",
      "peanut",
      "pear",
      "peasant",
      "pelican",
      "pen",
      "penalty",
      "pencil",
      "people",
      "pepper",
      "perfect",
      "permit",
      "person",
      "pet",
      "phone",
      "photo",
      "phrase",
      "physical",
      "piano",
      "picnic",
      "picture",
      "piece",
      "pig",
      "pigeon",
      "pill",
      "pilot",
      "pink",
      "pioneer",
      "pipe",
      "pistol",
      "pitch",
      "pizza",
      "place",
      "planet",
      "plastic",
      "plate",
      "play",
      "please",
      "pledge",
      "pluck",
      "plug",
      "plunge",
      "poem",
      "poet",
      "point",
      "polar",
      "pole",
      "police",
      "pond",
      "pony",
      "pool",
      "popular",
      "portion",
      "position",
      "possible",
      "post",
      "potato",
      "pottery",
      "poverty",
      "powder",
      "power",
      "practice",
      "praise",
      "predict",
      "prefer",
      "prepare",
      "present",
      "pretty",
      "prevent",
      "price",
      "pride",
      "primary",
      "print",
      "priority",
      "prison",
      "private",
      "prize",
      "problem",
      "process",
      "produce",
      "profit",
      "program",
      "project",
      "promote",
      "proof",
      "property",
      "prosper",
      "protect",
      "proud",
      "provide",
      "public",
      "pudding",
      "pull",
      "pulp",
      "pulse",
      "pumpkin",
      "punch",
      "pupil",
      "puppy",
      "purchase",
      "purity",
      "purpose",
      "purse",
      "push",
      "put",
      "puzzle",
      "pyramid",
      "quality",
      "quantum",
      "quarter",
      "question",
      "quick",
      "quit",
      "quiz",
      "quote",
      "rabbit",
      "raccoon",
      "race",
      "rack",
      "radar",
      "radio",
      "rail",
      "rain",
      "raise",
      "rally",
      "ramp",
      "ranch",
      "random",
      "range",
      "rapid",
      "rare",
      "rate",
      "rather",
      "raven",
      "raw",
      "razor",
      "ready",
      "real",
      "reason",
      "rebel",
      "rebuild",
      "recall",
      "receive",
      "recipe",
      "record",
      "recycle",
      "reduce",
      "reflect",
      "reform",
      "refuse",
      "region",
      "regret",
      "regular",
      "reject",
      "relax",
      "release",
      "relief",
      "rely",
      "remain",
      "remember",
      "remind",
      "remove",
      "render",
      "renew",
      "rent",
      "reopen",
      "repair",
      "repeat",
      "replace",
      "report",
      "require",
      "rescue",
      "resemble",
      "resist",
      "resource",
      "response",
      "result",
      "retire",
      "retreat",
      "return",
      "reunion",
      "reveal",
      "review",
      "reward",
      "rhythm",
      "rib",
      "ribbon",
      "rice",
      "rich",
      "ride",
      "ridge",
      "rifle",
      "right",
      "rigid",
      "ring",
      "riot",
      "ripple",
      "risk",
      "ritual",
      "rival",
      "river",
      "road",
      "roast",
      "robot",
      "robust",
      "rocket",
      "romance",
      "roof",
      "rookie",
      "room",
      "rose",
      "rotate",
      "rough",
      "round",
      "route",
      "royal",
      "rubber",
      "rude",
      "rug",
      "rule",
      "run",
      "runway",
      "rural",
      "sad",
      "saddle",
      "sadness",
      "safe",
      "sail",
      "salad",
      "salmon",
      "salon",
      "salt",
      "salute",
      "same",
      "sample",
      "sand",
      "satisfy",
      "satoshi",
      "sauce",
      "sausage",
      "save",
      "say",
      "scale",
      "scan",
      "scare",
      "scatter",
      "scene",
      "scheme",
      "school",
      "science",
      "scissors",
      "scorpion",
      "scout",
      "scrap",
      "screen",
      "script",
      "scrub",
      "sea",
      "search",
      "season",
      "seat",
      "second",
      "secret",
      "section",
      "security",
      "seed",
      "seek",
      "segment",
      "select",
      "sell",
      "seminar",
      "senior",
      "sense",
      "sentence",
      "series",
      "service",
      "session",
      "settle",
      "setup",
      "seven",
      "shadow",
      "shaft",
      "shallow",
      "share",
      "shed",
      "shell",
      "sheriff",
      "shield",
      "shift",
      "shine",
      "ship",
      "shiver",
      "shock",
      "shoe",
      "shoot",
      "shop",
      "short",
      "shoulder",
      "shove",
      "shrimp",
      "shrug",
      "shuffle",
      "shy",
      "sibling",
      "sick",
      "side",
      "siege",
      "sight",
      "sign",
      "silent",
      "silk",
      "silly",
      "silver",
      "similar",
      "simple",
      "since",
      "sing",
      "siren",
      "sister",
      "situate",
      "six",
      "size",
      "skate",
      "sketch",
      "ski",
      "skill",
      "skin",
      "skirt",
      "skull",
      "slab",
      "slam",
      "sleep",
      "slender",
      "slice",
      "slide",
      "slight",
      "slim",
      "slogan",
      "slot",
      "slow",
      "slush",
      "small",
      "smart",
      "smile",
      "smoke",
      "smooth",
      "snack",
      "snake",
      "snap",
      "sniff",
      "snow",
      "soap",
      "soccer",
      "social",
      "sock",
      "soda",
      "soft",
      "solar",
      "soldier",
      "solid",
      "solution",
      "solve",
      "someone",
      "song",
      "soon",
      "sorry",
      "sort",
      "soul",
      "sound",
      "soup",
      "source",
      "south",
      "space",
      "spare",
      "spatial",
      "spawn",
      "speak",
      "special",
      "speed",
      "spell",
      "spend",
      "sphere",
      "spice",
      "spider",
      "spike",
      "spin",
      "spirit",
      "split",
      "spoil",
      "sponsor",
      "spoon",
      "sport",
      "spot",
      "spray",
      "spread",
      "spring",
      "spy",
      "square",
      "squeeze",
      "squirrel",
      "stable",
      "stadium",
      "staff",
      "stage",
      "stairs",
      "stamp",
      "stand",
      "start",
      "state",
      "stay",
      "steak",
      "steel",
      "stem",
      "step",
      "stereo",
      "stick",
      "still",
      "sting",
      "stock",
      "stomach",
      "stone",
      "stool",
      "story",
      "stove",
      "strategy",
      "street",
      "strike",
      "strong",
      "struggle",
      "student",
      "stuff",
      "stumble",
      "style",
      "subject",
      "submit",
      "subway",
      "success",
      "such",
      "sudden",
      "suffer",
      "sugar",
      "suggest",
      "suit",
      "summer",
      "sun",
      "sunny",
      "sunset",
      "super",
      "supply",
      "supreme",
      "sure",
      "surface",
      "surge",
      "surprise",
      "surround",
      "survey",
      "suspect",
      "sustain",
      "swallow",
      "swamp",
      "swap",
      "swarm",
      "swear",
      "sweet",
      "swift",
      "swim",
      "swing",
      "switch",
      "sword",
      "symbol",
      "symptom",
      "syrup",
      "system",
      "table",
      "tackle",
      "tag",
      "tail",
      "talent",
      "talk",
      "tank",
      "tape",
      "target",
      "task",
      "taste",
      "tattoo",
      "taxi",
      "teach",
      "team",
      "tell",
      "ten",
      "tenant",
      "tennis",
      "tent",
      "term",
      "test",
      "text",
      "thank",
      "that",
      "theme",
      "then",
      "theory",
      "there",
      "they",
      "thing",
      "this",
      "thought",
      "three",
      "thrive",
      "throw",
      "thumb",
      "thunder",
      "ticket",
      "tide",
      "tiger",
      "tilt",
      "timber",
      "time",
      "tiny",
      "tip",
      "tired",
      "tissue",
      "title",
      "toast",
      "tobacco",
      "today",
      "toddler",
      "toe",
      "together",
      "toilet",
      "token",
      "tomato",
      "tomorrow",
      "tone",
      "tongue",
      "tonight",
      "tool",
      "tooth",
      "top",
      "topic",
      "topple",
      "torch",
      "tornado",
      "tortoise",
      "toss",
      "total",
      "tourist",
      "toward",
      "tower",
      "town",
      "toy",
      "track",
      "trade",
      "traffic",
      "tragic",
      "train",
      "transfer",
      "trap",
      "trash",
      "travel",
      "tray",
      "treat",
      "tree",
      "trend",
      "trial",
      "tribe",
      "trick",
      "trigger",
      "trim",
      "trip",
      "trophy",
      "trouble",
      "truck",
      "true",
      "truly",
      "trumpet",
      "trust",
      "truth",
      "try",
      "tube",
      "tuition",
      "tumble",
      "tuna",
      "tunnel",
      "turkey",
      "turn",
      "turtle",
      "twelve",
      "twenty",
      "twice",
      "twin",
      "twist",
      "two",
      "type",
      "typical",
      "ugly",
      "umbrella",
      "unable",
      "unaware",
      "uncle",
      "uncover",
      "under",
      "undo",
      "unfair",
      "unfold",
      "unhappy",
      "uniform",
      "unique",
      "unit",
      "universe",
      "unknown",
      "unlock",
      "until",
      "unusual",
      "unveil",
      "update",
      "upgrade",
      "uphold",
      "upon",
      "upper",
      "upset",
      "urban",
      "urge",
      "usage",
      "use",
      "used",
      "useful",
      "useless",
      "usual",
      "utility",
      "vacant",
      "vacuum",
      "vague",
      "valid",
      "valley",
      "valve",
      "van",
      "vanish",
      "vapor",
      "various",
      "vast",
      "vault",
      "vehicle",
      "velvet",
      "vendor",
      "venture",
      "venue",
      "verb",
      "verify",
      "version",
      "very",
      "vessel",
      "veteran",
      "viable",
      "vibrant",
      "vicious",
      "victory",
      "video",
      "view",
      "village",
      "vintage",
      "violin",
      "virtual",
      "virus",
      "visa",
      "visit",
      "visual",
      "vital",
      "vivid",
      "vocal",
      "voice",
      "void",
      "volcano",
      "volume",
      "vote",
      "voyage",
      "wage",
      "wagon",
      "wait",
      "walk",
      "wall",
      "walnut",
      "want",
      "warfare",
      "warm",
      "warrior",
      "wash",
      "wasp",
      "waste",
      "water",
      "wave",
      "way",
      "wealth",
      "weapon",
      "wear",
      "weasel",
      "weather",
      "web",
      "wedding",
      "weekend",
      "weird",
      "welcome",
      "west",
      "wet",
      "whale",
      "what",
      "wheat",
      "wheel",
      "when",
      "where",
      "whip",
      "whisper",
      "wide",
      "width",
      "wife",
      "wild",
      "will",
      "win",
      "window",
      "wine",
      "wing",
      "wink",
      "winner",
      "winter",
      "wire",
      "wisdom",
      "wise",
      "wish",
      "witness",
      "wolf",
      "woman",
      "wonder",
      "wood",
      "wool",
      "word",
      "work",
      "world",
      "worry",
      "worth",
      "wrap",
      "wreck",
      "wrestle",
      "wrist",
      "write",
      "wrong",
      "yard",
      "year",
      "yellow",
      "you",
      "young",
      "youth",
      "zebra",
      "zero",
      "zone",
      "zoo"
    ];
  }
});

// node_modules/bip39/src/_wordlists.js
var require_wordlists = __commonJS({
  "node_modules/bip39/src/_wordlists.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    var wordlists = {};
    exports.wordlists = wordlists;
    var _default;
    exports._default = _default;
    try {
      exports._default = _default = require_czech();
      wordlists.czech = _default;
    } catch (err2) {
    }
    try {
      exports._default = _default = require_chinese_simplified();
      wordlists.chinese_simplified = _default;
    } catch (err2) {
    }
    try {
      exports._default = _default = require_chinese_traditional();
      wordlists.chinese_traditional = _default;
    } catch (err2) {
    }
    try {
      exports._default = _default = require_korean();
      wordlists.korean = _default;
    } catch (err2) {
    }
    try {
      exports._default = _default = require_french();
      wordlists.french = _default;
    } catch (err2) {
    }
    try {
      exports._default = _default = require_italian();
      wordlists.italian = _default;
    } catch (err2) {
    }
    try {
      exports._default = _default = require_spanish();
      wordlists.spanish = _default;
    } catch (err2) {
    }
    try {
      exports._default = _default = require_japanese();
      wordlists.japanese = _default;
      wordlists.JA = _default;
    } catch (err2) {
    }
    try {
      exports._default = _default = require_portuguese();
      wordlists.portuguese = _default;
    } catch (err2) {
    }
    try {
      exports._default = _default = require_english();
      wordlists.english = _default;
      wordlists.EN = _default;
    } catch (err2) {
    }
  }
});

// node_modules/bip39/src/index.js
var require_src = __commonJS({
  "node_modules/bip39/src/index.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    var sha256_1 = require_sha256();
    var sha512_1 = require_sha512();
    var pbkdf2_1 = require_pbkdf2();
    var utils_1 = require_utils();
    var _wordlists_1 = require_wordlists();
    var DEFAULT_WORDLIST = _wordlists_1._default;
    var INVALID_MNEMONIC = "Invalid mnemonic";
    var INVALID_ENTROPY = "Invalid entropy";
    var INVALID_CHECKSUM = "Invalid mnemonic checksum";
    var WORDLIST_REQUIRED = "A wordlist is required but a default could not be found.\nPlease pass a 2048 word array explicitly.";
    function normalize2(str2) {
      return (str2 || "").normalize("NFKD");
    }
    function lpad(str2, padString, length) {
      while (str2.length < length) {
        str2 = padString + str2;
      }
      return str2;
    }
    function binaryToByte(bin) {
      return parseInt(bin, 2);
    }
    function bytesToBinary(bytes2) {
      return bytes2.map((x) => lpad(x.toString(2), "0", 8)).join("");
    }
    function deriveChecksumBits(entropyBuffer) {
      const ENT = entropyBuffer.length * 8;
      const CS = ENT / 32;
      const hash2 = sha256_1.sha256(Uint8Array.from(entropyBuffer));
      return bytesToBinary(Array.from(hash2)).slice(0, CS);
    }
    function salt(password) {
      return "mnemonic" + (password || "");
    }
    function mnemonicToSeedSync(mnemonic, password) {
      const mnemonicBuffer = Uint8Array.from(Buffer.from(normalize2(mnemonic), "utf8"));
      const saltBuffer = Uint8Array.from(Buffer.from(salt(normalize2(password)), "utf8"));
      const res = pbkdf2_1.pbkdf2(sha512_1.sha512, mnemonicBuffer, saltBuffer, {
        c: 2048,
        dkLen: 64
      });
      return Buffer.from(res);
    }
    exports.mnemonicToSeedSync = mnemonicToSeedSync;
    function mnemonicToSeed(mnemonic, password) {
      const mnemonicBuffer = Uint8Array.from(Buffer.from(normalize2(mnemonic), "utf8"));
      const saltBuffer = Uint8Array.from(Buffer.from(salt(normalize2(password)), "utf8"));
      return pbkdf2_1.pbkdf2Async(sha512_1.sha512, mnemonicBuffer, saltBuffer, {
        c: 2048,
        dkLen: 64
      }).then((res) => Buffer.from(res));
    }
    exports.mnemonicToSeed = mnemonicToSeed;
    function mnemonicToEntropy(mnemonic, wordlist) {
      wordlist = wordlist || DEFAULT_WORDLIST;
      if (!wordlist) {
        throw new Error(WORDLIST_REQUIRED);
      }
      const words = normalize2(mnemonic).split(" ");
      if (words.length % 3 !== 0) {
        throw new Error(INVALID_MNEMONIC);
      }
      const bits = words.map((word) => {
        const index = wordlist.indexOf(word);
        if (index === -1) {
          throw new Error(INVALID_MNEMONIC);
        }
        return lpad(index.toString(2), "0", 11);
      }).join("");
      const dividerIndex = Math.floor(bits.length / 33) * 32;
      const entropyBits = bits.slice(0, dividerIndex);
      const checksumBits = bits.slice(dividerIndex);
      const entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte);
      if (entropyBytes.length < 16) {
        throw new Error(INVALID_ENTROPY);
      }
      if (entropyBytes.length > 32) {
        throw new Error(INVALID_ENTROPY);
      }
      if (entropyBytes.length % 4 !== 0) {
        throw new Error(INVALID_ENTROPY);
      }
      const entropy = Buffer.from(entropyBytes);
      const newChecksum = deriveChecksumBits(entropy);
      if (newChecksum !== checksumBits) {
        throw new Error(INVALID_CHECKSUM);
      }
      return entropy.toString("hex");
    }
    exports.mnemonicToEntropy = mnemonicToEntropy;
    function entropyToMnemonic(entropy, wordlist) {
      if (!Buffer.isBuffer(entropy)) {
        entropy = Buffer.from(entropy, "hex");
      }
      wordlist = wordlist || DEFAULT_WORDLIST;
      if (!wordlist) {
        throw new Error(WORDLIST_REQUIRED);
      }
      if (entropy.length < 16) {
        throw new TypeError(INVALID_ENTROPY);
      }
      if (entropy.length > 32) {
        throw new TypeError(INVALID_ENTROPY);
      }
      if (entropy.length % 4 !== 0) {
        throw new TypeError(INVALID_ENTROPY);
      }
      const entropyBits = bytesToBinary(Array.from(entropy));
      const checksumBits = deriveChecksumBits(entropy);
      const bits = entropyBits + checksumBits;
      const chunks = bits.match(/(.{1,11})/g);
      const words = chunks.map((binary) => {
        const index = binaryToByte(binary);
        return wordlist[index];
      });
      return wordlist[0] === "\u3042\u3044\u3053\u304F\u3057\u3093" ? words.join("\u3000") : words.join(" ");
    }
    exports.entropyToMnemonic = entropyToMnemonic;
    function generateMnemonic(strength, rng, wordlist) {
      strength = strength || 128;
      if (strength % 32 !== 0) {
        throw new TypeError(INVALID_ENTROPY);
      }
      rng = rng || ((size) => Buffer.from(utils_1.randomBytes(size)));
      return entropyToMnemonic(rng(strength / 8), wordlist);
    }
    exports.generateMnemonic = generateMnemonic;
    function validateMnemonic(mnemonic, wordlist) {
      try {
        mnemonicToEntropy(mnemonic, wordlist);
      } catch (e) {
        return false;
      }
      return true;
    }
    exports.validateMnemonic = validateMnemonic;
    function setDefaultWordlist(language) {
      const result = _wordlists_1.wordlists[language];
      if (result) {
        DEFAULT_WORDLIST = result;
      } else {
        throw new Error('Could not find wordlist for language "' + language + '"');
      }
    }
    exports.setDefaultWordlist = setDefaultWordlist;
    function getDefaultWordlist() {
      if (!DEFAULT_WORDLIST) {
        throw new Error("No Default Wordlist set");
      }
      return Object.keys(_wordlists_1.wordlists).filter((lang) => {
        if (lang === "JA" || lang === "EN") {
          return false;
        }
        return _wordlists_1.wordlists[lang].every((word, index) => word === DEFAULT_WORDLIST[index]);
      })[0];
    }
    exports.getDefaultWordlist = getDefaultWordlist;
    var _wordlists_2 = require_wordlists();
    exports.wordlists = _wordlists_2.wordlists;
  }
});

// node_modules/bip32/node_modules/@noble/hashes/crypto.js
var require_crypto2 = __commonJS({
  "node_modules/bip32/node_modules/@noble/hashes/crypto.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.crypto = void 0;
    exports.crypto = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0;
  }
});

// node_modules/bip32/node_modules/@noble/hashes/utils.js
var require_utils2 = __commonJS({
  "node_modules/bip32/node_modules/@noble/hashes/utils.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.wrapXOFConstructorWithOpts = exports.wrapConstructorWithOpts = exports.wrapConstructor = exports.Hash = exports.nextTick = exports.swap32IfBE = exports.byteSwapIfBE = exports.swap8IfBE = exports.isLE = void 0;
    exports.isBytes = isBytes4;
    exports.anumber = anumber3;
    exports.abytes = abytes4;
    exports.ahash = ahash2;
    exports.aexists = aexists2;
    exports.aoutput = aoutput2;
    exports.u8 = u8;
    exports.u32 = u322;
    exports.clean = clean2;
    exports.createView = createView2;
    exports.rotr = rotr2;
    exports.rotl = rotl;
    exports.byteSwap = byteSwap2;
    exports.byteSwap32 = byteSwap322;
    exports.bytesToHex = bytesToHex2;
    exports.hexToBytes = hexToBytes2;
    exports.asyncLoop = asyncLoop;
    exports.utf8ToBytes = utf8ToBytes;
    exports.bytesToUtf8 = bytesToUtf8;
    exports.toBytes = toBytes;
    exports.kdfInputToBytes = kdfInputToBytes;
    exports.concatBytes = concatBytes2;
    exports.checkOpts = checkOpts;
    exports.createHasher = createHasher2;
    exports.createOptHasher = createOptHasher;
    exports.createXOFer = createXOFer;
    exports.randomBytes = randomBytes2;
    var crypto_1 = require_crypto2();
    function isBytes4(a) {
      return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
    }
    function anumber3(n) {
      if (!Number.isSafeInteger(n) || n < 0)
        throw new Error("positive integer expected, got " + n);
    }
    function abytes4(b, ...lengths2) {
      if (!isBytes4(b))
        throw new Error("Uint8Array expected");
      if (lengths2.length > 0 && !lengths2.includes(b.length))
        throw new Error("Uint8Array expected of length " + lengths2 + ", got length=" + b.length);
    }
    function ahash2(h) {
      if (typeof h !== "function" || typeof h.create !== "function")
        throw new Error("Hash should be wrapped by utils.createHasher");
      anumber3(h.outputLen);
      anumber3(h.blockLen);
    }
    function aexists2(instance, checkFinished = true) {
      if (instance.destroyed)
        throw new Error("Hash instance has been destroyed");
      if (checkFinished && instance.finished)
        throw new Error("Hash#digest() has already been called");
    }
    function aoutput2(out, instance) {
      abytes4(out);
      const min = instance.outputLen;
      if (out.length < min) {
        throw new Error("digestInto() expects output buffer of length at least " + min);
      }
    }
    function u8(arr) {
      return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
    }
    function u322(arr) {
      return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
    }
    function clean2(...arrays) {
      for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
      }
    }
    function createView2(arr) {
      return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    }
    function rotr2(word, shift) {
      return word << 32 - shift | word >>> shift;
    }
    function rotl(word, shift) {
      return word << shift | word >>> 32 - shift >>> 0;
    }
    exports.isLE = (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
    function byteSwap2(word) {
      return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
    }
    exports.swap8IfBE = exports.isLE ? (n) => n : (n) => byteSwap2(n);
    exports.byteSwapIfBE = exports.swap8IfBE;
    function byteSwap322(arr) {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = byteSwap2(arr[i]);
      }
      return arr;
    }
    exports.swap32IfBE = exports.isLE ? (u) => u : byteSwap322;
    var hasHexBuiltin2 = /* @__PURE__ */ (() => (
      // @ts-ignore
      typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
    ))();
    var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
    function bytesToHex2(bytes2) {
      abytes4(bytes2);
      if (hasHexBuiltin2)
        return bytes2.toHex();
      let hex2 = "";
      for (let i = 0; i < bytes2.length; i++) {
        hex2 += hexes[bytes2[i]];
      }
      return hex2;
    }
    var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
    function asciiToBase16(ch) {
      if (ch >= asciis._0 && ch <= asciis._9)
        return ch - asciis._0;
      if (ch >= asciis.A && ch <= asciis.F)
        return ch - (asciis.A - 10);
      if (ch >= asciis.a && ch <= asciis.f)
        return ch - (asciis.a - 10);
      return;
    }
    function hexToBytes2(hex2) {
      if (typeof hex2 !== "string")
        throw new Error("hex string expected, got " + typeof hex2);
      if (hasHexBuiltin2)
        return Uint8Array.fromHex(hex2);
      const hl = hex2.length;
      const al = hl / 2;
      if (hl % 2)
        throw new Error("hex string expected, got unpadded hex of length " + hl);
      const array = new Uint8Array(al);
      for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex2.charCodeAt(hi));
        const n2 = asciiToBase16(hex2.charCodeAt(hi + 1));
        if (n1 === void 0 || n2 === void 0) {
          const char = hex2[hi] + hex2[hi + 1];
          throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2;
      }
      return array;
    }
    var nextTick = async () => {
    };
    exports.nextTick = nextTick;
    async function asyncLoop(iters, tick, cb) {
      let ts = Date.now();
      for (let i = 0; i < iters; i++) {
        cb(i);
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick)
          continue;
        await (0, exports.nextTick)();
        ts += diff;
      }
    }
    function utf8ToBytes(str2) {
      if (typeof str2 !== "string")
        throw new Error("string expected");
      return new Uint8Array(new TextEncoder().encode(str2));
    }
    function bytesToUtf8(bytes2) {
      return new TextDecoder().decode(bytes2);
    }
    function toBytes(data) {
      if (typeof data === "string")
        data = utf8ToBytes(data);
      abytes4(data);
      return data;
    }
    function kdfInputToBytes(data) {
      if (typeof data === "string")
        data = utf8ToBytes(data);
      abytes4(data);
      return data;
    }
    function concatBytes2(...arrays) {
      let sum = 0;
      for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        abytes4(a);
        sum += a.length;
      }
      const res = new Uint8Array(sum);
      for (let i = 0, pad = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
      }
      return res;
    }
    function checkOpts(defaults, opts) {
      if (opts !== void 0 && {}.toString.call(opts) !== "[object Object]")
        throw new Error("options should be object or undefined");
      const merged = Object.assign(defaults, opts);
      return merged;
    }
    var Hash = class {
    };
    exports.Hash = Hash;
    function createHasher2(hashCons) {
      const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
      const tmp = hashCons();
      hashC.outputLen = tmp.outputLen;
      hashC.blockLen = tmp.blockLen;
      hashC.create = () => hashCons();
      return hashC;
    }
    function createOptHasher(hashCons) {
      const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
      const tmp = hashCons({});
      hashC.outputLen = tmp.outputLen;
      hashC.blockLen = tmp.blockLen;
      hashC.create = (opts) => hashCons(opts);
      return hashC;
    }
    function createXOFer(hashCons) {
      const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
      const tmp = hashCons({});
      hashC.outputLen = tmp.outputLen;
      hashC.blockLen = tmp.blockLen;
      hashC.create = (opts) => hashCons(opts);
      return hashC;
    }
    exports.wrapConstructor = createHasher2;
    exports.wrapConstructorWithOpts = createOptHasher;
    exports.wrapXOFConstructorWithOpts = createXOFer;
    function randomBytes2(bytesLength = 32) {
      if (crypto_1.crypto && typeof crypto_1.crypto.getRandomValues === "function") {
        return crypto_1.crypto.getRandomValues(new Uint8Array(bytesLength));
      }
      if (crypto_1.crypto && typeof crypto_1.crypto.randomBytes === "function") {
        return Uint8Array.from(crypto_1.crypto.randomBytes(bytesLength));
      }
      throw new Error("crypto.getRandomValues must be defined");
    }
  }
});

// node_modules/bip32/node_modules/@noble/hashes/hmac.js
var require_hmac2 = __commonJS({
  "node_modules/bip32/node_modules/@noble/hashes/hmac.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.hmac = exports.HMAC = void 0;
    var utils_ts_1 = require_utils2();
    var HMAC = class extends utils_ts_1.Hash {
      constructor(hash2, _key) {
        super();
        this.finished = false;
        this.destroyed = false;
        (0, utils_ts_1.ahash)(hash2);
        const key = (0, utils_ts_1.toBytes)(_key);
        this.iHash = hash2.create();
        if (typeof this.iHash.update !== "function")
          throw new Error("Expected instance of class which extends utils.Hash");
        this.blockLen = this.iHash.blockLen;
        this.outputLen = this.iHash.outputLen;
        const blockLen = this.blockLen;
        const pad = new Uint8Array(blockLen);
        pad.set(key.length > blockLen ? hash2.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
          pad[i] ^= 54;
        this.iHash.update(pad);
        this.oHash = hash2.create();
        for (let i = 0; i < pad.length; i++)
          pad[i] ^= 54 ^ 92;
        this.oHash.update(pad);
        (0, utils_ts_1.clean)(pad);
      }
      update(buf) {
        (0, utils_ts_1.aexists)(this);
        this.iHash.update(buf);
        return this;
      }
      digestInto(out) {
        (0, utils_ts_1.aexists)(this);
        (0, utils_ts_1.abytes)(out, this.outputLen);
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
      }
      digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
      }
      _cloneInto(to) {
        to || (to = Object.create(Object.getPrototypeOf(this), {}));
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
      }
      clone() {
        return this._cloneInto();
      }
      destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
      }
    };
    exports.HMAC = HMAC;
    var hmac2 = (hash2, key, message) => new HMAC(hash2, key).update(message).digest();
    exports.hmac = hmac2;
    exports.hmac.create = (hash2, key) => new HMAC(hash2, key);
  }
});

// node_modules/bip32/node_modules/@noble/hashes/_md.js
var require_md2 = __commonJS({
  "node_modules/bip32/node_modules/@noble/hashes/_md.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.SHA512_IV = exports.SHA384_IV = exports.SHA224_IV = exports.SHA256_IV = exports.HashMD = void 0;
    exports.setBigUint64 = setBigUint64;
    exports.Chi = Chi2;
    exports.Maj = Maj2;
    var utils_ts_1 = require_utils2();
    function setBigUint64(view, byteOffset, value, isLE2) {
      if (typeof view.setBigUint64 === "function")
        return view.setBigUint64(byteOffset, value, isLE2);
      const _32n2 = BigInt(32);
      const _u32_max = BigInt(4294967295);
      const wh = Number(value >> _32n2 & _u32_max);
      const wl = Number(value & _u32_max);
      const h = isLE2 ? 4 : 0;
      const l = isLE2 ? 0 : 4;
      view.setUint32(byteOffset + h, wh, isLE2);
      view.setUint32(byteOffset + l, wl, isLE2);
    }
    function Chi2(a, b, c) {
      return a & b ^ ~a & c;
    }
    function Maj2(a, b, c) {
      return a & b ^ a & c ^ b & c;
    }
    var HashMD2 = class extends utils_ts_1.Hash {
      constructor(blockLen, outputLen, padOffset, isLE2) {
        super();
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE2;
        this.buffer = new Uint8Array(blockLen);
        this.view = (0, utils_ts_1.createView)(this.buffer);
      }
      update(data) {
        (0, utils_ts_1.aexists)(this);
        data = (0, utils_ts_1.toBytes)(data);
        (0, utils_ts_1.abytes)(data);
        const { view, buffer, blockLen } = this;
        const len = data.length;
        for (let pos = 0; pos < len; ) {
          const take = Math.min(blockLen - this.pos, len - pos);
          if (take === blockLen) {
            const dataView = (0, utils_ts_1.createView)(data);
            for (; blockLen <= len - pos; pos += blockLen)
              this.process(dataView, pos);
            continue;
          }
          buffer.set(data.subarray(pos, pos + take), this.pos);
          this.pos += take;
          pos += take;
          if (this.pos === blockLen) {
            this.process(view, 0);
            this.pos = 0;
          }
        }
        this.length += data.length;
        this.roundClean();
        return this;
      }
      digestInto(out) {
        (0, utils_ts_1.aexists)(this);
        (0, utils_ts_1.aoutput)(out, this);
        this.finished = true;
        const { buffer, view, blockLen, isLE: isLE2 } = this;
        let { pos } = this;
        buffer[pos++] = 128;
        (0, utils_ts_1.clean)(this.buffer.subarray(pos));
        if (this.padOffset > blockLen - pos) {
          this.process(view, 0);
          pos = 0;
        }
        for (let i = pos; i < blockLen; i++)
          buffer[i] = 0;
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
        this.process(view, 0);
        const oview = (0, utils_ts_1.createView)(out);
        const len = this.outputLen;
        if (len % 4)
          throw new Error("_sha2: outputLen should be aligned to 32bit");
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
          throw new Error("_sha2: outputLen bigger than state");
        for (let i = 0; i < outLen; i++)
          oview.setUint32(4 * i, state[i], isLE2);
      }
      digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
      }
      _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.destroyed = destroyed;
        to.finished = finished;
        to.length = length;
        to.pos = pos;
        if (length % blockLen)
          to.buffer.set(buffer);
        return to;
      }
      clone() {
        return this._cloneInto();
      }
    };
    exports.HashMD = HashMD2;
    exports.SHA256_IV = Uint32Array.from([
      1779033703,
      3144134277,
      1013904242,
      2773480762,
      1359893119,
      2600822924,
      528734635,
      1541459225
    ]);
    exports.SHA224_IV = Uint32Array.from([
      3238371032,
      914150663,
      812702999,
      4144912697,
      4290775857,
      1750603025,
      1694076839,
      3204075428
    ]);
    exports.SHA384_IV = Uint32Array.from([
      3418070365,
      3238371032,
      1654270250,
      914150663,
      2438529370,
      812702999,
      355462360,
      4144912697,
      1731405415,
      4290775857,
      2394180231,
      1750603025,
      3675008525,
      1694076839,
      1203062813,
      3204075428
    ]);
    exports.SHA512_IV = Uint32Array.from([
      1779033703,
      4089235720,
      3144134277,
      2227873595,
      1013904242,
      4271175723,
      2773480762,
      1595750129,
      1359893119,
      2917565137,
      2600822924,
      725511199,
      528734635,
      4215389547,
      1541459225,
      327033209
    ]);
  }
});

// node_modules/bip32/node_modules/@noble/hashes/legacy.js
var require_legacy = __commonJS({
  "node_modules/bip32/node_modules/@noble/hashes/legacy.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.ripemd160 = exports.RIPEMD160 = exports.md5 = exports.MD5 = exports.sha1 = exports.SHA1 = void 0;
    var _md_ts_1 = require_md2();
    var utils_ts_1 = require_utils2();
    var SHA1_IV = /* @__PURE__ */ Uint32Array.from([
      1732584193,
      4023233417,
      2562383102,
      271733878,
      3285377520
    ]);
    var SHA1_W = /* @__PURE__ */ new Uint32Array(80);
    var SHA1 = class extends _md_ts_1.HashMD {
      constructor() {
        super(64, 20, 8, false);
        this.A = SHA1_IV[0] | 0;
        this.B = SHA1_IV[1] | 0;
        this.C = SHA1_IV[2] | 0;
        this.D = SHA1_IV[3] | 0;
        this.E = SHA1_IV[4] | 0;
      }
      get() {
        const { A, B, C: C2, D, E } = this;
        return [A, B, C2, D, E];
      }
      set(A, B, C2, D, E) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C2 | 0;
        this.D = D | 0;
        this.E = E | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
          SHA1_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 80; i++)
          SHA1_W[i] = (0, utils_ts_1.rotl)(SHA1_W[i - 3] ^ SHA1_W[i - 8] ^ SHA1_W[i - 14] ^ SHA1_W[i - 16], 1);
        let { A, B, C: C2, D, E } = this;
        for (let i = 0; i < 80; i++) {
          let F, K2;
          if (i < 20) {
            F = (0, _md_ts_1.Chi)(B, C2, D);
            K2 = 1518500249;
          } else if (i < 40) {
            F = B ^ C2 ^ D;
            K2 = 1859775393;
          } else if (i < 60) {
            F = (0, _md_ts_1.Maj)(B, C2, D);
            K2 = 2400959708;
          } else {
            F = B ^ C2 ^ D;
            K2 = 3395469782;
          }
          const T = (0, utils_ts_1.rotl)(A, 5) + F + E + K2 + SHA1_W[i] | 0;
          E = D;
          D = C2;
          C2 = (0, utils_ts_1.rotl)(B, 30);
          B = A;
          A = T;
        }
        A = A + this.A | 0;
        B = B + this.B | 0;
        C2 = C2 + this.C | 0;
        D = D + this.D | 0;
        E = E + this.E | 0;
        this.set(A, B, C2, D, E);
      }
      roundClean() {
        (0, utils_ts_1.clean)(SHA1_W);
      }
      destroy() {
        this.set(0, 0, 0, 0, 0);
        (0, utils_ts_1.clean)(this.buffer);
      }
    };
    exports.SHA1 = SHA1;
    exports.sha1 = (0, utils_ts_1.createHasher)(() => new SHA1());
    var p32 = /* @__PURE__ */ Math.pow(2, 32);
    var K = /* @__PURE__ */ Array.from({ length: 64 }, (_, i) => Math.floor(p32 * Math.abs(Math.sin(i + 1))));
    var MD5_IV = /* @__PURE__ */ SHA1_IV.slice(0, 4);
    var MD5_W = /* @__PURE__ */ new Uint32Array(16);
    var MD5 = class extends _md_ts_1.HashMD {
      constructor() {
        super(64, 16, 8, true);
        this.A = MD5_IV[0] | 0;
        this.B = MD5_IV[1] | 0;
        this.C = MD5_IV[2] | 0;
        this.D = MD5_IV[3] | 0;
      }
      get() {
        const { A, B, C: C2, D } = this;
        return [A, B, C2, D];
      }
      set(A, B, C2, D) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C2 | 0;
        this.D = D | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
          MD5_W[i] = view.getUint32(offset, true);
        let { A, B, C: C2, D } = this;
        for (let i = 0; i < 64; i++) {
          let F, g, s;
          if (i < 16) {
            F = (0, _md_ts_1.Chi)(B, C2, D);
            g = i;
            s = [7, 12, 17, 22];
          } else if (i < 32) {
            F = (0, _md_ts_1.Chi)(D, B, C2);
            g = (5 * i + 1) % 16;
            s = [5, 9, 14, 20];
          } else if (i < 48) {
            F = B ^ C2 ^ D;
            g = (3 * i + 5) % 16;
            s = [4, 11, 16, 23];
          } else {
            F = C2 ^ (B | ~D);
            g = 7 * i % 16;
            s = [6, 10, 15, 21];
          }
          F = F + A + K[i] + MD5_W[g];
          A = D;
          D = C2;
          C2 = B;
          B = B + (0, utils_ts_1.rotl)(F, s[i % 4]);
        }
        A = A + this.A | 0;
        B = B + this.B | 0;
        C2 = C2 + this.C | 0;
        D = D + this.D | 0;
        this.set(A, B, C2, D);
      }
      roundClean() {
        (0, utils_ts_1.clean)(MD5_W);
      }
      destroy() {
        this.set(0, 0, 0, 0);
        (0, utils_ts_1.clean)(this.buffer);
      }
    };
    exports.MD5 = MD5;
    exports.md5 = (0, utils_ts_1.createHasher)(() => new MD5());
    var Rho160 = /* @__PURE__ */ Uint8Array.from([
      7,
      4,
      13,
      1,
      10,
      6,
      15,
      3,
      12,
      0,
      9,
      5,
      2,
      14,
      11,
      8
    ]);
    var Id160 = /* @__PURE__ */ (() => Uint8Array.from(new Array(16).fill(0).map((_, i) => i)))();
    var Pi160 = /* @__PURE__ */ (() => Id160.map((i) => (9 * i + 5) % 16))();
    var idxLR = /* @__PURE__ */ (() => {
      const L3 = [Id160];
      const R = [Pi160];
      const res = [L3, R];
      for (let i = 0; i < 4; i++)
        for (let j of res)
          j.push(j[i].map((k) => Rho160[k]));
      return res;
    })();
    var idxL = /* @__PURE__ */ (() => idxLR[0])();
    var idxR = /* @__PURE__ */ (() => idxLR[1])();
    var shifts160 = /* @__PURE__ */ [
      [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
      [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
      [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
      [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
      [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]
    ].map((i) => Uint8Array.from(i));
    var shiftsL160 = /* @__PURE__ */ idxL.map((idx, i) => idx.map((j) => shifts160[i][j]));
    var shiftsR160 = /* @__PURE__ */ idxR.map((idx, i) => idx.map((j) => shifts160[i][j]));
    var Kl160 = /* @__PURE__ */ Uint32Array.from([
      0,
      1518500249,
      1859775393,
      2400959708,
      2840853838
    ]);
    var Kr160 = /* @__PURE__ */ Uint32Array.from([
      1352829926,
      1548603684,
      1836072691,
      2053994217,
      0
    ]);
    function ripemd_f(group, x, y, z) {
      if (group === 0)
        return x ^ y ^ z;
      if (group === 1)
        return x & y | ~x & z;
      if (group === 2)
        return (x | ~y) ^ z;
      if (group === 3)
        return x & z | y & ~z;
      return x ^ (y | ~z);
    }
    var BUF_160 = /* @__PURE__ */ new Uint32Array(16);
    var RIPEMD160 = class extends _md_ts_1.HashMD {
      constructor() {
        super(64, 20, 8, true);
        this.h0 = 1732584193 | 0;
        this.h1 = 4023233417 | 0;
        this.h2 = 2562383102 | 0;
        this.h3 = 271733878 | 0;
        this.h4 = 3285377520 | 0;
      }
      get() {
        const { h0, h1, h2, h3, h4 } = this;
        return [h0, h1, h2, h3, h4];
      }
      set(h0, h1, h2, h3, h4) {
        this.h0 = h0 | 0;
        this.h1 = h1 | 0;
        this.h2 = h2 | 0;
        this.h3 = h3 | 0;
        this.h4 = h4 | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
          BUF_160[i] = view.getUint32(offset, true);
        let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr2 = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
        for (let group = 0; group < 5; group++) {
          const rGroup = 4 - group;
          const hbl = Kl160[group], hbr = Kr160[group];
          const rl = idxL[group], rr = idxR[group];
          const sl = shiftsL160[group], sr = shiftsR160[group];
          for (let i = 0; i < 16; i++) {
            const tl = (0, utils_ts_1.rotl)(al + ripemd_f(group, bl, cl, dl) + BUF_160[rl[i]] + hbl, sl[i]) + el | 0;
            al = el, el = dl, dl = (0, utils_ts_1.rotl)(cl, 10) | 0, cl = bl, bl = tl;
          }
          for (let i = 0; i < 16; i++) {
            const tr = (0, utils_ts_1.rotl)(ar + ripemd_f(rGroup, br, cr2, dr) + BUF_160[rr[i]] + hbr, sr[i]) + er | 0;
            ar = er, er = dr, dr = (0, utils_ts_1.rotl)(cr2, 10) | 0, cr2 = br, br = tr;
          }
        }
        this.set(this.h1 + cl + dr | 0, this.h2 + dl + er | 0, this.h3 + el + ar | 0, this.h4 + al + br | 0, this.h0 + bl + cr2 | 0);
      }
      roundClean() {
        (0, utils_ts_1.clean)(BUF_160);
      }
      destroy() {
        this.destroyed = true;
        (0, utils_ts_1.clean)(this.buffer);
        this.set(0, 0, 0, 0, 0);
      }
    };
    exports.RIPEMD160 = RIPEMD160;
    exports.ripemd160 = (0, utils_ts_1.createHasher)(() => new RIPEMD160());
  }
});

// node_modules/bip32/node_modules/@noble/hashes/ripemd160.js
var require_ripemd160 = __commonJS({
  "node_modules/bip32/node_modules/@noble/hashes/ripemd160.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.ripemd160 = exports.RIPEMD160 = void 0;
    var legacy_ts_1 = require_legacy();
    exports.RIPEMD160 = legacy_ts_1.RIPEMD160;
    exports.ripemd160 = legacy_ts_1.ripemd160;
  }
});

// node_modules/bip32/node_modules/@noble/hashes/_u64.js
var require_u642 = __commonJS({
  "node_modules/bip32/node_modules/@noble/hashes/_u64.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.toBig = exports.shrSL = exports.shrSH = exports.rotrSL = exports.rotrSH = exports.rotrBL = exports.rotrBH = exports.rotr32L = exports.rotr32H = exports.rotlSL = exports.rotlSH = exports.rotlBL = exports.rotlBH = exports.add5L = exports.add5H = exports.add4L = exports.add4H = exports.add3L = exports.add3H = void 0;
    exports.add = add2;
    exports.fromBig = fromBig2;
    exports.split = split2;
    var U32_MASK642 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
    var _32n2 = /* @__PURE__ */ BigInt(32);
    function fromBig2(n, le = false) {
      if (le)
        return { h: Number(n & U32_MASK642), l: Number(n >> _32n2 & U32_MASK642) };
      return { h: Number(n >> _32n2 & U32_MASK642) | 0, l: Number(n & U32_MASK642) | 0 };
    }
    function split2(lst, le = false) {
      const len = lst.length;
      let Ah = new Uint32Array(len);
      let Al = new Uint32Array(len);
      for (let i = 0; i < len; i++) {
        const { h, l } = fromBig2(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
      }
      return [Ah, Al];
    }
    var toBig = (h, l) => BigInt(h >>> 0) << _32n2 | BigInt(l >>> 0);
    exports.toBig = toBig;
    var shrSH2 = (h, _l, s) => h >>> s;
    exports.shrSH = shrSH2;
    var shrSL2 = (h, l, s) => h << 32 - s | l >>> s;
    exports.shrSL = shrSL2;
    var rotrSH2 = (h, l, s) => h >>> s | l << 32 - s;
    exports.rotrSH = rotrSH2;
    var rotrSL2 = (h, l, s) => h << 32 - s | l >>> s;
    exports.rotrSL = rotrSL2;
    var rotrBH2 = (h, l, s) => h << 64 - s | l >>> s - 32;
    exports.rotrBH = rotrBH2;
    var rotrBL2 = (h, l, s) => h >>> s - 32 | l << 64 - s;
    exports.rotrBL = rotrBL2;
    var rotr32H = (_h, l) => l;
    exports.rotr32H = rotr32H;
    var rotr32L = (h, _l) => h;
    exports.rotr32L = rotr32L;
    var rotlSH2 = (h, l, s) => h << s | l >>> 32 - s;
    exports.rotlSH = rotlSH2;
    var rotlSL2 = (h, l, s) => l << s | h >>> 32 - s;
    exports.rotlSL = rotlSL2;
    var rotlBH2 = (h, l, s) => l << s - 32 | h >>> 64 - s;
    exports.rotlBH = rotlBH2;
    var rotlBL2 = (h, l, s) => h << s - 32 | l >>> 64 - s;
    exports.rotlBL = rotlBL2;
    function add2(Ah, Al, Bh, Bl) {
      const l = (Al >>> 0) + (Bl >>> 0);
      return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
    }
    var add3L2 = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
    exports.add3L = add3L2;
    var add3H2 = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
    exports.add3H = add3H2;
    var add4L2 = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
    exports.add4L = add4L2;
    var add4H2 = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
    exports.add4H = add4H2;
    var add5L2 = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
    exports.add5L = add5L2;
    var add5H2 = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
    exports.add5H = add5H2;
    var u64 = {
      fromBig: fromBig2,
      split: split2,
      toBig,
      shrSH: shrSH2,
      shrSL: shrSL2,
      rotrSH: rotrSH2,
      rotrSL: rotrSL2,
      rotrBH: rotrBH2,
      rotrBL: rotrBL2,
      rotr32H,
      rotr32L,
      rotlSH: rotlSH2,
      rotlSL: rotlSL2,
      rotlBH: rotlBH2,
      rotlBL: rotlBL2,
      add: add2,
      add3L: add3L2,
      add3H: add3H2,
      add4L: add4L2,
      add4H: add4H2,
      add5H: add5H2,
      add5L: add5L2
    };
    exports.default = u64;
  }
});

// node_modules/bip32/node_modules/@noble/hashes/sha2.js
var require_sha22 = __commonJS({
  "node_modules/bip32/node_modules/@noble/hashes/sha2.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.sha512_224 = exports.sha512_256 = exports.sha384 = exports.sha512 = exports.sha224 = exports.sha256 = exports.SHA512_256 = exports.SHA512_224 = exports.SHA384 = exports.SHA512 = exports.SHA224 = exports.SHA256 = void 0;
    var _md_ts_1 = require_md2();
    var u64 = require_u642();
    var utils_ts_1 = require_utils2();
    var SHA256_K2 = /* @__PURE__ */ Uint32Array.from([
      1116352408,
      1899447441,
      3049323471,
      3921009573,
      961987163,
      1508970993,
      2453635748,
      2870763221,
      3624381080,
      310598401,
      607225278,
      1426881987,
      1925078388,
      2162078206,
      2614888103,
      3248222580,
      3835390401,
      4022224774,
      264347078,
      604807628,
      770255983,
      1249150122,
      1555081692,
      1996064986,
      2554220882,
      2821834349,
      2952996808,
      3210313671,
      3336571891,
      3584528711,
      113926993,
      338241895,
      666307205,
      773529912,
      1294757372,
      1396182291,
      1695183700,
      1986661051,
      2177026350,
      2456956037,
      2730485921,
      2820302411,
      3259730800,
      3345764771,
      3516065817,
      3600352804,
      4094571909,
      275423344,
      430227734,
      506948616,
      659060556,
      883997877,
      958139571,
      1322822218,
      1537002063,
      1747873779,
      1955562222,
      2024104815,
      2227730452,
      2361852424,
      2428436474,
      2756734187,
      3204031479,
      3329325298
    ]);
    var SHA256_W2 = /* @__PURE__ */ new Uint32Array(64);
    var SHA256 = class extends _md_ts_1.HashMD {
      constructor(outputLen = 32) {
        super(64, outputLen, 8, false);
        this.A = _md_ts_1.SHA256_IV[0] | 0;
        this.B = _md_ts_1.SHA256_IV[1] | 0;
        this.C = _md_ts_1.SHA256_IV[2] | 0;
        this.D = _md_ts_1.SHA256_IV[3] | 0;
        this.E = _md_ts_1.SHA256_IV[4] | 0;
        this.F = _md_ts_1.SHA256_IV[5] | 0;
        this.G = _md_ts_1.SHA256_IV[6] | 0;
        this.H = _md_ts_1.SHA256_IV[7] | 0;
      }
      get() {
        const { A, B, C: C2, D, E, F, G: G2, H } = this;
        return [A, B, C2, D, E, F, G2, H];
      }
      // prettier-ignore
      set(A, B, C2, D, E, F, G2, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C2 | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G2 | 0;
        this.H = H | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
          SHA256_W2[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
          const W15 = SHA256_W2[i - 15];
          const W2 = SHA256_W2[i - 2];
          const s0 = (0, utils_ts_1.rotr)(W15, 7) ^ (0, utils_ts_1.rotr)(W15, 18) ^ W15 >>> 3;
          const s1 = (0, utils_ts_1.rotr)(W2, 17) ^ (0, utils_ts_1.rotr)(W2, 19) ^ W2 >>> 10;
          SHA256_W2[i] = s1 + SHA256_W2[i - 7] + s0 + SHA256_W2[i - 16] | 0;
        }
        let { A, B, C: C2, D, E, F, G: G2, H } = this;
        for (let i = 0; i < 64; i++) {
          const sigma1 = (0, utils_ts_1.rotr)(E, 6) ^ (0, utils_ts_1.rotr)(E, 11) ^ (0, utils_ts_1.rotr)(E, 25);
          const T1 = H + sigma1 + (0, _md_ts_1.Chi)(E, F, G2) + SHA256_K2[i] + SHA256_W2[i] | 0;
          const sigma0 = (0, utils_ts_1.rotr)(A, 2) ^ (0, utils_ts_1.rotr)(A, 13) ^ (0, utils_ts_1.rotr)(A, 22);
          const T2 = sigma0 + (0, _md_ts_1.Maj)(A, B, C2) | 0;
          H = G2;
          G2 = F;
          F = E;
          E = D + T1 | 0;
          D = C2;
          C2 = B;
          B = A;
          A = T1 + T2 | 0;
        }
        A = A + this.A | 0;
        B = B + this.B | 0;
        C2 = C2 + this.C | 0;
        D = D + this.D | 0;
        E = E + this.E | 0;
        F = F + this.F | 0;
        G2 = G2 + this.G | 0;
        H = H + this.H | 0;
        this.set(A, B, C2, D, E, F, G2, H);
      }
      roundClean() {
        (0, utils_ts_1.clean)(SHA256_W2);
      }
      destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        (0, utils_ts_1.clean)(this.buffer);
      }
    };
    exports.SHA256 = SHA256;
    var SHA224 = class extends SHA256 {
      constructor() {
        super(28);
        this.A = _md_ts_1.SHA224_IV[0] | 0;
        this.B = _md_ts_1.SHA224_IV[1] | 0;
        this.C = _md_ts_1.SHA224_IV[2] | 0;
        this.D = _md_ts_1.SHA224_IV[3] | 0;
        this.E = _md_ts_1.SHA224_IV[4] | 0;
        this.F = _md_ts_1.SHA224_IV[5] | 0;
        this.G = _md_ts_1.SHA224_IV[6] | 0;
        this.H = _md_ts_1.SHA224_IV[7] | 0;
      }
    };
    exports.SHA224 = SHA224;
    var K5122 = /* @__PURE__ */ (() => u64.split([
      "0x428a2f98d728ae22",
      "0x7137449123ef65cd",
      "0xb5c0fbcfec4d3b2f",
      "0xe9b5dba58189dbbc",
      "0x3956c25bf348b538",
      "0x59f111f1b605d019",
      "0x923f82a4af194f9b",
      "0xab1c5ed5da6d8118",
      "0xd807aa98a3030242",
      "0x12835b0145706fbe",
      "0x243185be4ee4b28c",
      "0x550c7dc3d5ffb4e2",
      "0x72be5d74f27b896f",
      "0x80deb1fe3b1696b1",
      "0x9bdc06a725c71235",
      "0xc19bf174cf692694",
      "0xe49b69c19ef14ad2",
      "0xefbe4786384f25e3",
      "0x0fc19dc68b8cd5b5",
      "0x240ca1cc77ac9c65",
      "0x2de92c6f592b0275",
      "0x4a7484aa6ea6e483",
      "0x5cb0a9dcbd41fbd4",
      "0x76f988da831153b5",
      "0x983e5152ee66dfab",
      "0xa831c66d2db43210",
      "0xb00327c898fb213f",
      "0xbf597fc7beef0ee4",
      "0xc6e00bf33da88fc2",
      "0xd5a79147930aa725",
      "0x06ca6351e003826f",
      "0x142929670a0e6e70",
      "0x27b70a8546d22ffc",
      "0x2e1b21385c26c926",
      "0x4d2c6dfc5ac42aed",
      "0x53380d139d95b3df",
      "0x650a73548baf63de",
      "0x766a0abb3c77b2a8",
      "0x81c2c92e47edaee6",
      "0x92722c851482353b",
      "0xa2bfe8a14cf10364",
      "0xa81a664bbc423001",
      "0xc24b8b70d0f89791",
      "0xc76c51a30654be30",
      "0xd192e819d6ef5218",
      "0xd69906245565a910",
      "0xf40e35855771202a",
      "0x106aa07032bbd1b8",
      "0x19a4c116b8d2d0c8",
      "0x1e376c085141ab53",
      "0x2748774cdf8eeb99",
      "0x34b0bcb5e19b48a8",
      "0x391c0cb3c5c95a63",
      "0x4ed8aa4ae3418acb",
      "0x5b9cca4f7763e373",
      "0x682e6ff3d6b2b8a3",
      "0x748f82ee5defb2fc",
      "0x78a5636f43172f60",
      "0x84c87814a1f0ab72",
      "0x8cc702081a6439ec",
      "0x90befffa23631e28",
      "0xa4506cebde82bde9",
      "0xbef9a3f7b2c67915",
      "0xc67178f2e372532b",
      "0xca273eceea26619c",
      "0xd186b8c721c0c207",
      "0xeada7dd6cde0eb1e",
      "0xf57d4f7fee6ed178",
      "0x06f067aa72176fba",
      "0x0a637dc5a2c898a6",
      "0x113f9804bef90dae",
      "0x1b710b35131c471b",
      "0x28db77f523047d84",
      "0x32caab7b40c72493",
      "0x3c9ebe0a15c9bebc",
      "0x431d67c49c100d4c",
      "0x4cc5d4becb3e42b6",
      "0x597f299cfc657e2a",
      "0x5fcb6fab3ad6faec",
      "0x6c44198c4a475817"
    ].map((n) => BigInt(n))))();
    var SHA512_Kh2 = /* @__PURE__ */ (() => K5122[0])();
    var SHA512_Kl2 = /* @__PURE__ */ (() => K5122[1])();
    var SHA512_W_H2 = /* @__PURE__ */ new Uint32Array(80);
    var SHA512_W_L2 = /* @__PURE__ */ new Uint32Array(80);
    var SHA512 = class extends _md_ts_1.HashMD {
      constructor(outputLen = 64) {
        super(128, outputLen, 16, false);
        this.Ah = _md_ts_1.SHA512_IV[0] | 0;
        this.Al = _md_ts_1.SHA512_IV[1] | 0;
        this.Bh = _md_ts_1.SHA512_IV[2] | 0;
        this.Bl = _md_ts_1.SHA512_IV[3] | 0;
        this.Ch = _md_ts_1.SHA512_IV[4] | 0;
        this.Cl = _md_ts_1.SHA512_IV[5] | 0;
        this.Dh = _md_ts_1.SHA512_IV[6] | 0;
        this.Dl = _md_ts_1.SHA512_IV[7] | 0;
        this.Eh = _md_ts_1.SHA512_IV[8] | 0;
        this.El = _md_ts_1.SHA512_IV[9] | 0;
        this.Fh = _md_ts_1.SHA512_IV[10] | 0;
        this.Fl = _md_ts_1.SHA512_IV[11] | 0;
        this.Gh = _md_ts_1.SHA512_IV[12] | 0;
        this.Gl = _md_ts_1.SHA512_IV[13] | 0;
        this.Hh = _md_ts_1.SHA512_IV[14] | 0;
        this.Hl = _md_ts_1.SHA512_IV[15] | 0;
      }
      // prettier-ignore
      get() {
        const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
      }
      // prettier-ignore
      set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
        this.Ah = Ah | 0;
        this.Al = Al | 0;
        this.Bh = Bh | 0;
        this.Bl = Bl | 0;
        this.Ch = Ch | 0;
        this.Cl = Cl | 0;
        this.Dh = Dh | 0;
        this.Dl = Dl | 0;
        this.Eh = Eh | 0;
        this.El = El | 0;
        this.Fh = Fh | 0;
        this.Fl = Fl | 0;
        this.Gh = Gh | 0;
        this.Gl = Gl | 0;
        this.Hh = Hh | 0;
        this.Hl = Hl | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4) {
          SHA512_W_H2[i] = view.getUint32(offset);
          SHA512_W_L2[i] = view.getUint32(offset += 4);
        }
        for (let i = 16; i < 80; i++) {
          const W15h = SHA512_W_H2[i - 15] | 0;
          const W15l = SHA512_W_L2[i - 15] | 0;
          const s0h = u64.rotrSH(W15h, W15l, 1) ^ u64.rotrSH(W15h, W15l, 8) ^ u64.shrSH(W15h, W15l, 7);
          const s0l = u64.rotrSL(W15h, W15l, 1) ^ u64.rotrSL(W15h, W15l, 8) ^ u64.shrSL(W15h, W15l, 7);
          const W2h = SHA512_W_H2[i - 2] | 0;
          const W2l = SHA512_W_L2[i - 2] | 0;
          const s1h = u64.rotrSH(W2h, W2l, 19) ^ u64.rotrBH(W2h, W2l, 61) ^ u64.shrSH(W2h, W2l, 6);
          const s1l = u64.rotrSL(W2h, W2l, 19) ^ u64.rotrBL(W2h, W2l, 61) ^ u64.shrSL(W2h, W2l, 6);
          const SUMl = u64.add4L(s0l, s1l, SHA512_W_L2[i - 7], SHA512_W_L2[i - 16]);
          const SUMh = u64.add4H(SUMl, s0h, s1h, SHA512_W_H2[i - 7], SHA512_W_H2[i - 16]);
          SHA512_W_H2[i] = SUMh | 0;
          SHA512_W_L2[i] = SUMl | 0;
        }
        let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        for (let i = 0; i < 80; i++) {
          const sigma1h = u64.rotrSH(Eh, El, 14) ^ u64.rotrSH(Eh, El, 18) ^ u64.rotrBH(Eh, El, 41);
          const sigma1l = u64.rotrSL(Eh, El, 14) ^ u64.rotrSL(Eh, El, 18) ^ u64.rotrBL(Eh, El, 41);
          const CHIh = Eh & Fh ^ ~Eh & Gh;
          const CHIl = El & Fl ^ ~El & Gl;
          const T1ll = u64.add5L(Hl, sigma1l, CHIl, SHA512_Kl2[i], SHA512_W_L2[i]);
          const T1h = u64.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh2[i], SHA512_W_H2[i]);
          const T1l = T1ll | 0;
          const sigma0h = u64.rotrSH(Ah, Al, 28) ^ u64.rotrBH(Ah, Al, 34) ^ u64.rotrBH(Ah, Al, 39);
          const sigma0l = u64.rotrSL(Ah, Al, 28) ^ u64.rotrBL(Ah, Al, 34) ^ u64.rotrBL(Ah, Al, 39);
          const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
          const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
          Hh = Gh | 0;
          Hl = Gl | 0;
          Gh = Fh | 0;
          Gl = Fl | 0;
          Fh = Eh | 0;
          Fl = El | 0;
          ({ h: Eh, l: El } = u64.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
          Dh = Ch | 0;
          Dl = Cl | 0;
          Ch = Bh | 0;
          Cl = Bl | 0;
          Bh = Ah | 0;
          Bl = Al | 0;
          const All = u64.add3L(T1l, sigma0l, MAJl);
          Ah = u64.add3H(All, T1h, sigma0h, MAJh);
          Al = All | 0;
        }
        ({ h: Ah, l: Al } = u64.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
        ({ h: Bh, l: Bl } = u64.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
        ({ h: Ch, l: Cl } = u64.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
        ({ h: Dh, l: Dl } = u64.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
        ({ h: Eh, l: El } = u64.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
        ({ h: Fh, l: Fl } = u64.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
        ({ h: Gh, l: Gl } = u64.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
        ({ h: Hh, l: Hl } = u64.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
        this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
      }
      roundClean() {
        (0, utils_ts_1.clean)(SHA512_W_H2, SHA512_W_L2);
      }
      destroy() {
        (0, utils_ts_1.clean)(this.buffer);
        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      }
    };
    exports.SHA512 = SHA512;
    var SHA384 = class extends SHA512 {
      constructor() {
        super(48);
        this.Ah = _md_ts_1.SHA384_IV[0] | 0;
        this.Al = _md_ts_1.SHA384_IV[1] | 0;
        this.Bh = _md_ts_1.SHA384_IV[2] | 0;
        this.Bl = _md_ts_1.SHA384_IV[3] | 0;
        this.Ch = _md_ts_1.SHA384_IV[4] | 0;
        this.Cl = _md_ts_1.SHA384_IV[5] | 0;
        this.Dh = _md_ts_1.SHA384_IV[6] | 0;
        this.Dl = _md_ts_1.SHA384_IV[7] | 0;
        this.Eh = _md_ts_1.SHA384_IV[8] | 0;
        this.El = _md_ts_1.SHA384_IV[9] | 0;
        this.Fh = _md_ts_1.SHA384_IV[10] | 0;
        this.Fl = _md_ts_1.SHA384_IV[11] | 0;
        this.Gh = _md_ts_1.SHA384_IV[12] | 0;
        this.Gl = _md_ts_1.SHA384_IV[13] | 0;
        this.Hh = _md_ts_1.SHA384_IV[14] | 0;
        this.Hl = _md_ts_1.SHA384_IV[15] | 0;
      }
    };
    exports.SHA384 = SHA384;
    var T224_IV2 = /* @__PURE__ */ Uint32Array.from([
      2352822216,
      424955298,
      1944164710,
      2312950998,
      502970286,
      855612546,
      1738396948,
      1479516111,
      258812777,
      2077511080,
      2011393907,
      79989058,
      1067287976,
      1780299464,
      286451373,
      2446758561
    ]);
    var T256_IV2 = /* @__PURE__ */ Uint32Array.from([
      573645204,
      4230739756,
      2673172387,
      3360449730,
      596883563,
      1867755857,
      2520282905,
      1497426621,
      2519219938,
      2827943907,
      3193839141,
      1401305490,
      721525244,
      746961066,
      246885852,
      2177182882
    ]);
    var SHA512_224 = class extends SHA512 {
      constructor() {
        super(28);
        this.Ah = T224_IV2[0] | 0;
        this.Al = T224_IV2[1] | 0;
        this.Bh = T224_IV2[2] | 0;
        this.Bl = T224_IV2[3] | 0;
        this.Ch = T224_IV2[4] | 0;
        this.Cl = T224_IV2[5] | 0;
        this.Dh = T224_IV2[6] | 0;
        this.Dl = T224_IV2[7] | 0;
        this.Eh = T224_IV2[8] | 0;
        this.El = T224_IV2[9] | 0;
        this.Fh = T224_IV2[10] | 0;
        this.Fl = T224_IV2[11] | 0;
        this.Gh = T224_IV2[12] | 0;
        this.Gl = T224_IV2[13] | 0;
        this.Hh = T224_IV2[14] | 0;
        this.Hl = T224_IV2[15] | 0;
      }
    };
    exports.SHA512_224 = SHA512_224;
    var SHA512_256 = class extends SHA512 {
      constructor() {
        super(32);
        this.Ah = T256_IV2[0] | 0;
        this.Al = T256_IV2[1] | 0;
        this.Bh = T256_IV2[2] | 0;
        this.Bl = T256_IV2[3] | 0;
        this.Ch = T256_IV2[4] | 0;
        this.Cl = T256_IV2[5] | 0;
        this.Dh = T256_IV2[6] | 0;
        this.Dl = T256_IV2[7] | 0;
        this.Eh = T256_IV2[8] | 0;
        this.El = T256_IV2[9] | 0;
        this.Fh = T256_IV2[10] | 0;
        this.Fl = T256_IV2[11] | 0;
        this.Gh = T256_IV2[12] | 0;
        this.Gl = T256_IV2[13] | 0;
        this.Hh = T256_IV2[14] | 0;
        this.Hl = T256_IV2[15] | 0;
      }
    };
    exports.SHA512_256 = SHA512_256;
    exports.sha256 = (0, utils_ts_1.createHasher)(() => new SHA256());
    exports.sha224 = (0, utils_ts_1.createHasher)(() => new SHA224());
    exports.sha512 = (0, utils_ts_1.createHasher)(() => new SHA512());
    exports.sha384 = (0, utils_ts_1.createHasher)(() => new SHA384());
    exports.sha512_256 = (0, utils_ts_1.createHasher)(() => new SHA512_256());
    exports.sha512_224 = (0, utils_ts_1.createHasher)(() => new SHA512_224());
  }
});

// node_modules/bip32/node_modules/@noble/hashes/sha256.js
var require_sha2562 = __commonJS({
  "node_modules/bip32/node_modules/@noble/hashes/sha256.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.sha224 = exports.SHA224 = exports.sha256 = exports.SHA256 = void 0;
    var sha2_ts_1 = require_sha22();
    exports.SHA256 = sha2_ts_1.SHA256;
    exports.sha256 = sha2_ts_1.sha256;
    exports.SHA224 = sha2_ts_1.SHA224;
    exports.sha224 = sha2_ts_1.sha224;
  }
});

// node_modules/bip32/node_modules/@noble/hashes/sha512.js
var require_sha5122 = __commonJS({
  "node_modules/bip32/node_modules/@noble/hashes/sha512.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.sha512_256 = exports.SHA512_256 = exports.sha512_224 = exports.SHA512_224 = exports.sha384 = exports.SHA384 = exports.sha512 = exports.SHA512 = void 0;
    var sha2_ts_1 = require_sha22();
    exports.SHA512 = sha2_ts_1.SHA512;
    exports.sha512 = sha2_ts_1.sha512;
    exports.SHA384 = sha2_ts_1.SHA384;
    exports.sha384 = sha2_ts_1.sha384;
    exports.SHA512_224 = sha2_ts_1.SHA512_224;
    exports.sha512_224 = sha2_ts_1.sha512_224;
    exports.SHA512_256 = sha2_ts_1.SHA512_256;
    exports.sha512_256 = sha2_ts_1.sha512_256;
  }
});

// node_modules/bip32/src/cjs/crypto.cjs
var require_crypto3 = __commonJS({
  "node_modules/bip32/src/cjs/crypto.cjs"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.hash160 = hash160;
    exports.hmacSHA512 = hmacSHA512;
    var hmac_1 = require_hmac2();
    var ripemd160_1 = require_ripemd160();
    var sha256_1 = require_sha2562();
    var sha512_1 = require_sha5122();
    function hash160(buffer) {
      return (0, ripemd160_1.ripemd160)((0, sha256_1.sha256)(buffer));
    }
    function hmacSHA512(key, data) {
      return (0, hmac_1.hmac)(sha512_1.sha512, key, data);
    }
  }
});

// node_modules/uint8array-tools/src/mjs/browser.js
var browser_exports = {};
__export(browser_exports, {
  compare: () => compare,
  concat: () => concat,
  fromBase64: () => fromBase64,
  fromHex: () => fromHex,
  fromUtf8: () => fromUtf8,
  readUInt16: () => readUInt16,
  readUInt32: () => readUInt32,
  readUInt64: () => readUInt64,
  readUInt8: () => readUInt8,
  toBase64: () => toBase64,
  toHex: () => toHex,
  toUtf8: () => toUtf8,
  writeUInt16: () => writeUInt16,
  writeUInt32: () => writeUInt32,
  writeUInt64: () => writeUInt64,
  writeUInt8: () => writeUInt8
});
function toUtf8(bytes2) {
  return DECODER.decode(bytes2);
}
function fromUtf8(s) {
  return ENCODER.encode(s);
}
function concat(arrays) {
  const totalLength = arrays.reduce((a, b) => a + b.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const array of arrays) {
    result.set(array, offset);
    offset += array.length;
  }
  return result;
}
function toHex(bytes2) {
  const b = bytes2 || new Uint8Array();
  return b.length > 512 ? _toHexLengthPerf(b) : _toHexIterPerf(b);
}
function _toHexIterPerf(bytes2) {
  let s = "";
  for (let i = 0; i < bytes2.length; ++i) {
    s += HEX_STRINGS[HEX_CODEPOINTS[HEX_CODES[bytes2[i] >> 4]]];
    s += HEX_STRINGS[HEX_CODEPOINTS[HEX_CODES[bytes2[i] & 15]]];
  }
  return s;
}
function _toHexLengthPerf(bytes2) {
  const hexBytes = new Uint8Array(bytes2.length * 2);
  for (let i = 0; i < bytes2.length; ++i) {
    hexBytes[i * 2] = HEX_CODES[bytes2[i] >> 4];
    hexBytes[i * 2 + 1] = HEX_CODES[bytes2[i] & 15];
  }
  return DECODER.decode(hexBytes);
}
function fromHex(hexString) {
  const hexBytes = ENCODER.encode(hexString || "");
  const resultBytes = new Uint8Array(Math.floor(hexBytes.length / 2));
  let i;
  for (i = 0; i < resultBytes.length; i++) {
    const a = HEX_CODEPOINTS[hexBytes[i * 2]];
    const b = HEX_CODEPOINTS[hexBytes[i * 2 + 1]];
    if (a === void 0 || b === void 0) {
      break;
    }
    resultBytes[i] = a << 4 | b;
  }
  return i === resultBytes.length ? resultBytes : resultBytes.slice(0, i);
}
function toBase64(bytes2) {
  return btoa(String.fromCharCode(...bytes2));
}
function fromBase64(base642) {
  const binaryString = atob(base642);
  const bytes2 = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes2[i] = binaryString.charCodeAt(i);
  }
  return bytes2;
}
function compare(v1, v2) {
  const minLength = Math.min(v1.length, v2.length);
  for (let i = 0; i < minLength; ++i) {
    if (v1[i] !== v2[i]) {
      return v1[i] < v2[i] ? -1 : 1;
    }
  }
  return v1.length === v2.length ? 0 : v1.length > v2.length ? 1 : -1;
}
function writeUInt8(buffer, offset, value) {
  if (offset + 1 > buffer.length) {
    throw new Error("Offset is outside the bounds of Uint8Array");
  }
  if (value > 255) {
    throw new Error(`The value of "value" is out of range. It must be >= 0 and <= ${255}. Received ${value}`);
  }
  buffer[offset] = value;
}
function writeUInt16(buffer, offset, value, littleEndian) {
  if (offset + 2 > buffer.length) {
    throw new Error("Offset is outside the bounds of Uint8Array");
  }
  littleEndian = littleEndian.toUpperCase();
  if (value > 65535) {
    throw new Error(`The value of "value" is out of range. It must be >= 0 and <= ${65535}. Received ${value}`);
  }
  if (littleEndian === "LE") {
    buffer[offset] = value & 255;
    buffer[offset + 1] = value >> 8 & 255;
  } else {
    buffer[offset] = value >> 8 & 255;
    buffer[offset + 1] = value & 255;
  }
}
function writeUInt32(buffer, offset, value, littleEndian) {
  if (offset + 4 > buffer.length) {
    throw new Error("Offset is outside the bounds of Uint8Array");
  }
  littleEndian = littleEndian.toUpperCase();
  if (value > 4294967295) {
    throw new Error(`The value of "value" is out of range. It must be >= 0 and <= ${4294967295}. Received ${value}`);
  }
  if (littleEndian === "LE") {
    buffer[offset] = value & 255;
    buffer[offset + 1] = value >> 8 & 255;
    buffer[offset + 2] = value >> 16 & 255;
    buffer[offset + 3] = value >> 24 & 255;
  } else {
    buffer[offset] = value >> 24 & 255;
    buffer[offset + 1] = value >> 16 & 255;
    buffer[offset + 2] = value >> 8 & 255;
    buffer[offset + 3] = value & 255;
  }
}
function writeUInt64(buffer, offset, value, littleEndian) {
  if (offset + 8 > buffer.length) {
    throw new Error("Offset is outside the bounds of Uint8Array");
  }
  littleEndian = littleEndian.toUpperCase();
  if (value > 0xffffffffffffffffn) {
    throw new Error(`The value of "value" is out of range. It must be >= 0 and <= ${0xffffffffffffffffn}. Received ${value}`);
  }
  if (littleEndian === "LE") {
    buffer[offset] = Number(value & 0xffn);
    buffer[offset + 1] = Number(value >> 8n & 0xffn);
    buffer[offset + 2] = Number(value >> 16n & 0xffn);
    buffer[offset + 3] = Number(value >> 24n & 0xffn);
    buffer[offset + 4] = Number(value >> 32n & 0xffn);
    buffer[offset + 5] = Number(value >> 40n & 0xffn);
    buffer[offset + 6] = Number(value >> 48n & 0xffn);
    buffer[offset + 7] = Number(value >> 56n & 0xffn);
  } else {
    buffer[offset] = Number(value >> 56n & 0xffn);
    buffer[offset + 1] = Number(value >> 48n & 0xffn);
    buffer[offset + 2] = Number(value >> 40n & 0xffn);
    buffer[offset + 3] = Number(value >> 32n & 0xffn);
    buffer[offset + 4] = Number(value >> 24n & 0xffn);
    buffer[offset + 5] = Number(value >> 16n & 0xffn);
    buffer[offset + 6] = Number(value >> 8n & 0xffn);
    buffer[offset + 7] = Number(value & 0xffn);
  }
}
function readUInt8(buffer, offset) {
  if (offset + 1 > buffer.length) {
    throw new Error("Offset is outside the bounds of Uint8Array");
  }
  return buffer[offset];
}
function readUInt16(buffer, offset, littleEndian) {
  if (offset + 2 > buffer.length) {
    throw new Error("Offset is outside the bounds of Uint8Array");
  }
  littleEndian = littleEndian.toUpperCase();
  if (littleEndian === "LE") {
    let num = 0;
    num = (num << 8) + buffer[offset + 1];
    num = (num << 8) + buffer[offset];
    return num;
  } else {
    let num = 0;
    num = (num << 8) + buffer[offset];
    num = (num << 8) + buffer[offset + 1];
    return num;
  }
}
function readUInt32(buffer, offset, littleEndian) {
  if (offset + 4 > buffer.length) {
    throw new Error("Offset is outside the bounds of Uint8Array");
  }
  littleEndian = littleEndian.toUpperCase();
  if (littleEndian === "LE") {
    let num = 0;
    num = (num << 8) + buffer[offset + 3] >>> 0;
    num = (num << 8) + buffer[offset + 2] >>> 0;
    num = (num << 8) + buffer[offset + 1] >>> 0;
    num = (num << 8) + buffer[offset] >>> 0;
    return num;
  } else {
    let num = 0;
    num = (num << 8) + buffer[offset] >>> 0;
    num = (num << 8) + buffer[offset + 1] >>> 0;
    num = (num << 8) + buffer[offset + 2] >>> 0;
    num = (num << 8) + buffer[offset + 3] >>> 0;
    return num;
  }
}
function readUInt64(buffer, offset, littleEndian) {
  if (offset + 8 > buffer.length) {
    throw new Error("Offset is outside the bounds of Uint8Array");
  }
  littleEndian = littleEndian.toUpperCase();
  if (littleEndian === "LE") {
    let num = 0n;
    num = (num << 8n) + BigInt(buffer[offset + 7]);
    num = (num << 8n) + BigInt(buffer[offset + 6]);
    num = (num << 8n) + BigInt(buffer[offset + 5]);
    num = (num << 8n) + BigInt(buffer[offset + 4]);
    num = (num << 8n) + BigInt(buffer[offset + 3]);
    num = (num << 8n) + BigInt(buffer[offset + 2]);
    num = (num << 8n) + BigInt(buffer[offset + 1]);
    num = (num << 8n) + BigInt(buffer[offset]);
    return num;
  } else {
    let num = 0n;
    num = (num << 8n) + BigInt(buffer[offset]);
    num = (num << 8n) + BigInt(buffer[offset + 1]);
    num = (num << 8n) + BigInt(buffer[offset + 2]);
    num = (num << 8n) + BigInt(buffer[offset + 3]);
    num = (num << 8n) + BigInt(buffer[offset + 4]);
    num = (num << 8n) + BigInt(buffer[offset + 5]);
    num = (num << 8n) + BigInt(buffer[offset + 6]);
    num = (num << 8n) + BigInt(buffer[offset + 7]);
    return num;
  }
}
var HEX_STRINGS, HEX_CODES, HEX_CODEPOINTS, ENCODER, DECODER;
var init_browser = __esm({
  "node_modules/uint8array-tools/src/mjs/browser.js"() {
    HEX_STRINGS = "0123456789abcdefABCDEF";
    HEX_CODES = HEX_STRINGS.split("").map((c) => c.codePointAt(0));
    HEX_CODEPOINTS = Array(256).fill(true).map((_, i) => {
      const s = String.fromCodePoint(i);
      const index = HEX_STRINGS.indexOf(s);
      return index < 0 ? void 0 : index < 16 ? index : index - 6;
    });
    ENCODER = new TextEncoder();
    DECODER = new TextDecoder();
  }
});

// node_modules/bip32/src/cjs/testecc.cjs
var require_testecc = __commonJS({
  "node_modules/bip32/src/cjs/testecc.cjs"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      var desc = Object.getOwnPropertyDescriptor(m, k);
      if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m[k];
        } };
      }
      Object.defineProperty(o, k2, desc);
    }) : (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    }));
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? (function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    }) : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule) return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.testEcc = testEcc;
    var tools = __importStar((init_browser(), __toCommonJS(browser_exports)));
    var h = (hex2) => tools.fromHex(hex2);
    function testEcc(ecc) {
      assert(ecc.isPoint(h("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")));
      assert(!ecc.isPoint(h("030000000000000000000000000000000000000000000000000000000000000005")));
      assert(ecc.isPrivate(h("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")));
      assert(ecc.isPrivate(h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")));
      assert(!ecc.isPrivate(h("0000000000000000000000000000000000000000000000000000000000000000")));
      assert(!ecc.isPrivate(h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")));
      assert(!ecc.isPrivate(h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142")));
      assert(tools.compare(ecc.pointFromScalar(h("b1121e4088a66a28f5b6b0f5844943ecd9f610196d7bb83b25214b60452c09af")), h("02b07ba9dca9523b7ef4bd97703d43d20399eb698e194704791a25ce77a400df99")) === 0);
      if (ecc.xOnlyPointAddTweak) {
        assert(ecc.xOnlyPointAddTweak(h("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")) === null);
        let xOnlyRes = ecc.xOnlyPointAddTweak(h("1617d38ed8d8657da4d4761e8057bc396ea9e4b9d29776d4be096016dbd2509b"), h("a8397a935f0dfceba6ba9618f6451ef4d80637abf4e6af2669fbc9de6a8fd2ac"));
        assert(tools.compare(xOnlyRes.xOnlyPubkey, h("e478f99dab91052ab39a33ea35fd5e6e4933f4d28023cd597c9a1f6760346adf")) === 0 && xOnlyRes.parity === 1);
        xOnlyRes = ecc.xOnlyPointAddTweak(h("2c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"), h("823c3cd2142744b075a87eade7e1b8678ba308d566226a0056ca2b7a76f86b47"));
      }
      assert(tools.compare(ecc.pointAddScalar(h("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), h("0000000000000000000000000000000000000000000000000000000000000003")), h("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")) === 0);
      assert(tools.compare(ecc.privateAdd(h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e"), h("0000000000000000000000000000000000000000000000000000000000000002")), h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")) === 0);
      if (ecc.privateNegate) {
        assert(tools.compare(ecc.privateNegate(h("0000000000000000000000000000000000000000000000000000000000000001")), h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")) === 0);
        assert(tools.compare(ecc.privateNegate(h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e")), h("0000000000000000000000000000000000000000000000000000000000000003")) === 0);
        assert(tools.compare(ecc.privateNegate(h("b1121e4088a66a28f5b6b0f5844943ecd9f610196d7bb83b25214b60452c09af")), h("4eede1bf775995d70a494f0a7bb6bc11e0b8cccd41cce8009ab1132c8b0a3792")) === 0);
      }
      assert(tools.compare(ecc.sign(h("5e9f0a0d593efdcf78ac923bc3313e4e7d408d574354ee2b3288c0da9fbba6ed"), h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")), h("54c4a33c6423d689378f160a7ff8b61330444abb58fb470f96ea16d99d4a2fed07082304410efa6b2943111b6a4e0aaa7b7db55a07e9861d1fb3cb1f421044a5")) === 0);
      assert(ecc.verify(h("5e9f0a0d593efdcf78ac923bc3313e4e7d408d574354ee2b3288c0da9fbba6ed"), h("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), h("54c4a33c6423d689378f160a7ff8b61330444abb58fb470f96ea16d99d4a2fed07082304410efa6b2943111b6a4e0aaa7b7db55a07e9861d1fb3cb1f421044a5")));
      if (ecc.signSchnorr) {
        assert(tools.compare(ecc.signSchnorr(h("7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c"), h("c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9"), h("c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906")), h("5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7")) === 0);
      }
      if (ecc.verifySchnorr) {
        assert(ecc.verifySchnorr(h("7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c"), h("dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8"), h("5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7")));
      }
    }
    function assert(bool) {
      if (!bool)
        throw new Error("ecc library invalid");
    }
  }
});

// node_modules/bip32/node_modules/@scure/base/lib/index.js
var require_lib = __commonJS({
  "node_modules/bip32/node_modules/@scure/base/lib/index.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.bytes = exports.stringToBytes = exports.str = exports.bytesToString = exports.hex = exports.utf8 = exports.bech32m = exports.bech32 = exports.base58check = exports.createBase58check = exports.base58xmr = exports.base58xrp = exports.base58flickr = exports.base58 = exports.base64urlnopad = exports.base64url = exports.base64nopad = exports.base64 = exports.base32crockford = exports.base32hexnopad = exports.base32hex = exports.base32nopad = exports.base32 = exports.base16 = exports.utils = void 0;
    function isBytes4(a) {
      return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
    }
    function abytes4(b, ...lengths2) {
      if (!isBytes4(b))
        throw new Error("Uint8Array expected");
      if (lengths2.length > 0 && !lengths2.includes(b.length))
        throw new Error("Uint8Array expected of length " + lengths2 + ", got length=" + b.length);
    }
    function isArrayOf2(isString, arr) {
      if (!Array.isArray(arr))
        return false;
      if (arr.length === 0)
        return true;
      if (isString) {
        return arr.every((item) => typeof item === "string");
      } else {
        return arr.every((item) => Number.isSafeInteger(item));
      }
    }
    function afn2(input) {
      if (typeof input !== "function")
        throw new Error("function expected");
      return true;
    }
    function astr2(label, input) {
      if (typeof input !== "string")
        throw new Error(`${label}: string expected`);
      return true;
    }
    function anumber3(n) {
      if (!Number.isSafeInteger(n))
        throw new Error(`invalid integer: ${n}`);
    }
    function aArr2(input) {
      if (!Array.isArray(input))
        throw new Error("array expected");
    }
    function astrArr2(label, input) {
      if (!isArrayOf2(true, input))
        throw new Error(`${label}: array of strings expected`);
    }
    function anumArr2(label, input) {
      if (!isArrayOf2(false, input))
        throw new Error(`${label}: array of numbers expected`);
    }
    // @__NO_SIDE_EFFECTS__
    function chain2(...args) {
      const id = (a) => a;
      const wrap = (a, b) => (c) => a(b(c));
      const encode = args.map((x) => x.encode).reduceRight(wrap, id);
      const decode = args.map((x) => x.decode).reduce(wrap, id);
      return { encode, decode };
    }
    // @__NO_SIDE_EFFECTS__
    function alphabet2(letters) {
      const lettersA = typeof letters === "string" ? letters.split("") : letters;
      const len = lettersA.length;
      astrArr2("alphabet", lettersA);
      const indexes = new Map(lettersA.map((l, i) => [l, i]));
      return {
        encode: (digits) => {
          aArr2(digits);
          return digits.map((i) => {
            if (!Number.isSafeInteger(i) || i < 0 || i >= len)
              throw new Error(`alphabet.encode: digit index outside alphabet "${i}". Allowed: ${letters}`);
            return lettersA[i];
          });
        },
        decode: (input) => {
          aArr2(input);
          return input.map((letter) => {
            astr2("alphabet.decode", letter);
            const i = indexes.get(letter);
            if (i === void 0)
              throw new Error(`Unknown letter: "${letter}". Allowed: ${letters}`);
            return i;
          });
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function join2(separator = "") {
      astr2("join", separator);
      return {
        encode: (from) => {
          astrArr2("join.decode", from);
          return from.join(separator);
        },
        decode: (to) => {
          astr2("join.decode", to);
          return to.split(separator);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function padding2(bits, chr = "=") {
      anumber3(bits);
      astr2("padding", chr);
      return {
        encode(data) {
          astrArr2("padding.encode", data);
          while (data.length * bits % 8)
            data.push(chr);
          return data;
        },
        decode(input) {
          astrArr2("padding.decode", input);
          let end = input.length;
          if (end * bits % 8)
            throw new Error("padding: invalid, string should have whole number of bytes");
          for (; end > 0 && input[end - 1] === chr; end--) {
            const last = end - 1;
            const byte = last * bits;
            if (byte % 8 === 0)
              throw new Error("padding: invalid, string has too much padding");
          }
          return input.slice(0, end);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function normalize2(fn) {
      afn2(fn);
      return { encode: (from) => from, decode: (to) => fn(to) };
    }
    function convertRadix3(data, from, to) {
      if (from < 2)
        throw new Error(`convertRadix: invalid from=${from}, base cannot be less than 2`);
      if (to < 2)
        throw new Error(`convertRadix: invalid to=${to}, base cannot be less than 2`);
      aArr2(data);
      if (!data.length)
        return [];
      let pos = 0;
      const res = [];
      const digits = Array.from(data, (d) => {
        anumber3(d);
        if (d < 0 || d >= from)
          throw new Error(`invalid integer: ${d}`);
        return d;
      });
      const dlen = digits.length;
      while (true) {
        let carry = 0;
        let done = true;
        for (let i = pos; i < dlen; i++) {
          const digit = digits[i];
          const fromCarry = from * carry;
          const digitBase = fromCarry + digit;
          if (!Number.isSafeInteger(digitBase) || fromCarry / from !== carry || digitBase - digit !== fromCarry) {
            throw new Error("convertRadix: carry overflow");
          }
          const div = digitBase / to;
          carry = digitBase % to;
          const rounded = Math.floor(div);
          digits[i] = rounded;
          if (!Number.isSafeInteger(rounded) || rounded * to + carry !== digitBase)
            throw new Error("convertRadix: carry overflow");
          if (!done)
            continue;
          else if (!rounded)
            pos = i;
          else
            done = false;
        }
        res.push(carry);
        if (done)
          break;
      }
      for (let i = 0; i < data.length - 1 && data[i] === 0; i++)
        res.push(0);
      return res.reverse();
    }
    var gcd2 = (a, b) => b === 0 ? a : gcd2(b, a % b);
    var radix2carry2 = /* @__NO_SIDE_EFFECTS__ */ (from, to) => from + (to - gcd2(from, to));
    var powers2 = /* @__PURE__ */ (() => {
      let res = [];
      for (let i = 0; i < 40; i++)
        res.push(2 ** i);
      return res;
    })();
    function convertRadix22(data, from, to, padding3) {
      aArr2(data);
      if (from <= 0 || from > 32)
        throw new Error(`convertRadix2: wrong from=${from}`);
      if (to <= 0 || to > 32)
        throw new Error(`convertRadix2: wrong to=${to}`);
      if (/* @__PURE__ */ radix2carry2(from, to) > 32) {
        throw new Error(`convertRadix2: carry overflow from=${from} to=${to} carryBits=${/* @__PURE__ */ radix2carry2(from, to)}`);
      }
      let carry = 0;
      let pos = 0;
      const max = powers2[from];
      const mask = powers2[to] - 1;
      const res = [];
      for (const n of data) {
        anumber3(n);
        if (n >= max)
          throw new Error(`convertRadix2: invalid data word=${n} from=${from}`);
        carry = carry << from | n;
        if (pos + from > 32)
          throw new Error(`convertRadix2: carry overflow pos=${pos} from=${from}`);
        pos += from;
        for (; pos >= to; pos -= to)
          res.push((carry >> pos - to & mask) >>> 0);
        const pow = powers2[pos];
        if (pow === void 0)
          throw new Error("invalid carry");
        carry &= pow - 1;
      }
      carry = carry << to - pos & mask;
      if (!padding3 && pos >= from)
        throw new Error("Excess padding");
      if (!padding3 && carry > 0)
        throw new Error(`Non-zero padding: ${carry}`);
      if (padding3 && pos > 0)
        res.push(carry >>> 0);
      return res;
    }
    // @__NO_SIDE_EFFECTS__
    function radix3(num) {
      anumber3(num);
      const _256 = 2 ** 8;
      return {
        encode: (bytes2) => {
          if (!isBytes4(bytes2))
            throw new Error("radix.encode input should be Uint8Array");
          return convertRadix3(Array.from(bytes2), _256, num);
        },
        decode: (digits) => {
          anumArr2("radix.decode", digits);
          return Uint8Array.from(convertRadix3(digits, num, _256));
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function radix22(bits, revPadding = false) {
      anumber3(bits);
      if (bits <= 0 || bits > 32)
        throw new Error("radix2: bits should be in (0..32]");
      if (/* @__PURE__ */ radix2carry2(8, bits) > 32 || /* @__PURE__ */ radix2carry2(bits, 8) > 32)
        throw new Error("radix2: carry overflow");
      return {
        encode: (bytes2) => {
          if (!isBytes4(bytes2))
            throw new Error("radix2.encode input should be Uint8Array");
          return convertRadix22(Array.from(bytes2), 8, bits, !revPadding);
        },
        decode: (digits) => {
          anumArr2("radix2.decode", digits);
          return Uint8Array.from(convertRadix22(digits, bits, 8, revPadding));
        }
      };
    }
    function unsafeWrapper2(fn) {
      afn2(fn);
      return function(...args) {
        try {
          return fn.apply(null, args);
        } catch (e) {
        }
      };
    }
    function checksum2(len, fn) {
      anumber3(len);
      afn2(fn);
      return {
        encode(data) {
          if (!isBytes4(data))
            throw new Error("checksum.encode: input should be Uint8Array");
          const sum = fn(data).slice(0, len);
          const res = new Uint8Array(data.length + len);
          res.set(data);
          res.set(sum, data.length);
          return res;
        },
        decode(data) {
          if (!isBytes4(data))
            throw new Error("checksum.decode: input should be Uint8Array");
          const payload = data.slice(0, -len);
          const oldChecksum = data.slice(-len);
          const newChecksum = fn(payload).slice(0, len);
          for (let i = 0; i < len; i++)
            if (newChecksum[i] !== oldChecksum[i])
              throw new Error("Invalid checksum");
          return payload;
        }
      };
    }
    exports.utils = {
      alphabet: alphabet2,
      chain: chain2,
      checksum: checksum2,
      convertRadix: convertRadix3,
      convertRadix2: convertRadix22,
      radix: radix3,
      radix2: radix22,
      join: join2,
      padding: padding2
    };
    exports.base16 = /* @__PURE__ */ chain2(/* @__PURE__ */ radix22(4), /* @__PURE__ */ alphabet2("0123456789ABCDEF"), /* @__PURE__ */ join2(""));
    exports.base32 = /* @__PURE__ */ chain2(/* @__PURE__ */ radix22(5), /* @__PURE__ */ alphabet2("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), /* @__PURE__ */ padding2(5), /* @__PURE__ */ join2(""));
    exports.base32nopad = /* @__PURE__ */ chain2(/* @__PURE__ */ radix22(5), /* @__PURE__ */ alphabet2("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), /* @__PURE__ */ join2(""));
    exports.base32hex = /* @__PURE__ */ chain2(/* @__PURE__ */ radix22(5), /* @__PURE__ */ alphabet2("0123456789ABCDEFGHIJKLMNOPQRSTUV"), /* @__PURE__ */ padding2(5), /* @__PURE__ */ join2(""));
    exports.base32hexnopad = /* @__PURE__ */ chain2(/* @__PURE__ */ radix22(5), /* @__PURE__ */ alphabet2("0123456789ABCDEFGHIJKLMNOPQRSTUV"), /* @__PURE__ */ join2(""));
    exports.base32crockford = /* @__PURE__ */ chain2(/* @__PURE__ */ radix22(5), /* @__PURE__ */ alphabet2("0123456789ABCDEFGHJKMNPQRSTVWXYZ"), /* @__PURE__ */ join2(""), /* @__PURE__ */ normalize2((s) => s.toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1")));
    var hasBase64Builtin2 = /* @__PURE__ */ (() => typeof Uint8Array.from([]).toBase64 === "function" && typeof Uint8Array.fromBase64 === "function")();
    var decodeBase64Builtin2 = (s, isUrl) => {
      astr2("base64", s);
      const re = isUrl ? /^[A-Za-z0-9=_-]+$/ : /^[A-Za-z0-9=+/]+$/;
      const alphabet3 = isUrl ? "base64url" : "base64";
      if (s.length > 0 && !re.test(s))
        throw new Error("invalid base64");
      return Uint8Array.fromBase64(s, { alphabet: alphabet3, lastChunkHandling: "strict" });
    };
    exports.base64 = hasBase64Builtin2 ? {
      encode(b) {
        abytes4(b);
        return b.toBase64();
      },
      decode(s) {
        return decodeBase64Builtin2(s, false);
      }
    } : /* @__PURE__ */ chain2(/* @__PURE__ */ radix22(6), /* @__PURE__ */ alphabet2("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), /* @__PURE__ */ padding2(6), /* @__PURE__ */ join2(""));
    exports.base64nopad = /* @__PURE__ */ chain2(/* @__PURE__ */ radix22(6), /* @__PURE__ */ alphabet2("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), /* @__PURE__ */ join2(""));
    exports.base64url = hasBase64Builtin2 ? {
      encode(b) {
        abytes4(b);
        return b.toBase64({ alphabet: "base64url" });
      },
      decode(s) {
        return decodeBase64Builtin2(s, true);
      }
    } : /* @__PURE__ */ chain2(/* @__PURE__ */ radix22(6), /* @__PURE__ */ alphabet2("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), /* @__PURE__ */ padding2(6), /* @__PURE__ */ join2(""));
    exports.base64urlnopad = /* @__PURE__ */ chain2(/* @__PURE__ */ radix22(6), /* @__PURE__ */ alphabet2("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), /* @__PURE__ */ join2(""));
    var genBase582 = /* @__NO_SIDE_EFFECTS__ */ (abc) => /* @__PURE__ */ chain2(/* @__PURE__ */ radix3(58), /* @__PURE__ */ alphabet2(abc), /* @__PURE__ */ join2(""));
    exports.base58 = /* @__PURE__ */ genBase582("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
    exports.base58flickr = /* @__PURE__ */ genBase582("123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ");
    exports.base58xrp = /* @__PURE__ */ genBase582("rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz");
    var XMR_BLOCK_LEN2 = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    exports.base58xmr = {
      encode(data) {
        let res = "";
        for (let i = 0; i < data.length; i += 8) {
          const block = data.subarray(i, i + 8);
          res += exports.base58.encode(block).padStart(XMR_BLOCK_LEN2[block.length], "1");
        }
        return res;
      },
      decode(str2) {
        let res = [];
        for (let i = 0; i < str2.length; i += 11) {
          const slice = str2.slice(i, i + 11);
          const blockLen = XMR_BLOCK_LEN2.indexOf(slice.length);
          const block = exports.base58.decode(slice);
          for (let j = 0; j < block.length - blockLen; j++) {
            if (block[j] !== 0)
              throw new Error("base58xmr: wrong padding");
          }
          res = res.concat(Array.from(block.slice(block.length - blockLen)));
        }
        return Uint8Array.from(res);
      }
    };
    var createBase58check2 = (sha2562) => /* @__PURE__ */ chain2(checksum2(4, (data) => sha2562(sha2562(data))), exports.base58);
    exports.createBase58check = createBase58check2;
    exports.base58check = exports.createBase58check;
    var BECH_ALPHABET2 = /* @__PURE__ */ chain2(/* @__PURE__ */ alphabet2("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), /* @__PURE__ */ join2(""));
    var POLYMOD_GENERATORS2 = [996825010, 642813549, 513874426, 1027748829, 705979059];
    function bech32Polymod2(pre) {
      const b = pre >> 25;
      let chk = (pre & 33554431) << 5;
      for (let i = 0; i < POLYMOD_GENERATORS2.length; i++) {
        if ((b >> i & 1) === 1)
          chk ^= POLYMOD_GENERATORS2[i];
      }
      return chk;
    }
    function bechChecksum2(prefix, words, encodingConst = 1) {
      const len = prefix.length;
      let chk = 1;
      for (let i = 0; i < len; i++) {
        const c = prefix.charCodeAt(i);
        if (c < 33 || c > 126)
          throw new Error(`Invalid prefix (${prefix})`);
        chk = bech32Polymod2(chk) ^ c >> 5;
      }
      chk = bech32Polymod2(chk);
      for (let i = 0; i < len; i++)
        chk = bech32Polymod2(chk) ^ prefix.charCodeAt(i) & 31;
      for (let v of words)
        chk = bech32Polymod2(chk) ^ v;
      for (let i = 0; i < 6; i++)
        chk = bech32Polymod2(chk);
      chk ^= encodingConst;
      return BECH_ALPHABET2.encode(convertRadix22([chk % powers2[30]], 30, 5, false));
    }
    // @__NO_SIDE_EFFECTS__
    function genBech322(encoding) {
      const ENCODING_CONST = encoding === "bech32" ? 1 : 734539939;
      const _words = /* @__PURE__ */ radix22(5);
      const fromWords = _words.decode;
      const toWords = _words.encode;
      const fromWordsUnsafe = unsafeWrapper2(fromWords);
      function encode(prefix, words, limit = 90) {
        astr2("bech32.encode prefix", prefix);
        if (isBytes4(words))
          words = Array.from(words);
        anumArr2("bech32.encode", words);
        const plen = prefix.length;
        if (plen === 0)
          throw new TypeError(`Invalid prefix length ${plen}`);
        const actualLength = plen + 7 + words.length;
        if (limit !== false && actualLength > limit)
          throw new TypeError(`Length ${actualLength} exceeds limit ${limit}`);
        const lowered = prefix.toLowerCase();
        const sum = bechChecksum2(lowered, words, ENCODING_CONST);
        return `${lowered}1${BECH_ALPHABET2.encode(words)}${sum}`;
      }
      function decode(str2, limit = 90) {
        astr2("bech32.decode input", str2);
        const slen = str2.length;
        if (slen < 8 || limit !== false && slen > limit)
          throw new TypeError(`invalid string length: ${slen} (${str2}). Expected (8..${limit})`);
        const lowered = str2.toLowerCase();
        if (str2 !== lowered && str2 !== str2.toUpperCase())
          throw new Error(`String must be lowercase or uppercase`);
        const sepIndex = lowered.lastIndexOf("1");
        if (sepIndex === 0 || sepIndex === -1)
          throw new Error(`Letter "1" must be present between prefix and data only`);
        const prefix = lowered.slice(0, sepIndex);
        const data = lowered.slice(sepIndex + 1);
        if (data.length < 6)
          throw new Error("Data must be at least 6 characters long");
        const words = BECH_ALPHABET2.decode(data).slice(0, -6);
        const sum = bechChecksum2(prefix, words, ENCODING_CONST);
        if (!data.endsWith(sum))
          throw new Error(`Invalid checksum in ${str2}: expected "${sum}"`);
        return { prefix, words };
      }
      const decodeUnsafe = unsafeWrapper2(decode);
      function decodeToBytes(str2) {
        const { prefix, words } = decode(str2, false);
        return { prefix, words, bytes: fromWords(words) };
      }
      function encodeFromBytes(prefix, bytes2) {
        return encode(prefix, toWords(bytes2));
      }
      return {
        encode,
        decode,
        encodeFromBytes,
        decodeToBytes,
        decodeUnsafe,
        fromWords,
        fromWordsUnsafe,
        toWords
      };
    }
    exports.bech32 = /* @__PURE__ */ genBech322("bech32");
    exports.bech32m = /* @__PURE__ */ genBech322("bech32m");
    exports.utf8 = {
      encode: (data) => new TextDecoder().decode(data),
      decode: (str2) => new TextEncoder().encode(str2)
    };
    var hasHexBuiltin2 = /* @__PURE__ */ (() => typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function")();
    var hexBuiltin2 = {
      encode(data) {
        abytes4(data);
        return data.toHex();
      },
      decode(s) {
        astr2("hex", s);
        return Uint8Array.fromHex(s);
      }
    };
    exports.hex = hasHexBuiltin2 ? hexBuiltin2 : /* @__PURE__ */ chain2(/* @__PURE__ */ radix22(4), /* @__PURE__ */ alphabet2("0123456789abcdef"), /* @__PURE__ */ join2(""), /* @__PURE__ */ normalize2((s) => {
      if (typeof s !== "string" || s.length % 2 !== 0)
        throw new TypeError(`hex.decode: expected string, got ${typeof s} with length ${s.length}`);
      return s.toLowerCase();
    }));
    var CODERS2 = {
      utf8: exports.utf8,
      hex: exports.hex,
      base16: exports.base16,
      base32: exports.base32,
      base64: exports.base64,
      base64url: exports.base64url,
      base58: exports.base58,
      base58xmr: exports.base58xmr
    };
    var coderTypeError2 = "Invalid encoding type. Available types: utf8, hex, base16, base32, base64, base64url, base58, base58xmr";
    var bytesToString2 = (type, bytes2) => {
      if (typeof type !== "string" || !CODERS2.hasOwnProperty(type))
        throw new TypeError(coderTypeError2);
      if (!isBytes4(bytes2))
        throw new TypeError("bytesToString() expects Uint8Array");
      return CODERS2[type].encode(bytes2);
    };
    exports.bytesToString = bytesToString2;
    exports.str = exports.bytesToString;
    var stringToBytes2 = (type, str2) => {
      if (!CODERS2.hasOwnProperty(type))
        throw new TypeError(coderTypeError2);
      if (typeof str2 !== "string")
        throw new TypeError("stringToBytes() expects string");
      return CODERS2[type].decode(str2);
    };
    exports.stringToBytes = stringToBytes2;
    exports.bytes = exports.stringToBytes;
  }
});

// node_modules/valibot/dist/index.cjs
var require_dist = __commonJS({
  "node_modules/valibot/dist/index.cjs"(exports) {
    var store$4;
    function setGlobalConfig(config$1) {
      store$4 = {
        ...store$4,
        ...config$1
      };
    }
    // @__NO_SIDE_EFFECTS__
    function getGlobalConfig(config$1) {
      return {
        lang: config$1?.lang ?? store$4?.lang,
        message: config$1?.message,
        abortEarly: config$1?.abortEarly ?? store$4?.abortEarly,
        abortPipeEarly: config$1?.abortPipeEarly ?? store$4?.abortPipeEarly
      };
    }
    function deleteGlobalConfig() {
      store$4 = void 0;
    }
    var store$3;
    function setGlobalMessage(message$1, lang) {
      if (!store$3) store$3 = /* @__PURE__ */ new Map();
      store$3.set(lang, message$1);
    }
    // @__NO_SIDE_EFFECTS__
    function getGlobalMessage(lang) {
      return store$3?.get(lang);
    }
    function deleteGlobalMessage(lang) {
      store$3?.delete(lang);
    }
    var store$2;
    function setSchemaMessage(message$1, lang) {
      if (!store$2) store$2 = /* @__PURE__ */ new Map();
      store$2.set(lang, message$1);
    }
    // @__NO_SIDE_EFFECTS__
    function getSchemaMessage(lang) {
      return store$2?.get(lang);
    }
    function deleteSchemaMessage(lang) {
      store$2?.delete(lang);
    }
    var store$1;
    function setSpecificMessage(reference, message$1, lang) {
      if (!store$1) store$1 = /* @__PURE__ */ new Map();
      if (!store$1.get(reference)) store$1.set(reference, /* @__PURE__ */ new Map());
      store$1.get(reference).set(lang, message$1);
    }
    // @__NO_SIDE_EFFECTS__
    function getSpecificMessage(reference, lang) {
      return store$1?.get(reference)?.get(lang);
    }
    function deleteSpecificMessage(reference, lang) {
      store$1?.get(reference)?.delete(lang);
    }
    // @__NO_SIDE_EFFECTS__
    function _stringify(input) {
      const type = typeof input;
      if (type === "string") return `"${input}"`;
      if (type === "number" || type === "bigint" || type === "boolean") return `${input}`;
      if (type === "object" || type === "function") return (input && Object.getPrototypeOf(input)?.constructor?.name) ?? "null";
      return type;
    }
    function _addIssue(context, label, dataset, config$1, other) {
      const input = other && "input" in other ? other.input : dataset.value;
      const expected = other?.expected ?? context.expects ?? null;
      const received = other?.received ?? /* @__PURE__ */ _stringify(input);
      const issue = {
        kind: context.kind,
        type: context.type,
        input,
        expected,
        received,
        message: `Invalid ${label}: ${expected ? `Expected ${expected} but r` : "R"}eceived ${received}`,
        requirement: context.requirement,
        path: other?.path,
        issues: other?.issues,
        lang: config$1.lang,
        abortEarly: config$1.abortEarly,
        abortPipeEarly: config$1.abortPipeEarly
      };
      const isSchema = context.kind === "schema";
      const message$1 = other?.message ?? context.message ?? /* @__PURE__ */ getSpecificMessage(context.reference, issue.lang) ?? (isSchema ? /* @__PURE__ */ getSchemaMessage(issue.lang) : null) ?? config$1.message ?? /* @__PURE__ */ getGlobalMessage(issue.lang);
      if (message$1 !== void 0) issue.message = typeof message$1 === "function" ? message$1(issue) : message$1;
      if (isSchema) dataset.typed = false;
      if (dataset.issues) dataset.issues.push(issue);
      else dataset.issues = [issue];
    }
    // @__NO_SIDE_EFFECTS__
    function _cloneDataset(dataset) {
      return {
        typed: dataset.typed,
        value: dataset.value,
        issues: dataset.issues && [...dataset.issues]
      };
    }
    var textEncoder;
    // @__NO_SIDE_EFFECTS__
    function _getByteCount(input) {
      if (!textEncoder) textEncoder = new TextEncoder();
      return textEncoder.encode(input).length;
    }
    var segmenter;
    // @__NO_SIDE_EFFECTS__
    function _getGraphemeCount(input) {
      if (!segmenter) segmenter = new Intl.Segmenter();
      const segments = segmenter.segment(input);
      let count = 0;
      for (const _ of segments) count++;
      return count;
    }
    // @__NO_SIDE_EFFECTS__
    function _getLastMetadata(schema, type) {
      if ("pipe" in schema) {
        const nestedSchemas = [];
        for (let index = schema.pipe.length - 1; index >= 0; index--) {
          const item = schema.pipe[index];
          if (item.kind === "schema" && "pipe" in item) nestedSchemas.push(item);
          else if (item.kind === "metadata" && item.type === type) return item[type];
        }
        for (const nestedSchema of nestedSchemas) {
          const result = /* @__PURE__ */ _getLastMetadata(nestedSchema, type);
          if (result !== void 0) return result;
        }
      }
    }
    // @__NO_SIDE_EFFECTS__
    function _getStandardProps(context) {
      return {
        version: 1,
        vendor: "valibot",
        validate(value$1) {
          return context["~run"]({ value: value$1 }, /* @__PURE__ */ getGlobalConfig());
        }
      };
    }
    var store;
    // @__NO_SIDE_EFFECTS__
    function _getWordCount(locales, input) {
      if (!store) store = /* @__PURE__ */ new Map();
      if (!store.get(locales)) store.set(locales, new Intl.Segmenter(locales, { granularity: "word" }));
      const segments = store.get(locales).segment(input);
      let count = 0;
      for (const segment of segments) if (segment.isWordLike) count++;
      return count;
    }
    var NON_DIGIT_REGEX = /\D/gu;
    // @__NO_SIDE_EFFECTS__
    function _isLuhnAlgo(input) {
      const number$1 = input.replace(NON_DIGIT_REGEX, "");
      let length$1 = number$1.length;
      let bit = 1;
      let sum = 0;
      while (length$1) {
        const value$1 = +number$1[--length$1];
        bit ^= 1;
        sum += bit ? [
          0,
          2,
          4,
          6,
          8,
          1,
          3,
          5,
          7,
          9
        ][value$1] : value$1;
      }
      return sum % 10 === 0;
    }
    // @__NO_SIDE_EFFECTS__
    function _isValidObjectKey(object$1, key) {
      return Object.hasOwn(object$1, key) && key !== "__proto__" && key !== "prototype" && key !== "constructor";
    }
    // @__NO_SIDE_EFFECTS__
    function _joinExpects(values$1, separator) {
      const list = [...new Set(values$1)];
      if (list.length > 1) return `(${list.join(` ${separator} `)})`;
      return list[0] ?? "never";
    }
    // @__NO_SIDE_EFFECTS__
    function entriesFromList(list, schema) {
      const entries$1 = {};
      for (const key of list) entries$1[key] = schema;
      return entries$1;
    }
    // @__NO_SIDE_EFFECTS__
    function entriesFromObjects(schemas) {
      const entries$1 = {};
      for (const schema of schemas) Object.assign(entries$1, schema.entries);
      return entries$1;
    }
    // @__NO_SIDE_EFFECTS__
    function getDotPath(issue) {
      if (issue.path) {
        let key = "";
        for (const item of issue.path) if (typeof item.key === "string" || typeof item.key === "number") if (key) key += `.${item.key}`;
        else key += item.key;
        else return null;
        return key;
      }
      return null;
    }
    // @__NO_SIDE_EFFECTS__
    function isOfKind(kind, object$1) {
      return object$1.kind === kind;
    }
    // @__NO_SIDE_EFFECTS__
    function isOfType(type, object$1) {
      return object$1.type === type;
    }
    // @__NO_SIDE_EFFECTS__
    function isValiError(error) {
      return error instanceof ValiError;
    }
    var ValiError = class extends Error {
      /**
      * Creates a Valibot error with useful information.
      *
      * @param issues The error issues.
      */
      constructor(issues) {
        super(issues[0].message);
        this.name = "ValiError";
        this.issues = issues;
      }
    };
    // @__NO_SIDE_EFFECTS__
    function args(schema) {
      return {
        kind: "transformation",
        type: "args",
        reference: args,
        async: false,
        schema,
        "~run"(dataset, config$1) {
          const func = dataset.value;
          dataset.value = (...args_) => {
            const argsDataset = this.schema["~run"]({ value: args_ }, config$1);
            if (argsDataset.issues) throw new ValiError(argsDataset.issues);
            return func(...argsDataset.value);
          };
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function argsAsync(schema) {
      return {
        kind: "transformation",
        type: "args",
        reference: argsAsync,
        async: false,
        schema,
        "~run"(dataset, config$1) {
          const func = dataset.value;
          dataset.value = async (...args$1) => {
            const argsDataset = await schema["~run"]({ value: args$1 }, config$1);
            if (argsDataset.issues) throw new ValiError(argsDataset.issues);
            return func(...argsDataset.value);
          };
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function awaitAsync() {
      return {
        kind: "transformation",
        type: "await",
        reference: awaitAsync,
        async: true,
        async "~run"(dataset) {
          dataset.value = await dataset.value;
          return dataset;
        }
      };
    }
    var BASE64_REGEX = /^(?:[\da-z+/]{4})*(?:[\da-z+/]{2}==|[\da-z+/]{3}=)?$/iu;
    var BIC_REGEX = /^[A-Z]{6}(?!00)[\dA-Z]{2}(?:[\dA-Z]{3})?$/u;
    var CUID2_REGEX = /^[a-z][\da-z]*$/u;
    var DECIMAL_REGEX = /^[+-]?(?:\d*\.)?\d+$/u;
    var DIGITS_REGEX = /^\d+$/u;
    var DOMAIN_REGEX = /^(?=.{1,253}$)(?:(?![Xx][Nn]--)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/u;
    var EMAIL_REGEX = /^[\w+-]+(?:\.[\w+-]+)*@[\da-z]+(?:[.-][\da-z]+)*\.[a-z]{2,}$/iu;
    var EMOJI_REGEX = /^(?:[\u{1F1E6}-\u{1F1FF}]{2}|\u{1F3F4}[\u{E0061}-\u{E007A}]{2}[\u{E0030}-\u{E0039}\u{E0061}-\u{E007A}]{1,3}\u{E007F}|(?:\p{Emoji}\uFE0F\u20E3?|\p{Emoji_Modifier_Base}\p{Emoji_Modifier}?|(?![\p{Emoji_Modifier_Base}\u{1F1E6}-\u{1F1FF}])\p{Emoji_Presentation})(?:\u200D(?:\p{Emoji}\uFE0F\u20E3?|\p{Emoji_Modifier_Base}\p{Emoji_Modifier}?|(?![\p{Emoji_Modifier_Base}\u{1F1E6}-\u{1F1FF}])\p{Emoji_Presentation}))*)+$/u;
    var HEXADECIMAL_REGEX = /^(?:0[hx])?[\da-fA-F]+$/u;
    var HEX_COLOR_REGEX = /^#(?:[\da-fA-F]{3,4}|[\da-fA-F]{6}|[\da-fA-F]{8})$/u;
    var IMEI_REGEX = /^\d{15}$|^\d{2}-\d{6}-\d{6}-\d$/u;
    var IPV4_REGEX = /^(?:(?:[1-9]|1\d|2[0-4])?\d|25[0-5])(?:\.(?:(?:[1-9]|1\d|2[0-4])?\d|25[0-5])){3}$/u;
    var IPV6_REGEX = /^(?:(?:[\da-f]{1,4}:){7}[\da-f]{1,4}|(?:[\da-f]{1,4}:){1,7}:|(?:[\da-f]{1,4}:){1,6}:[\da-f]{1,4}|(?:[\da-f]{1,4}:){1,5}(?::[\da-f]{1,4}){1,2}|(?:[\da-f]{1,4}:){1,4}(?::[\da-f]{1,4}){1,3}|(?:[\da-f]{1,4}:){1,3}(?::[\da-f]{1,4}){1,4}|(?:[\da-f]{1,4}:){1,2}(?::[\da-f]{1,4}){1,5}|[\da-f]{1,4}:(?::[\da-f]{1,4}){1,6}|:(?:(?::[\da-f]{1,4}){1,7}|:)|fe80:(?::[\da-f]{0,4}){0,4}%[\da-z]+|::(?:f{4}(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)|(?:[\da-f]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d))$/iu;
    var IP_REGEX = /^(?:(?:[1-9]|1\d|2[0-4])?\d|25[0-5])(?:\.(?:(?:[1-9]|1\d|2[0-4])?\d|25[0-5])){3}$|^(?:(?:[\da-f]{1,4}:){7}[\da-f]{1,4}|(?:[\da-f]{1,4}:){1,7}:|(?:[\da-f]{1,4}:){1,6}:[\da-f]{1,4}|(?:[\da-f]{1,4}:){1,5}(?::[\da-f]{1,4}){1,2}|(?:[\da-f]{1,4}:){1,4}(?::[\da-f]{1,4}){1,3}|(?:[\da-f]{1,4}:){1,3}(?::[\da-f]{1,4}){1,4}|(?:[\da-f]{1,4}:){1,2}(?::[\da-f]{1,4}){1,5}|[\da-f]{1,4}:(?::[\da-f]{1,4}){1,6}|:(?:(?::[\da-f]{1,4}){1,7}|:)|fe80:(?::[\da-f]{0,4}){0,4}%[\da-z]+|::(?:f{4}(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)|(?:[\da-f]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d))$/iu;
    var ISO_DATE_REGEX = /^\d{4}-(?:0[1-9]|1[0-2])-(?:[12]\d|0[1-9]|3[01])$/u;
    var ISO_DATE_TIME_REGEX = /^\d{4}-(?:0[1-9]|1[0-2])-(?:[12]\d|0[1-9]|3[01])[T ](?:0\d|1\d|2[0-3]):[0-5]\d$/u;
    var ISO_TIME_REGEX = /^(?:0\d|1\d|2[0-3]):[0-5]\d$/u;
    var ISO_TIME_SECOND_REGEX = /^(?:0\d|1\d|2[0-3])(?::[0-5]\d){2}$/u;
    var ISO_TIMESTAMP_REGEX = /^\d{4}-(?:0[1-9]|1[0-2])-(?:[12]\d|0[1-9]|3[01])[T ](?:0\d|1\d|2[0-3])(?::[0-5]\d){2}(?:\.\d{1,9})?(?:Z| ?[+-](?:0\d|1\d|2[0-3])(?::?[0-5]\d)?)$/u;
    var ISO_WEEK_REGEX = /^\d{4}-W(?:0[1-9]|[1-4]\d|5[0-3])$/u;
    var JWS_COMPACT_REGEX = /^(?:[\w-]{2,3}|(?:[\w-]{4})+(?:[\w-]{2,3})?)\.(?:[\w-]{2,3}|(?:[\w-]{4})+(?:[\w-]{2,3})?)?\.(?:[\w-]{2,3}|(?:[\w-]{4})+(?:[\w-]{2,3})?)?$/u;
    var ISRC_REGEX = /^(?:[A-Z]{2}[A-Z\d]{3}\d{7}|[A-Z]{2}-[A-Z\d]{3}-\d{2}-\d{5})$/u;
    var MAC48_REGEX = /^(?:[\da-fA-F]{2}:){5}[\da-fA-F]{2}$|^(?:[\da-fA-F]{2}-){5}[\da-fA-F]{2}$|^(?:[\da-fA-F]{4}\.){2}[\da-fA-F]{4}$/u;
    var MAC64_REGEX = /^(?:[\da-fA-F]{2}:){7}[\da-fA-F]{2}$|^(?:[\da-fA-F]{2}-){7}[\da-fA-F]{2}$|^(?:[\da-fA-F]{4}\.){3}[\da-fA-F]{4}$|^(?:[\da-fA-F]{4}:){3}[\da-fA-F]{4}$/u;
    var MAC_REGEX = /^(?:[\da-fA-F]{2}:){5}[\da-fA-F]{2}$|^(?:[\da-fA-F]{2}-){5}[\da-fA-F]{2}$|^(?:[\da-fA-F]{4}\.){2}[\da-fA-F]{4}$|^(?:[\da-fA-F]{2}:){7}[\da-fA-F]{2}$|^(?:[\da-fA-F]{2}-){7}[\da-fA-F]{2}$|^(?:[\da-fA-F]{4}\.){3}[\da-fA-F]{4}$|^(?:[\da-fA-F]{4}:){3}[\da-fA-F]{4}$/u;
    var NANO_ID_REGEX = /^[\w-]+$/u;
    var OCTAL_REGEX = /^(?:0o)?[0-7]+$/u;
    var RFC_EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    var SLUG_REGEX = /^[\da-z]+(?:[-_][\da-z]+)*$/u;
    var ULID_REGEX = /^[\da-hjkmnp-tv-zA-HJKMNP-TV-Z]{26}$/u;
    var UUID_REGEX = /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/iu;
    // @__NO_SIDE_EFFECTS__
    function base642(message$1) {
      return {
        kind: "validation",
        type: "base64",
        reference: base642,
        async: false,
        expects: null,
        requirement: BASE64_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "Base64", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function bic(message$1) {
      return {
        kind: "validation",
        type: "bic",
        reference: bic,
        async: false,
        expects: null,
        requirement: BIC_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "BIC", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function brand(name) {
      return {
        kind: "transformation",
        type: "brand",
        reference: brand,
        async: false,
        name,
        "~run"(dataset) {
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function bytes2(requirement, message$1) {
      return {
        kind: "validation",
        type: "bytes",
        reference: bytes2,
        async: false,
        expects: `${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) {
            const length$1 = /* @__PURE__ */ _getByteCount(dataset.value);
            if (length$1 !== this.requirement) _addIssue(this, "bytes", dataset, config$1, { received: `${length$1}` });
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function check(requirement, message$1) {
      return {
        kind: "validation",
        type: "check",
        reference: check,
        async: false,
        expects: null,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement(dataset.value)) _addIssue(this, "input", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function checkAsync(requirement, message$1) {
      return {
        kind: "validation",
        type: "check",
        reference: checkAsync,
        async: true,
        expects: null,
        requirement,
        message: message$1,
        async "~run"(dataset, config$1) {
          if (dataset.typed && !await this.requirement(dataset.value)) _addIssue(this, "input", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function checkItems(requirement, message$1) {
      return {
        kind: "validation",
        type: "check_items",
        reference: checkItems,
        async: false,
        expects: null,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) for (let index = 0; index < dataset.value.length; index++) {
            const item = dataset.value[index];
            if (!this.requirement(item, index, dataset.value)) _addIssue(this, "item", dataset, config$1, {
              input: item,
              path: [{
                type: "array",
                origin: "value",
                input: dataset.value,
                key: index,
                value: item
              }]
            });
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function checkItemsAsync(requirement, message$1) {
      return {
        kind: "validation",
        type: "check_items",
        reference: checkItemsAsync,
        async: true,
        expects: null,
        requirement,
        message: message$1,
        async "~run"(dataset, config$1) {
          if (dataset.typed) {
            const requirementResults = await Promise.all(dataset.value.map(this.requirement));
            for (let index = 0; index < dataset.value.length; index++) if (!requirementResults[index]) {
              const item = dataset.value[index];
              _addIssue(this, "item", dataset, config$1, {
                input: item,
                path: [{
                  type: "array",
                  origin: "value",
                  input: dataset.value,
                  key: index,
                  value: item
                }]
              });
            }
          }
          return dataset;
        }
      };
    }
    var CREDIT_CARD_REGEX = /^(?:\d{13,19}|\d{4}(?: \d{3,6}){2,4}|\d{4}(?:-\d{3,6}){2,4})$/u;
    var SANITIZE_REGEX = /[- ]/gu;
    var PROVIDER_REGEX_LIST = [
      /^3[47]\d{13}$/u,
      /^3(?:0[0-5]|[68]\d)\d{11,13}$/u,
      /^6(?:011|5\d{2})\d{12,15}$/u,
      /^(?:2131|1800|35\d{3})\d{11}$/u,
      /^5[1-5]\d{2}|(?:222\d|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)\d{12}$/u,
      /^(?:6[27]\d{14,17}|81\d{14,17})$/u,
      /^4\d{12}(?:\d{3,6})?$/u
    ];
    // @__NO_SIDE_EFFECTS__
    function creditCard(message$1) {
      return {
        kind: "validation",
        type: "credit_card",
        reference: creditCard,
        async: false,
        expects: null,
        requirement(input) {
          let sanitized;
          return CREDIT_CARD_REGEX.test(input) && (sanitized = input.replace(SANITIZE_REGEX, "")) && PROVIDER_REGEX_LIST.some((regex$1) => regex$1.test(sanitized)) && /* @__PURE__ */ _isLuhnAlgo(sanitized);
        },
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement(dataset.value)) _addIssue(this, "credit card", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function cuid2(message$1) {
      return {
        kind: "validation",
        type: "cuid2",
        reference: cuid2,
        async: false,
        expects: null,
        requirement: CUID2_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "Cuid2", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function decimal(message$1) {
      return {
        kind: "validation",
        type: "decimal",
        reference: decimal,
        async: false,
        expects: null,
        requirement: DECIMAL_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "decimal", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function description(description_) {
      return {
        kind: "metadata",
        type: "description",
        reference: description,
        description: description_
      };
    }
    // @__NO_SIDE_EFFECTS__
    function digits(message$1) {
      return {
        kind: "validation",
        type: "digits",
        reference: digits,
        async: false,
        expects: null,
        requirement: DIGITS_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "digits", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function domain(message$1) {
      return {
        kind: "validation",
        type: "domain",
        reference: domain,
        expects: null,
        async: false,
        requirement: DOMAIN_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "domain", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function email(message$1) {
      return {
        kind: "validation",
        type: "email",
        reference: email,
        expects: null,
        async: false,
        requirement: EMAIL_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "email", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function emoji(message$1) {
      return {
        kind: "validation",
        type: "emoji",
        reference: emoji,
        async: false,
        expects: null,
        requirement: EMOJI_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "emoji", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function empty(message$1) {
      return {
        kind: "validation",
        type: "empty",
        reference: empty,
        async: false,
        expects: "0",
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && dataset.value.length > 0) _addIssue(this, "length", dataset, config$1, { received: `${dataset.value.length}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function endsWith(requirement, message$1) {
      return {
        kind: "validation",
        type: "ends_with",
        reference: endsWith,
        async: false,
        expects: `"${requirement}"`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !dataset.value.endsWith(this.requirement)) _addIssue(this, "end", dataset, config$1, { received: `"${dataset.value.slice(-this.requirement.length)}"` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function entries(requirement, message$1) {
      return {
        kind: "validation",
        type: "entries",
        reference: entries,
        async: false,
        expects: `${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (!dataset.typed) return dataset;
          const count = Object.keys(dataset.value).length;
          if (dataset.typed && count !== this.requirement) _addIssue(this, "entries", dataset, config$1, { received: `${count}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function everyItem(requirement, message$1) {
      return {
        kind: "validation",
        type: "every_item",
        reference: everyItem,
        async: false,
        expects: null,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !dataset.value.every(this.requirement)) _addIssue(this, "item", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function examples(examples_) {
      return {
        kind: "metadata",
        type: "examples",
        reference: examples,
        examples: examples_
      };
    }
    // @__NO_SIDE_EFFECTS__
    function excludes(requirement, message$1) {
      const received = /* @__PURE__ */ _stringify(requirement);
      return {
        kind: "validation",
        type: "excludes",
        reference: excludes,
        async: false,
        expects: `!${received}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && dataset.value.includes(this.requirement)) _addIssue(this, "content", dataset, config$1, { received });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function filterItems(operation) {
      return {
        kind: "transformation",
        type: "filter_items",
        reference: filterItems,
        async: false,
        operation,
        "~run"(dataset) {
          dataset.value = dataset.value.filter(this.operation);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function findItem(operation) {
      return {
        kind: "transformation",
        type: "find_item",
        reference: findItem,
        async: false,
        operation,
        "~run"(dataset) {
          dataset.value = dataset.value.find(this.operation);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function finite(message$1) {
      return {
        kind: "validation",
        type: "finite",
        reference: finite,
        async: false,
        expects: null,
        requirement: Number.isFinite,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement(dataset.value)) _addIssue(this, "finite", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function flavor(name) {
      return {
        kind: "transformation",
        type: "flavor",
        reference: flavor,
        async: false,
        name,
        "~run"(dataset) {
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function graphemes(requirement, message$1) {
      return {
        kind: "validation",
        type: "graphemes",
        reference: graphemes,
        async: false,
        expects: `${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) {
            const count = /* @__PURE__ */ _getGraphemeCount(dataset.value);
            if (count !== this.requirement) _addIssue(this, "graphemes", dataset, config$1, { received: `${count}` });
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function gtValue(requirement, message$1) {
      return {
        kind: "validation",
        type: "gt_value",
        reference: gtValue,
        async: false,
        expects: `>${requirement instanceof Date ? requirement.toJSON() : /* @__PURE__ */ _stringify(requirement)}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !(dataset.value > this.requirement)) _addIssue(this, "value", dataset, config$1, { received: dataset.value instanceof Date ? dataset.value.toJSON() : /* @__PURE__ */ _stringify(dataset.value) });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function guard(requirement, message$1) {
      return {
        kind: "transformation",
        type: "guard",
        reference: guard,
        async: false,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement(dataset.value)) {
            _addIssue(this, "input", dataset, config$1);
            dataset.typed = false;
          }
          return dataset;
        }
      };
    }
    var HASH_LENGTHS = {
      md4: 32,
      md5: 32,
      sha1: 40,
      sha256: 64,
      sha384: 96,
      sha512: 128,
      ripemd128: 32,
      ripemd160: 40,
      tiger128: 32,
      tiger160: 40,
      tiger192: 48,
      crc32: 8,
      crc32b: 8,
      adler32: 8
    };
    // @__NO_SIDE_EFFECTS__
    function hash2(types, message$1) {
      return {
        kind: "validation",
        type: "hash",
        reference: hash2,
        expects: null,
        async: false,
        requirement: RegExp(types.map((type) => `^[a-fA-F0-9]{${HASH_LENGTHS[type]}}$`).join("|"), "u"),
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "hash", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function hexadecimal(message$1) {
      return {
        kind: "validation",
        type: "hexadecimal",
        reference: hexadecimal,
        async: false,
        expects: null,
        requirement: HEXADECIMAL_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "hexadecimal", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function hexColor(message$1) {
      return {
        kind: "validation",
        type: "hex_color",
        reference: hexColor,
        async: false,
        expects: null,
        requirement: HEX_COLOR_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "hex color", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function imei(message$1) {
      return {
        kind: "validation",
        type: "imei",
        reference: imei,
        async: false,
        expects: null,
        requirement(input) {
          return IMEI_REGEX.test(input) && /* @__PURE__ */ _isLuhnAlgo(input);
        },
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement(dataset.value)) _addIssue(this, "IMEI", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function includes(requirement, message$1) {
      const expects = /* @__PURE__ */ _stringify(requirement);
      return {
        kind: "validation",
        type: "includes",
        reference: includes,
        async: false,
        expects,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !dataset.value.includes(this.requirement)) _addIssue(this, "content", dataset, config$1, { received: `!${expects}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function integer(message$1) {
      return {
        kind: "validation",
        type: "integer",
        reference: integer,
        async: false,
        expects: null,
        requirement: Number.isInteger,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement(dataset.value)) _addIssue(this, "integer", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function ip(message$1) {
      return {
        kind: "validation",
        type: "ip",
        reference: ip,
        async: false,
        expects: null,
        requirement: IP_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "IP", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function ipv4(message$1) {
      return {
        kind: "validation",
        type: "ipv4",
        reference: ipv4,
        async: false,
        expects: null,
        requirement: IPV4_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "IPv4", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function ipv6(message$1) {
      return {
        kind: "validation",
        type: "ipv6",
        reference: ipv6,
        async: false,
        expects: null,
        requirement: IPV6_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "IPv6", dataset, config$1);
          return dataset;
        }
      };
    }
    function _isIsbn10(input) {
      const digits$1 = input.split("").map((c) => c === "X" ? 10 : parseInt(c));
      let sum = 0;
      for (let i = 0; i < 10; i++) sum += digits$1[i] * (10 - i);
      return sum % 11 === 0;
    }
    function _isIsbn13(input) {
      const digits$1 = input.split("").map((c) => parseInt(c));
      let sum = 0;
      for (let i = 0; i < 13; i++) sum += digits$1[i] * (i % 2 === 0 ? 1 : 3);
      return sum % 10 === 0;
    }
    var ISBN_SEPARATOR_REGEX = /[- ]/gu;
    var ISBN_10_DETECTION_REGEX = /^\d{9}[\dX]$/u;
    var ISBN_13_DETECTION_REGEX = /^\d{13}$/u;
    // @__NO_SIDE_EFFECTS__
    function isbn(message$1) {
      return {
        kind: "validation",
        type: "isbn",
        reference: isbn,
        async: false,
        expects: null,
        requirement(input) {
          const replacedInput = input.replace(ISBN_SEPARATOR_REGEX, "");
          if (ISBN_10_DETECTION_REGEX.test(replacedInput)) return _isIsbn10(replacedInput);
          else if (ISBN_13_DETECTION_REGEX.test(replacedInput)) return _isIsbn13(replacedInput);
          return false;
        },
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement(dataset.value)) _addIssue(this, "ISBN", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function isrc(message$1) {
      return {
        kind: "validation",
        type: "isrc",
        reference: isrc,
        async: false,
        expects: null,
        requirement: ISRC_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "ISRC", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function isoDate(message$1) {
      return {
        kind: "validation",
        type: "iso_date",
        reference: isoDate,
        async: false,
        expects: null,
        requirement: ISO_DATE_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "date", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function isoDateTime(message$1) {
      return {
        kind: "validation",
        type: "iso_date_time",
        reference: isoDateTime,
        async: false,
        expects: null,
        requirement: ISO_DATE_TIME_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "date-time", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function isoTime(message$1) {
      return {
        kind: "validation",
        type: "iso_time",
        reference: isoTime,
        async: false,
        expects: null,
        requirement: ISO_TIME_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "time", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function isoTimeSecond(message$1) {
      return {
        kind: "validation",
        type: "iso_time_second",
        reference: isoTimeSecond,
        async: false,
        expects: null,
        requirement: ISO_TIME_SECOND_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "time-second", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function isoTimestamp(message$1) {
      return {
        kind: "validation",
        type: "iso_timestamp",
        reference: isoTimestamp,
        async: false,
        expects: null,
        requirement: ISO_TIMESTAMP_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "timestamp", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function isoWeek(message$1) {
      return {
        kind: "validation",
        type: "iso_week",
        reference: isoWeek,
        async: false,
        expects: null,
        requirement: ISO_WEEK_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "week", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function jwsCompact(message$1) {
      return {
        kind: "validation",
        type: "jws_compact",
        reference: jwsCompact,
        async: false,
        expects: null,
        requirement: JWS_COMPACT_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "JWS compact", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function length(requirement, message$1) {
      return {
        kind: "validation",
        type: "length",
        reference: length,
        async: false,
        expects: `${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && dataset.value.length !== this.requirement) _addIssue(this, "length", dataset, config$1, { received: `${dataset.value.length}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function ltValue(requirement, message$1) {
      return {
        kind: "validation",
        type: "lt_value",
        reference: ltValue,
        async: false,
        expects: `<${requirement instanceof Date ? requirement.toJSON() : /* @__PURE__ */ _stringify(requirement)}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !(dataset.value < this.requirement)) _addIssue(this, "value", dataset, config$1, { received: dataset.value instanceof Date ? dataset.value.toJSON() : /* @__PURE__ */ _stringify(dataset.value) });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function mac(message$1) {
      return {
        kind: "validation",
        type: "mac",
        reference: mac,
        async: false,
        expects: null,
        requirement: MAC_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "MAC", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function mac48(message$1) {
      return {
        kind: "validation",
        type: "mac48",
        reference: mac48,
        async: false,
        expects: null,
        requirement: MAC48_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "48-bit MAC", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function mac64(message$1) {
      return {
        kind: "validation",
        type: "mac64",
        reference: mac64,
        async: false,
        expects: null,
        requirement: MAC64_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "64-bit MAC", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function mapItems(operation) {
      return {
        kind: "transformation",
        type: "map_items",
        reference: mapItems,
        async: false,
        operation,
        "~run"(dataset) {
          dataset.value = dataset.value.map(this.operation);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function maxBytes(requirement, message$1) {
      return {
        kind: "validation",
        type: "max_bytes",
        reference: maxBytes,
        async: false,
        expects: `<=${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) {
            const length$1 = /* @__PURE__ */ _getByteCount(dataset.value);
            if (length$1 > this.requirement) _addIssue(this, "bytes", dataset, config$1, { received: `${length$1}` });
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function maxEntries(requirement, message$1) {
      return {
        kind: "validation",
        type: "max_entries",
        reference: maxEntries,
        async: false,
        expects: `<=${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (!dataset.typed) return dataset;
          const count = Object.keys(dataset.value).length;
          if (dataset.typed && count > this.requirement) _addIssue(this, "entries", dataset, config$1, { received: `${count}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function maxGraphemes(requirement, message$1) {
      return {
        kind: "validation",
        type: "max_graphemes",
        reference: maxGraphemes,
        async: false,
        expects: `<=${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) {
            const count = /* @__PURE__ */ _getGraphemeCount(dataset.value);
            if (count > this.requirement) _addIssue(this, "graphemes", dataset, config$1, { received: `${count}` });
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function maxLength(requirement, message$1) {
      return {
        kind: "validation",
        type: "max_length",
        reference: maxLength,
        async: false,
        expects: `<=${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && dataset.value.length > this.requirement) _addIssue(this, "length", dataset, config$1, { received: `${dataset.value.length}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function maxSize(requirement, message$1) {
      return {
        kind: "validation",
        type: "max_size",
        reference: maxSize,
        async: false,
        expects: `<=${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && dataset.value.size > this.requirement) _addIssue(this, "size", dataset, config$1, { received: `${dataset.value.size}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function maxValue(requirement, message$1) {
      return {
        kind: "validation",
        type: "max_value",
        reference: maxValue,
        async: false,
        expects: `<=${requirement instanceof Date ? requirement.toJSON() : /* @__PURE__ */ _stringify(requirement)}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !(dataset.value <= this.requirement)) _addIssue(this, "value", dataset, config$1, { received: dataset.value instanceof Date ? dataset.value.toJSON() : /* @__PURE__ */ _stringify(dataset.value) });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function maxWords(locales, requirement, message$1) {
      return {
        kind: "validation",
        type: "max_words",
        reference: maxWords,
        async: false,
        expects: `<=${requirement}`,
        locales,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) {
            const count = /* @__PURE__ */ _getWordCount(this.locales, dataset.value);
            if (count > this.requirement) _addIssue(this, "words", dataset, config$1, { received: `${count}` });
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function metadata(metadata_) {
      return {
        kind: "metadata",
        type: "metadata",
        reference: metadata,
        metadata: metadata_
      };
    }
    // @__NO_SIDE_EFFECTS__
    function mimeType(requirement, message$1) {
      return {
        kind: "validation",
        type: "mime_type",
        reference: mimeType,
        async: false,
        expects: /* @__PURE__ */ _joinExpects(requirement.map((option) => `"${option}"`), "|"),
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.includes(dataset.value.type)) _addIssue(this, "MIME type", dataset, config$1, { received: `"${dataset.value.type}"` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function minBytes(requirement, message$1) {
      return {
        kind: "validation",
        type: "min_bytes",
        reference: minBytes,
        async: false,
        expects: `>=${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) {
            const length$1 = /* @__PURE__ */ _getByteCount(dataset.value);
            if (length$1 < this.requirement) _addIssue(this, "bytes", dataset, config$1, { received: `${length$1}` });
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function minEntries(requirement, message$1) {
      return {
        kind: "validation",
        type: "min_entries",
        reference: minEntries,
        async: false,
        expects: `>=${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (!dataset.typed) return dataset;
          const count = Object.keys(dataset.value).length;
          if (dataset.typed && count < this.requirement) _addIssue(this, "entries", dataset, config$1, { received: `${count}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function minGraphemes(requirement, message$1) {
      return {
        kind: "validation",
        type: "min_graphemes",
        reference: minGraphemes,
        async: false,
        expects: `>=${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) {
            const count = /* @__PURE__ */ _getGraphemeCount(dataset.value);
            if (count < this.requirement) _addIssue(this, "graphemes", dataset, config$1, { received: `${count}` });
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function minLength(requirement, message$1) {
      return {
        kind: "validation",
        type: "min_length",
        reference: minLength,
        async: false,
        expects: `>=${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && dataset.value.length < this.requirement) _addIssue(this, "length", dataset, config$1, { received: `${dataset.value.length}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function minSize(requirement, message$1) {
      return {
        kind: "validation",
        type: "min_size",
        reference: minSize,
        async: false,
        expects: `>=${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && dataset.value.size < this.requirement) _addIssue(this, "size", dataset, config$1, { received: `${dataset.value.size}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function minValue(requirement, message$1) {
      return {
        kind: "validation",
        type: "min_value",
        reference: minValue,
        async: false,
        expects: `>=${requirement instanceof Date ? requirement.toJSON() : /* @__PURE__ */ _stringify(requirement)}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !(dataset.value >= this.requirement)) _addIssue(this, "value", dataset, config$1, { received: dataset.value instanceof Date ? dataset.value.toJSON() : /* @__PURE__ */ _stringify(dataset.value) });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function minWords(locales, requirement, message$1) {
      return {
        kind: "validation",
        type: "min_words",
        reference: minWords,
        async: false,
        expects: `>=${requirement}`,
        locales,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) {
            const count = /* @__PURE__ */ _getWordCount(this.locales, dataset.value);
            if (count < this.requirement) _addIssue(this, "words", dataset, config$1, { received: `${count}` });
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function multipleOf(requirement, message$1) {
      return {
        kind: "validation",
        type: "multiple_of",
        reference: multipleOf,
        async: false,
        expects: `%${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && dataset.value % this.requirement != 0) _addIssue(this, "multiple", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nanoid(message$1) {
      return {
        kind: "validation",
        type: "nanoid",
        reference: nanoid,
        async: false,
        expects: null,
        requirement: NANO_ID_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "Nano ID", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nonEmpty(message$1) {
      return {
        kind: "validation",
        type: "non_empty",
        reference: nonEmpty,
        async: false,
        expects: "!0",
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && dataset.value.length === 0) _addIssue(this, "length", dataset, config$1, { received: "0" });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function normalize2(form) {
      return {
        kind: "transformation",
        type: "normalize",
        reference: normalize2,
        async: false,
        form,
        "~run"(dataset) {
          dataset.value = dataset.value.normalize(this.form);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function notBytes(requirement, message$1) {
      return {
        kind: "validation",
        type: "not_bytes",
        reference: notBytes,
        async: false,
        expects: `!${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) {
            const length$1 = /* @__PURE__ */ _getByteCount(dataset.value);
            if (length$1 === this.requirement) _addIssue(this, "bytes", dataset, config$1, { received: `${length$1}` });
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function notEntries(requirement, message$1) {
      return {
        kind: "validation",
        type: "not_entries",
        reference: notEntries,
        async: false,
        expects: `!${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (!dataset.typed) return dataset;
          const count = Object.keys(dataset.value).length;
          if (dataset.typed && count === this.requirement) _addIssue(this, "entries", dataset, config$1, { received: `${count}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function notGraphemes(requirement, message$1) {
      return {
        kind: "validation",
        type: "not_graphemes",
        reference: notGraphemes,
        async: false,
        expects: `!${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) {
            const count = /* @__PURE__ */ _getGraphemeCount(dataset.value);
            if (count === this.requirement) _addIssue(this, "graphemes", dataset, config$1, { received: `${count}` });
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function notLength(requirement, message$1) {
      return {
        kind: "validation",
        type: "not_length",
        reference: notLength,
        async: false,
        expects: `!${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && dataset.value.length === this.requirement) _addIssue(this, "length", dataset, config$1, { received: `${dataset.value.length}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function notSize(requirement, message$1) {
      return {
        kind: "validation",
        type: "not_size",
        reference: notSize,
        async: false,
        expects: `!${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && dataset.value.size === this.requirement) _addIssue(this, "size", dataset, config$1, { received: `${dataset.value.size}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function notValue(requirement, message$1) {
      return {
        kind: "validation",
        type: "not_value",
        reference: notValue,
        async: false,
        expects: requirement instanceof Date ? `!${requirement.toJSON()}` : `!${/* @__PURE__ */ _stringify(requirement)}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && this.requirement <= dataset.value && this.requirement >= dataset.value) _addIssue(this, "value", dataset, config$1, { received: dataset.value instanceof Date ? dataset.value.toJSON() : /* @__PURE__ */ _stringify(dataset.value) });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function notValues(requirement, message$1) {
      return {
        kind: "validation",
        type: "not_values",
        reference: notValues,
        async: false,
        expects: `!${/* @__PURE__ */ _joinExpects(requirement.map((value$1) => value$1 instanceof Date ? value$1.toJSON() : /* @__PURE__ */ _stringify(value$1)), "|")}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && this.requirement.some((value$1) => value$1 <= dataset.value && value$1 >= dataset.value)) _addIssue(this, "value", dataset, config$1, { received: dataset.value instanceof Date ? dataset.value.toJSON() : /* @__PURE__ */ _stringify(dataset.value) });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function notWords(locales, requirement, message$1) {
      return {
        kind: "validation",
        type: "not_words",
        reference: notWords,
        async: false,
        expects: `!${requirement}`,
        locales,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) {
            const count = /* @__PURE__ */ _getWordCount(this.locales, dataset.value);
            if (count === this.requirement) _addIssue(this, "words", dataset, config$1, { received: `${count}` });
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function octal(message$1) {
      return {
        kind: "validation",
        type: "octal",
        reference: octal,
        async: false,
        expects: null,
        requirement: OCTAL_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "octal", dataset, config$1);
          return dataset;
        }
      };
    }
    var TRUTHY = [
      true,
      1,
      "true",
      "1",
      "yes",
      "y",
      "on",
      "enabled"
    ];
    var FALSY = [
      false,
      0,
      "false",
      "0",
      "no",
      "n",
      "off",
      "disabled"
    ];
    // @__NO_SIDE_EFFECTS__
    function parseBoolean(config$1, message$1) {
      const normalize$1 = (v) => typeof v === "string" ? v.toLowerCase() : v;
      const truthyRaw = config$1?.truthy ?? TRUTHY;
      const falsyRaw = config$1?.falsy ?? FALSY;
      const truthy = config$1?.truthy ? config$1.truthy.map(normalize$1) : TRUTHY;
      const falsy = config$1?.falsy ? config$1.falsy.map(normalize$1) : FALSY;
      return {
        kind: "transformation",
        type: "parse_boolean",
        reference: parseBoolean,
        expects: /* @__PURE__ */ _joinExpects([...truthyRaw, ...falsyRaw].map(_stringify), "|"),
        config: config$1,
        message: message$1,
        async: false,
        "~run"(dataset, config$2) {
          const input = normalize$1(dataset.value);
          if (truthy.includes(input)) dataset.value = true;
          else if (falsy.includes(input)) dataset.value = false;
          else {
            _addIssue(this, "boolean", dataset, config$2);
            dataset.typed = false;
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function parseJson(config$1, message$1) {
      return {
        kind: "transformation",
        type: "parse_json",
        reference: parseJson,
        config: config$1,
        message: message$1,
        async: false,
        "~run"(dataset, config$2) {
          try {
            dataset.value = JSON.parse(dataset.value, this.config?.reviver);
          } catch (error) {
            if (error instanceof Error) {
              _addIssue(this, "JSON", dataset, config$2, { received: `"${error.message}"` });
              dataset.typed = false;
            } else throw error;
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function _isPartiallyTyped(dataset, paths) {
      if (dataset.issues) for (const path of paths) for (const issue of dataset.issues) {
        let typed = false;
        const bound = Math.min(path.length, issue.path?.length ?? 0);
        for (let index = 0; index < bound; index++) if (path[index] !== issue.path[index].key && (path[index] !== "$" || issue.path[index].type !== "array")) {
          typed = true;
          break;
        }
        if (!typed) return false;
      }
      return true;
    }
    // @__NO_SIDE_EFFECTS__
    function partialCheck(paths, requirement, message$1) {
      return {
        kind: "validation",
        type: "partial_check",
        reference: partialCheck,
        async: false,
        expects: null,
        paths,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if ((dataset.typed || /* @__PURE__ */ _isPartiallyTyped(dataset, paths)) && !this.requirement(dataset.value)) _addIssue(this, "input", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function partialCheckAsync(paths, requirement, message$1) {
      return {
        kind: "validation",
        type: "partial_check",
        reference: partialCheckAsync,
        async: true,
        expects: null,
        paths,
        requirement,
        message: message$1,
        async "~run"(dataset, config$1) {
          if ((dataset.typed || /* @__PURE__ */ _isPartiallyTyped(dataset, paths)) && !await this.requirement(dataset.value)) _addIssue(this, "input", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function rawCheck(action) {
      return {
        kind: "validation",
        type: "raw_check",
        reference: rawCheck,
        async: false,
        expects: null,
        "~run"(dataset, config$1) {
          action({
            dataset,
            config: config$1,
            addIssue: (info) => _addIssue(this, info?.label ?? "input", dataset, config$1, info)
          });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function rawCheckAsync(action) {
      return {
        kind: "validation",
        type: "raw_check",
        reference: rawCheckAsync,
        async: true,
        expects: null,
        async "~run"(dataset, config$1) {
          await action({
            dataset,
            config: config$1,
            addIssue: (info) => _addIssue(this, info?.label ?? "input", dataset, config$1, info)
          });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function rawTransform(action) {
      return {
        kind: "transformation",
        type: "raw_transform",
        reference: rawTransform,
        async: false,
        "~run"(dataset, config$1) {
          const output = action({
            dataset,
            config: config$1,
            addIssue: (info) => _addIssue(this, info?.label ?? "input", dataset, config$1, info),
            NEVER: null
          });
          if (dataset.issues) dataset.typed = false;
          else dataset.value = output;
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function rawTransformAsync(action) {
      return {
        kind: "transformation",
        type: "raw_transform",
        reference: rawTransformAsync,
        async: true,
        async "~run"(dataset, config$1) {
          const output = await action({
            dataset,
            config: config$1,
            addIssue: (info) => _addIssue(this, info?.label ?? "input", dataset, config$1, info),
            NEVER: null
          });
          if (dataset.issues) dataset.typed = false;
          else dataset.value = output;
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function readonly() {
      return {
        kind: "transformation",
        type: "readonly",
        reference: readonly,
        async: false,
        "~run"(dataset) {
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function reduceItems(operation, initial) {
      return {
        kind: "transformation",
        type: "reduce_items",
        reference: reduceItems,
        async: false,
        operation,
        initial,
        "~run"(dataset) {
          dataset.value = dataset.value.reduce(this.operation, this.initial);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function regex(requirement, message$1) {
      return {
        kind: "validation",
        type: "regex",
        reference: regex,
        async: false,
        expects: `${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "format", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function returns(schema) {
      return {
        kind: "transformation",
        type: "returns",
        reference: returns,
        async: false,
        schema,
        "~run"(dataset, config$1) {
          const func = dataset.value;
          dataset.value = (...args_) => {
            const returnsDataset = this.schema["~run"]({ value: func(...args_) }, config$1);
            if (returnsDataset.issues) throw new ValiError(returnsDataset.issues);
            return returnsDataset.value;
          };
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function returnsAsync(schema) {
      return {
        kind: "transformation",
        type: "returns",
        reference: returnsAsync,
        async: false,
        schema,
        "~run"(dataset, config$1) {
          const func = dataset.value;
          dataset.value = async (...args_) => {
            const returnsDataset = await this.schema["~run"]({ value: await func(...args_) }, config$1);
            if (returnsDataset.issues) throw new ValiError(returnsDataset.issues);
            return returnsDataset.value;
          };
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function rfcEmail(message$1) {
      return {
        kind: "validation",
        type: "rfc_email",
        reference: rfcEmail,
        expects: null,
        async: false,
        requirement: RFC_EMAIL_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "email", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function safeInteger(message$1) {
      return {
        kind: "validation",
        type: "safe_integer",
        reference: safeInteger,
        async: false,
        expects: null,
        requirement: Number.isSafeInteger,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement(dataset.value)) _addIssue(this, "safe integer", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function size(requirement, message$1) {
      return {
        kind: "validation",
        type: "size",
        reference: size,
        async: false,
        expects: `${requirement}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && dataset.value.size !== this.requirement) _addIssue(this, "size", dataset, config$1, { received: `${dataset.value.size}` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function slug(message$1) {
      return {
        kind: "validation",
        type: "slug",
        reference: slug,
        async: false,
        expects: null,
        requirement: SLUG_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "slug", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function someItem(requirement, message$1) {
      return {
        kind: "validation",
        type: "some_item",
        reference: someItem,
        async: false,
        expects: null,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !dataset.value.some(this.requirement)) _addIssue(this, "item", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function sortItems(operation) {
      return {
        kind: "transformation",
        type: "sort_items",
        reference: sortItems,
        async: false,
        operation,
        "~run"(dataset) {
          dataset.value = dataset.value.sort(this.operation);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function startsWith(requirement, message$1) {
      return {
        kind: "validation",
        type: "starts_with",
        reference: startsWith,
        async: false,
        expects: `"${requirement}"`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !dataset.value.startsWith(this.requirement)) _addIssue(this, "start", dataset, config$1, { received: `"${dataset.value.slice(0, this.requirement.length)}"` });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function stringifyJson(config$1, message$1) {
      return {
        kind: "transformation",
        type: "stringify_json",
        reference: stringifyJson,
        message: message$1,
        config: config$1,
        async: false,
        "~run"(dataset, config$2) {
          try {
            const output = JSON.stringify(dataset.value, this.config?.replacer, this.config?.space);
            if (output === void 0) {
              _addIssue(this, "JSON", dataset, config$2);
              dataset.typed = false;
            }
            dataset.value = output;
          } catch (error) {
            if (error instanceof Error) {
              _addIssue(this, "JSON", dataset, config$2, { received: `"${error.message}"` });
              dataset.typed = false;
            } else throw error;
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function title(title_) {
      return {
        kind: "metadata",
        type: "title",
        reference: title,
        title: title_
      };
    }
    // @__NO_SIDE_EFFECTS__
    function toBigint(message$1) {
      return {
        kind: "transformation",
        type: "to_bigint",
        reference: toBigint,
        async: false,
        message: message$1,
        "~run"(dataset, config$1) {
          try {
            dataset.value = BigInt(dataset.value);
          } catch {
            _addIssue(this, "bigint", dataset, config$1);
            dataset.typed = false;
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function toBoolean() {
      return {
        kind: "transformation",
        type: "to_boolean",
        reference: toBoolean,
        async: false,
        "~run"(dataset) {
          dataset.value = Boolean(dataset.value);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function toDate(message$1) {
      return {
        kind: "transformation",
        type: "to_date",
        reference: toDate,
        async: false,
        message: message$1,
        "~run"(dataset, config$1) {
          try {
            dataset.value = new Date(dataset.value);
            if (isNaN(dataset.value)) {
              _addIssue(this, "date", dataset, config$1, { received: '"Invalid Date"' });
              dataset.typed = false;
            }
          } catch {
            _addIssue(this, "date", dataset, config$1);
            dataset.typed = false;
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function toLowerCase() {
      return {
        kind: "transformation",
        type: "to_lower_case",
        reference: toLowerCase,
        async: false,
        "~run"(dataset) {
          dataset.value = dataset.value.toLowerCase();
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function toMaxValue(requirement) {
      return {
        kind: "transformation",
        type: "to_max_value",
        reference: toMaxValue,
        async: false,
        requirement,
        "~run"(dataset) {
          dataset.value = dataset.value > this.requirement ? this.requirement : dataset.value;
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function toMinValue(requirement) {
      return {
        kind: "transformation",
        type: "to_min_value",
        reference: toMinValue,
        async: false,
        requirement,
        "~run"(dataset) {
          dataset.value = dataset.value < this.requirement ? this.requirement : dataset.value;
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function toNumber(message$1) {
      return {
        kind: "transformation",
        type: "to_number",
        reference: toNumber,
        async: false,
        message: message$1,
        "~run"(dataset, config$1) {
          try {
            dataset.value = Number(dataset.value);
            if (isNaN(dataset.value)) {
              _addIssue(this, "number", dataset, config$1);
              dataset.typed = false;
            }
          } catch {
            _addIssue(this, "number", dataset, config$1);
            dataset.typed = false;
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function toString(message$1) {
      return {
        kind: "transformation",
        type: "to_string",
        reference: toString,
        async: false,
        message: message$1,
        "~run"(dataset, config$1) {
          try {
            dataset.value = String(dataset.value);
          } catch {
            _addIssue(this, "string", dataset, config$1);
            dataset.typed = false;
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function toUpperCase() {
      return {
        kind: "transformation",
        type: "to_upper_case",
        reference: toUpperCase,
        async: false,
        "~run"(dataset) {
          dataset.value = dataset.value.toUpperCase();
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function transform(operation) {
      return {
        kind: "transformation",
        type: "transform",
        reference: transform,
        async: false,
        operation,
        "~run"(dataset) {
          dataset.value = this.operation(dataset.value);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function transformAsync(operation) {
      return {
        kind: "transformation",
        type: "transform",
        reference: transformAsync,
        async: true,
        operation,
        async "~run"(dataset) {
          dataset.value = await this.operation(dataset.value);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function trim() {
      return {
        kind: "transformation",
        type: "trim",
        reference: trim,
        async: false,
        "~run"(dataset) {
          dataset.value = dataset.value.trim();
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function trimEnd() {
      return {
        kind: "transformation",
        type: "trim_end",
        reference: trimEnd,
        async: false,
        "~run"(dataset) {
          dataset.value = dataset.value.trimEnd();
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function trimStart() {
      return {
        kind: "transformation",
        type: "trim_start",
        reference: trimStart,
        async: false,
        "~run"(dataset) {
          dataset.value = dataset.value.trimStart();
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function ulid(message$1) {
      return {
        kind: "validation",
        type: "ulid",
        reference: ulid,
        async: false,
        expects: null,
        requirement: ULID_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "ULID", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function url(message$1) {
      return {
        kind: "validation",
        type: "url",
        reference: url,
        async: false,
        expects: null,
        requirement(input) {
          try {
            new URL(input);
            return true;
          } catch {
            return false;
          }
        },
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement(dataset.value)) _addIssue(this, "URL", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function uuid(message$1) {
      return {
        kind: "validation",
        type: "uuid",
        reference: uuid,
        async: false,
        expects: null,
        requirement: UUID_REGEX,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.test(dataset.value)) _addIssue(this, "UUID", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function value(requirement, message$1) {
      return {
        kind: "validation",
        type: "value",
        reference: value,
        async: false,
        expects: requirement instanceof Date ? requirement.toJSON() : /* @__PURE__ */ _stringify(requirement),
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !(this.requirement <= dataset.value && this.requirement >= dataset.value)) _addIssue(this, "value", dataset, config$1, { received: dataset.value instanceof Date ? dataset.value.toJSON() : /* @__PURE__ */ _stringify(dataset.value) });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function values(requirement, message$1) {
      return {
        kind: "validation",
        type: "values",
        reference: values,
        async: false,
        expects: `${/* @__PURE__ */ _joinExpects(requirement.map((value$1) => value$1 instanceof Date ? value$1.toJSON() : /* @__PURE__ */ _stringify(value$1)), "|")}`,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed && !this.requirement.some((value$1) => value$1 <= dataset.value && value$1 >= dataset.value)) _addIssue(this, "value", dataset, config$1, { received: dataset.value instanceof Date ? dataset.value.toJSON() : /* @__PURE__ */ _stringify(dataset.value) });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function words(locales, requirement, message$1) {
      return {
        kind: "validation",
        type: "words",
        reference: words,
        async: false,
        expects: `${requirement}`,
        locales,
        requirement,
        message: message$1,
        "~run"(dataset, config$1) {
          if (dataset.typed) {
            const count = /* @__PURE__ */ _getWordCount(this.locales, dataset.value);
            if (count !== this.requirement) _addIssue(this, "words", dataset, config$1, { received: `${count}` });
          }
          return dataset;
        }
      };
    }
    function assert(schema, input) {
      const issues = schema["~run"]({ value: input }, { abortEarly: true }).issues;
      if (issues) throw new ValiError(issues);
    }
    var _LruCache = class {
      constructor(config$1) {
        this.refCount = 0;
        this.maxSize = config$1?.maxSize ?? 1e3;
        this.maxAge = config$1?.maxAge ?? Infinity;
        this.hasMaxAge = isFinite(this.maxAge);
      }
      /**
      * Stringifies an unknown input to a cache key component.
      *
      * @param input The unknown input.
      *
      * @returns A cache key component.
      */
      #stringify(input) {
        const type = typeof input;
        if (type === "string") return `"${input}"`;
        if (type === "number" || type === "boolean") return `${input}`;
        if (type === "bigint") return `${input}n`;
        if (type === "object" || type === "function") {
          if (input) {
            this.refIds ??= /* @__PURE__ */ new WeakMap();
            let id = this.refIds.get(input);
            if (!id) {
              id = ++this.refCount;
              this.refIds.set(input, id);
            }
            return `#${id}`;
          }
          return "null";
        }
        return type;
      }
      /**
      * Creates a cache key from input and config.
      *
      * @param input The input value.
      * @param config The parse configuration.
      *
      * @returns The cache key.
      */
      key(input, config$1 = {}) {
        return `${this.#stringify(input)}|${this.#stringify(config$1.lang)}|${this.#stringify(config$1.message)}|${this.#stringify(config$1.abortEarly)}|${this.#stringify(config$1.abortPipeEarly)}`;
      }
      /**
      * Gets a value from the cache by key.
      *
      * @param key The cache key.
      *
      * @returns The cached value.
      */
      get(key) {
        if (!this.store) return void 0;
        const entry = this.store.get(key);
        if (!entry) return void 0;
        if (this.hasMaxAge && Date.now() - entry[1] > this.maxAge) {
          this.store.delete(key);
          return;
        }
        this.store.delete(key);
        this.store.set(key, entry);
        return entry[0];
      }
      /**
      * Sets a value in the cache by key.
      *
      * @param key The cache key.
      * @param value The cached value.
      */
      set(key, value$1) {
        this.store ??= /* @__PURE__ */ new Map();
        this.store.delete(key);
        const timestamp = this.hasMaxAge ? Date.now() : 0;
        this.store.set(key, [value$1, timestamp]);
        if (this.store.size > this.maxSize) this.store.delete(this.store.keys().next().value);
      }
      /**
      * Clears all entries from the cache.
      */
      clear() {
        this.store?.clear();
      }
    };
    // @__NO_SIDE_EFFECTS__
    function cache(schema, config$1) {
      return {
        ...schema,
        cacheConfig: config$1,
        cache: new _LruCache(config$1),
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, runConfig) {
          const key = this.cache.key(dataset.value, runConfig);
          let outputDataset = this.cache.get(key);
          if (!outputDataset) this.cache.set(key, outputDataset = schema["~run"](dataset, runConfig));
          return /* @__PURE__ */ _cloneDataset(outputDataset);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function cacheAsync(schema, config$1) {
      let activeRuns;
      return {
        ...schema,
        async: true,
        cacheConfig: config$1,
        cache: new _LruCache(config$1),
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, runConfig) {
          const key = this.cache.key(dataset.value, runConfig);
          const cached = this.cache.get(key);
          if (cached) return /* @__PURE__ */ _cloneDataset(cached);
          let promise$1 = activeRuns?.get(key);
          if (!promise$1) {
            activeRuns ??= /* @__PURE__ */ new Map();
            promise$1 = Promise.resolve(schema["~run"](dataset, runConfig));
            activeRuns.set(key, promise$1);
          }
          try {
            const outputDataset = await promise$1;
            this.cache.set(key, outputDataset);
            return /* @__PURE__ */ _cloneDataset(outputDataset);
          } finally {
            activeRuns?.delete(key);
          }
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function config(schema, config$1) {
      return {
        ...schema,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config_) {
          return schema["~run"](dataset, {
            ...config_,
            ...config$1
          });
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function getFallback(schema, dataset, config$1) {
      return typeof schema.fallback === "function" ? schema.fallback(dataset, config$1) : schema.fallback;
    }
    // @__NO_SIDE_EFFECTS__
    function fallback(schema, fallback$1) {
      return {
        ...schema,
        fallback: fallback$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const outputDataset = schema["~run"](dataset, config$1);
          return outputDataset.issues ? {
            typed: true,
            value: /* @__PURE__ */ getFallback(this, outputDataset, config$1)
          } : outputDataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function fallbackAsync(schema, fallback$1) {
      return {
        ...schema,
        fallback: fallback$1,
        async: true,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const outputDataset = await schema["~run"](dataset, config$1);
          return outputDataset.issues ? {
            typed: true,
            value: await /* @__PURE__ */ getFallback(this, outputDataset, config$1)
          } : outputDataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function flatten(issues) {
      const flatErrors = {};
      for (const issue of issues) if (issue.path) {
        const dotPath = /* @__PURE__ */ getDotPath(issue);
        if (dotPath) {
          if (!flatErrors.nested) flatErrors.nested = {};
          if (flatErrors.nested[dotPath]) flatErrors.nested[dotPath].push(issue.message);
          else flatErrors.nested[dotPath] = [issue.message];
        } else if (flatErrors.other) flatErrors.other.push(issue.message);
        else flatErrors.other = [issue.message];
      } else if (flatErrors.root) flatErrors.root.push(issue.message);
      else flatErrors.root = [issue.message];
      return flatErrors;
    }
    // @__NO_SIDE_EFFECTS__
    function forward(action, path) {
      return {
        ...action,
        "~run"(dataset, config$1) {
          const prevIssues = dataset.issues && [...dataset.issues];
          dataset = action["~run"](dataset, config$1);
          if (dataset.issues) {
            for (const issue of dataset.issues) if (!prevIssues?.includes(issue)) {
              let pathInput = dataset.value;
              for (const key of path) {
                const pathValue = pathInput[key];
                const pathItem = {
                  type: "unknown",
                  origin: "value",
                  input: pathInput,
                  key,
                  value: pathValue
                };
                if (issue.path) issue.path.push(pathItem);
                else issue.path = [pathItem];
                if (!pathValue) break;
                pathInput = pathValue;
              }
            }
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function forwardAsync(action, path) {
      return {
        ...action,
        async: true,
        async "~run"(dataset, config$1) {
          const prevIssues = dataset.issues && [...dataset.issues];
          dataset = await action["~run"](dataset, config$1);
          if (dataset.issues) {
            for (const issue of dataset.issues) if (!prevIssues?.includes(issue)) {
              let pathInput = dataset.value;
              for (const key of path) {
                const pathValue = pathInput[key];
                const pathItem = {
                  type: "unknown",
                  origin: "value",
                  input: pathInput,
                  key,
                  value: pathValue
                };
                if (issue.path) issue.path.push(pathItem);
                else issue.path = [pathItem];
                if (!pathValue) break;
                pathInput = pathValue;
              }
            }
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function getDefault(schema, dataset, config$1) {
      return typeof schema.default === "function" ? schema.default(dataset, config$1) : schema.default;
    }
    // @__NO_SIDE_EFFECTS__
    function getDefaults(schema) {
      if ("entries" in schema) {
        const object$1 = {};
        for (const key in schema.entries) object$1[key] = /* @__PURE__ */ getDefaults(schema.entries[key]);
        return object$1;
      }
      if ("items" in schema) return schema.items.map(getDefaults);
      return /* @__PURE__ */ getDefault(schema);
    }
    // @__NO_SIDE_EFFECTS__
    async function getDefaultsAsync(schema) {
      if ("entries" in schema) return Object.fromEntries(await Promise.all(Object.entries(schema.entries).map(async ([key, value$1]) => [key, await /* @__PURE__ */ getDefaultsAsync(value$1)])));
      if ("items" in schema) return Promise.all(schema.items.map(getDefaultsAsync));
      return /* @__PURE__ */ getDefault(schema);
    }
    // @__NO_SIDE_EFFECTS__
    function getDescription(schema) {
      return /* @__PURE__ */ _getLastMetadata(schema, "description");
    }
    // @__NO_SIDE_EFFECTS__
    function getExamples(schema) {
      const examples$1 = [];
      function depthFirstCollect(schema$1) {
        if ("pipe" in schema$1) {
          for (const item of schema$1.pipe) if (item.kind === "schema" && "pipe" in item) depthFirstCollect(item);
          else if (item.kind === "metadata" && item.type === "examples") examples$1.push(...item.examples);
        }
      }
      depthFirstCollect(schema);
      return examples$1;
    }
    // @__NO_SIDE_EFFECTS__
    function getFallbacks(schema) {
      if ("entries" in schema) {
        const object$1 = {};
        for (const key in schema.entries) object$1[key] = /* @__PURE__ */ getFallbacks(schema.entries[key]);
        return object$1;
      }
      if ("items" in schema) return schema.items.map(getFallbacks);
      return /* @__PURE__ */ getFallback(schema);
    }
    // @__NO_SIDE_EFFECTS__
    async function getFallbacksAsync(schema) {
      if ("entries" in schema) return Object.fromEntries(await Promise.all(Object.entries(schema.entries).map(async ([key, value$1]) => [key, await /* @__PURE__ */ getFallbacksAsync(value$1)])));
      if ("items" in schema) return Promise.all(schema.items.map(getFallbacksAsync));
      return /* @__PURE__ */ getFallback(schema);
    }
    // @__NO_SIDE_EFFECTS__
    function getMetadata(schema) {
      const result = {};
      function depthFirstMerge(schema$1) {
        if ("pipe" in schema$1) {
          for (const item of schema$1.pipe) if (item.kind === "schema" && "pipe" in item) depthFirstMerge(item);
          else if (item.kind === "metadata" && item.type === "metadata") Object.assign(result, item.metadata);
        }
      }
      depthFirstMerge(schema);
      return result;
    }
    // @__NO_SIDE_EFFECTS__
    function getTitle(schema) {
      return /* @__PURE__ */ _getLastMetadata(schema, "title");
    }
    // @__NO_SIDE_EFFECTS__
    function is(schema, input) {
      return !schema["~run"]({ value: input }, { abortEarly: true }).issues;
    }
    // @__NO_SIDE_EFFECTS__
    function any() {
      return {
        kind: "schema",
        type: "any",
        reference: any,
        expects: "any",
        async: false,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset) {
          dataset.typed = true;
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function array(item, message$1) {
      return {
        kind: "schema",
        type: "array",
        reference: array,
        expects: "Array",
        async: false,
        item,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (Array.isArray(input)) {
            dataset.typed = true;
            dataset.value = [];
            for (let key = 0; key < input.length; key++) {
              const value$1 = input[key];
              const itemDataset = this.item["~run"]({ value: value$1 }, config$1);
              if (itemDataset.issues) {
                const pathItem = {
                  type: "array",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of itemDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = itemDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!itemDataset.typed) dataset.typed = false;
              dataset.value.push(itemDataset.value);
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function arrayAsync(item, message$1) {
      return {
        kind: "schema",
        type: "array",
        reference: arrayAsync,
        expects: "Array",
        async: true,
        item,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (Array.isArray(input)) {
            dataset.typed = true;
            dataset.value = [];
            const itemDatasets = await Promise.all(input.map((value$1) => this.item["~run"]({ value: value$1 }, config$1)));
            for (let key = 0; key < itemDatasets.length; key++) {
              const itemDataset = itemDatasets[key];
              if (itemDataset.issues) {
                const pathItem = {
                  type: "array",
                  origin: "value",
                  input,
                  key,
                  value: input[key]
                };
                for (const issue of itemDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = itemDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!itemDataset.typed) dataset.typed = false;
              dataset.value.push(itemDataset.value);
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function bigint(message$1) {
      return {
        kind: "schema",
        type: "bigint",
        reference: bigint,
        expects: "bigint",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (typeof dataset.value === "bigint") dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function blob(message$1) {
      return {
        kind: "schema",
        type: "blob",
        reference: blob,
        expects: "Blob",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value instanceof Blob) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function boolean(message$1) {
      return {
        kind: "schema",
        type: "boolean",
        reference: boolean,
        expects: "boolean",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (typeof dataset.value === "boolean") dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function custom(check$1, message$1) {
      return {
        kind: "schema",
        type: "custom",
        reference: custom,
        expects: "unknown",
        async: false,
        check: check$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (this.check(dataset.value)) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function customAsync(check$1, message$1) {
      return {
        kind: "schema",
        type: "custom",
        reference: customAsync,
        expects: "unknown",
        async: true,
        check: check$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          if (await this.check(dataset.value)) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function date(message$1) {
      return {
        kind: "schema",
        type: "date",
        reference: date,
        expects: "Date",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value instanceof Date) if (!isNaN(dataset.value)) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1, { received: '"Invalid Date"' });
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function enum_(enum__, message$1) {
      const options = [];
      for (const key in enum__) if (`${+key}` !== key || typeof enum__[key] !== "string" || !Object.is(enum__[enum__[key]], +key)) options.push(enum__[key]);
      return {
        kind: "schema",
        type: "enum",
        reference: enum_,
        expects: /* @__PURE__ */ _joinExpects(options.map(_stringify), "|"),
        async: false,
        enum: enum__,
        options,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (this.options.includes(dataset.value)) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function exactOptional(wrapped, default_) {
      return {
        kind: "schema",
        type: "exact_optional",
        reference: exactOptional,
        expects: wrapped.expects,
        async: false,
        wrapped,
        default: default_,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          return this.wrapped["~run"](dataset, config$1);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function exactOptionalAsync(wrapped, default_) {
      return {
        kind: "schema",
        type: "exact_optional",
        reference: exactOptionalAsync,
        expects: wrapped.expects,
        async: true,
        wrapped,
        default: default_,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          return this.wrapped["~run"](dataset, config$1);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function file(message$1) {
      return {
        kind: "schema",
        type: "file",
        reference: file,
        expects: "File",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value instanceof File) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function function_(message$1) {
      return {
        kind: "schema",
        type: "function",
        reference: function_,
        expects: "Function",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (typeof dataset.value === "function") dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function instance(class_, message$1) {
      return {
        kind: "schema",
        type: "instance",
        reference: instance,
        expects: class_.name,
        async: false,
        class: class_,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value instanceof this.class) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function _merge(value1, value2) {
      if (typeof value1 === typeof value2) {
        if (value1 === value2 || value1 instanceof Date && value2 instanceof Date && +value1 === +value2) return { value: value1 };
        if (value1 && value2 && value1.constructor === Object && value2.constructor === Object) {
          for (const key in value2) if (key in value1) {
            const dataset = /* @__PURE__ */ _merge(value1[key], value2[key]);
            if (dataset.issue) return dataset;
            value1[key] = dataset.value;
          } else value1[key] = value2[key];
          return { value: value1 };
        }
        if (Array.isArray(value1) && Array.isArray(value2)) {
          if (value1.length === value2.length) {
            for (let index = 0; index < value1.length; index++) {
              const dataset = /* @__PURE__ */ _merge(value1[index], value2[index]);
              if (dataset.issue) return dataset;
              value1[index] = dataset.value;
            }
            return { value: value1 };
          }
        }
      }
      return { issue: true };
    }
    // @__NO_SIDE_EFFECTS__
    function intersect(options, message$1) {
      return {
        kind: "schema",
        type: "intersect",
        reference: intersect,
        expects: /* @__PURE__ */ _joinExpects(options.map((option) => option.expects), "&"),
        async: false,
        options,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (this.options.length) {
            const input = dataset.value;
            let outputs;
            dataset.typed = true;
            for (const schema of this.options) {
              const optionDataset = schema["~run"]({ value: input }, config$1);
              if (optionDataset.issues) {
                if (dataset.issues) dataset.issues.push(...optionDataset.issues);
                else dataset.issues = optionDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!optionDataset.typed) dataset.typed = false;
              if (dataset.typed) if (outputs) outputs.push(optionDataset.value);
              else outputs = [optionDataset.value];
            }
            if (dataset.typed) {
              dataset.value = outputs[0];
              for (let index = 1; index < outputs.length; index++) {
                const mergeDataset = /* @__PURE__ */ _merge(dataset.value, outputs[index]);
                if (mergeDataset.issue) {
                  _addIssue(this, "type", dataset, config$1, { received: "unknown" });
                  break;
                }
                dataset.value = mergeDataset.value;
              }
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function intersectAsync(options, message$1) {
      return {
        kind: "schema",
        type: "intersect",
        reference: intersectAsync,
        expects: /* @__PURE__ */ _joinExpects(options.map((option) => option.expects), "&"),
        async: true,
        options,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          if (this.options.length) {
            const input = dataset.value;
            let outputs;
            dataset.typed = true;
            const optionDatasets = await Promise.all(this.options.map((schema) => schema["~run"]({ value: input }, config$1)));
            for (const optionDataset of optionDatasets) {
              if (optionDataset.issues) {
                if (dataset.issues) dataset.issues.push(...optionDataset.issues);
                else dataset.issues = optionDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!optionDataset.typed) dataset.typed = false;
              if (dataset.typed) if (outputs) outputs.push(optionDataset.value);
              else outputs = [optionDataset.value];
            }
            if (dataset.typed) {
              dataset.value = outputs[0];
              for (let index = 1; index < outputs.length; index++) {
                const mergeDataset = /* @__PURE__ */ _merge(dataset.value, outputs[index]);
                if (mergeDataset.issue) {
                  _addIssue(this, "type", dataset, config$1, { received: "unknown" });
                  break;
                }
                dataset.value = mergeDataset.value;
              }
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function lazy(getter) {
      return {
        kind: "schema",
        type: "lazy",
        reference: lazy,
        expects: "unknown",
        async: false,
        getter,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          return this.getter(dataset.value)["~run"](dataset, config$1);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function lazyAsync(getter) {
      return {
        kind: "schema",
        type: "lazy",
        reference: lazyAsync,
        expects: "unknown",
        async: true,
        getter,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          return (await this.getter(dataset.value))["~run"](dataset, config$1);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function literal(literal_, message$1) {
      return {
        kind: "schema",
        type: "literal",
        reference: literal,
        expects: /* @__PURE__ */ _stringify(literal_),
        async: false,
        literal: literal_,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value === this.literal) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function looseObject(entries$1, message$1) {
      return {
        kind: "schema",
        type: "loose_object",
        reference: looseObject,
        expects: "Object",
        async: false,
        entries: entries$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input && typeof input === "object") {
            dataset.typed = true;
            dataset.value = {};
            for (const key in this.entries) {
              const valueSchema = this.entries[key];
              if (key in input || (valueSchema.type === "exact_optional" || valueSchema.type === "optional" || valueSchema.type === "nullish") && valueSchema.default !== void 0) {
                const value$1 = key in input ? input[key] : /* @__PURE__ */ getDefault(valueSchema);
                const valueDataset = valueSchema["~run"]({ value: value$1 }, config$1);
                if (valueDataset.issues) {
                  const pathItem = {
                    type: "object",
                    origin: "value",
                    input,
                    key,
                    value: value$1
                  };
                  for (const issue of valueDataset.issues) {
                    if (issue.path) issue.path.unshift(pathItem);
                    else issue.path = [pathItem];
                    dataset.issues?.push(issue);
                  }
                  if (!dataset.issues) dataset.issues = valueDataset.issues;
                  if (config$1.abortEarly) {
                    dataset.typed = false;
                    break;
                  }
                }
                if (!valueDataset.typed) dataset.typed = false;
                dataset.value[key] = valueDataset.value;
              } else if (valueSchema.fallback !== void 0) dataset.value[key] = /* @__PURE__ */ getFallback(valueSchema);
              else if (valueSchema.type !== "exact_optional" && valueSchema.type !== "optional" && valueSchema.type !== "nullish") {
                _addIssue(this, "key", dataset, config$1, {
                  input: void 0,
                  expected: `"${key}"`,
                  path: [{
                    type: "object",
                    origin: "key",
                    input,
                    key,
                    value: input[key]
                  }]
                });
                if (config$1.abortEarly) break;
              }
            }
            if (!dataset.issues || !config$1.abortEarly) {
              for (const key in input) if (/* @__PURE__ */ _isValidObjectKey(input, key) && !(key in this.entries)) dataset.value[key] = input[key];
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function looseObjectAsync(entries$1, message$1) {
      return {
        kind: "schema",
        type: "loose_object",
        reference: looseObjectAsync,
        expects: "Object",
        async: true,
        entries: entries$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input && typeof input === "object") {
            dataset.typed = true;
            dataset.value = {};
            const valueDatasets = await Promise.all(Object.entries(this.entries).map(async ([key, valueSchema]) => {
              if (key in input || (valueSchema.type === "exact_optional" || valueSchema.type === "optional" || valueSchema.type === "nullish") && valueSchema.default !== void 0) {
                const value$1 = key in input ? input[key] : await /* @__PURE__ */ getDefault(valueSchema);
                return [
                  key,
                  value$1,
                  valueSchema,
                  await valueSchema["~run"]({ value: value$1 }, config$1)
                ];
              }
              return [
                key,
                input[key],
                valueSchema,
                null
              ];
            }));
            for (const [key, value$1, valueSchema, valueDataset] of valueDatasets) if (valueDataset) {
              if (valueDataset.issues) {
                const pathItem = {
                  type: "object",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of valueDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = valueDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!valueDataset.typed) dataset.typed = false;
              dataset.value[key] = valueDataset.value;
            } else if (valueSchema.fallback !== void 0) dataset.value[key] = await /* @__PURE__ */ getFallback(valueSchema);
            else if (valueSchema.type !== "exact_optional" && valueSchema.type !== "optional" && valueSchema.type !== "nullish") {
              _addIssue(this, "key", dataset, config$1, {
                input: void 0,
                expected: `"${key}"`,
                path: [{
                  type: "object",
                  origin: "key",
                  input,
                  key,
                  value: value$1
                }]
              });
              if (config$1.abortEarly) break;
            }
            if (!dataset.issues || !config$1.abortEarly) {
              for (const key in input) if (/* @__PURE__ */ _isValidObjectKey(input, key) && !(key in this.entries)) dataset.value[key] = input[key];
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function looseTuple(items, message$1) {
      return {
        kind: "schema",
        type: "loose_tuple",
        reference: looseTuple,
        expects: "Array",
        async: false,
        items,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (Array.isArray(input)) {
            dataset.typed = true;
            dataset.value = [];
            for (let key = 0; key < this.items.length; key++) {
              const value$1 = input[key];
              const itemDataset = this.items[key]["~run"]({ value: value$1 }, config$1);
              if (itemDataset.issues) {
                const pathItem = {
                  type: "array",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of itemDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = itemDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!itemDataset.typed) dataset.typed = false;
              dataset.value.push(itemDataset.value);
            }
            if (!dataset.issues || !config$1.abortEarly) for (let key = this.items.length; key < input.length; key++) dataset.value.push(input[key]);
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function looseTupleAsync(items, message$1) {
      return {
        kind: "schema",
        type: "loose_tuple",
        reference: looseTupleAsync,
        expects: "Array",
        async: true,
        items,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (Array.isArray(input)) {
            dataset.typed = true;
            dataset.value = [];
            const itemDatasets = await Promise.all(this.items.map(async (item, key) => {
              const value$1 = input[key];
              return [
                key,
                value$1,
                await item["~run"]({ value: value$1 }, config$1)
              ];
            }));
            for (const [key, value$1, itemDataset] of itemDatasets) {
              if (itemDataset.issues) {
                const pathItem = {
                  type: "array",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of itemDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = itemDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!itemDataset.typed) dataset.typed = false;
              dataset.value.push(itemDataset.value);
            }
            if (!dataset.issues || !config$1.abortEarly) for (let key = this.items.length; key < input.length; key++) dataset.value.push(input[key]);
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function map(key, value$1, message$1) {
      return {
        kind: "schema",
        type: "map",
        reference: map,
        expects: "Map",
        async: false,
        key,
        value: value$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input instanceof Map) {
            dataset.typed = true;
            dataset.value = /* @__PURE__ */ new Map();
            for (const [inputKey, inputValue] of input) {
              const keyDataset = this.key["~run"]({ value: inputKey }, config$1);
              if (keyDataset.issues) {
                const pathItem = {
                  type: "map",
                  origin: "key",
                  input,
                  key: inputKey,
                  value: inputValue
                };
                for (const issue of keyDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = keyDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              const valueDataset = this.value["~run"]({ value: inputValue }, config$1);
              if (valueDataset.issues) {
                const pathItem = {
                  type: "map",
                  origin: "value",
                  input,
                  key: inputKey,
                  value: inputValue
                };
                for (const issue of valueDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = valueDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!keyDataset.typed || !valueDataset.typed) dataset.typed = false;
              dataset.value.set(keyDataset.value, valueDataset.value);
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function mapAsync(key, value$1, message$1) {
      return {
        kind: "schema",
        type: "map",
        reference: mapAsync,
        expects: "Map",
        async: true,
        key,
        value: value$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input instanceof Map) {
            dataset.typed = true;
            dataset.value = /* @__PURE__ */ new Map();
            const datasets = await Promise.all([...input].map(([inputKey, inputValue]) => Promise.all([
              inputKey,
              inputValue,
              this.key["~run"]({ value: inputKey }, config$1),
              this.value["~run"]({ value: inputValue }, config$1)
            ])));
            for (const [inputKey, inputValue, keyDataset, valueDataset] of datasets) {
              if (keyDataset.issues) {
                const pathItem = {
                  type: "map",
                  origin: "key",
                  input,
                  key: inputKey,
                  value: inputValue
                };
                for (const issue of keyDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = keyDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (valueDataset.issues) {
                const pathItem = {
                  type: "map",
                  origin: "value",
                  input,
                  key: inputKey,
                  value: inputValue
                };
                for (const issue of valueDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = valueDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!keyDataset.typed || !valueDataset.typed) dataset.typed = false;
              dataset.value.set(keyDataset.value, valueDataset.value);
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nan(message$1) {
      return {
        kind: "schema",
        type: "nan",
        reference: nan,
        expects: "NaN",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (Number.isNaN(dataset.value)) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function never(message$1) {
      return {
        kind: "schema",
        type: "never",
        reference: never,
        expects: "never",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nonNullable(wrapped, message$1) {
      return {
        kind: "schema",
        type: "non_nullable",
        reference: nonNullable,
        expects: "!null",
        async: false,
        wrapped,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value !== null) dataset = this.wrapped["~run"](dataset, config$1);
          if (dataset.value === null) _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nonNullableAsync(wrapped, message$1) {
      return {
        kind: "schema",
        type: "non_nullable",
        reference: nonNullableAsync,
        expects: "!null",
        async: true,
        wrapped,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          if (dataset.value !== null) dataset = await this.wrapped["~run"](dataset, config$1);
          if (dataset.value === null) _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nonNullish(wrapped, message$1) {
      return {
        kind: "schema",
        type: "non_nullish",
        reference: nonNullish,
        expects: "(!null & !undefined)",
        async: false,
        wrapped,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (!(dataset.value === null || dataset.value === void 0)) dataset = this.wrapped["~run"](dataset, config$1);
          if (dataset.value === null || dataset.value === void 0) _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nonNullishAsync(wrapped, message$1) {
      return {
        kind: "schema",
        type: "non_nullish",
        reference: nonNullishAsync,
        expects: "(!null & !undefined)",
        async: true,
        wrapped,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          if (!(dataset.value === null || dataset.value === void 0)) dataset = await this.wrapped["~run"](dataset, config$1);
          if (dataset.value === null || dataset.value === void 0) _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nonOptional(wrapped, message$1) {
      return {
        kind: "schema",
        type: "non_optional",
        reference: nonOptional,
        expects: "!undefined",
        async: false,
        wrapped,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value !== void 0) dataset = this.wrapped["~run"](dataset, config$1);
          if (dataset.value === void 0) _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nonOptionalAsync(wrapped, message$1) {
      return {
        kind: "schema",
        type: "non_optional",
        reference: nonOptionalAsync,
        expects: "!undefined",
        async: true,
        wrapped,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          if (dataset.value !== void 0) dataset = await this.wrapped["~run"](dataset, config$1);
          if (dataset.value === void 0) _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function null_(message$1) {
      return {
        kind: "schema",
        type: "null",
        reference: null_,
        expects: "null",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value === null) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nullable(wrapped, default_) {
      return {
        kind: "schema",
        type: "nullable",
        reference: nullable,
        expects: `(${wrapped.expects} | null)`,
        async: false,
        wrapped,
        default: default_,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value === null) {
            if (this.default !== void 0) dataset.value = /* @__PURE__ */ getDefault(this, dataset, config$1);
            if (dataset.value === null) {
              dataset.typed = true;
              return dataset;
            }
          }
          return this.wrapped["~run"](dataset, config$1);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nullableAsync(wrapped, default_) {
      return {
        kind: "schema",
        type: "nullable",
        reference: nullableAsync,
        expects: `(${wrapped.expects} | null)`,
        async: true,
        wrapped,
        default: default_,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          if (dataset.value === null) {
            if (this.default !== void 0) dataset.value = await /* @__PURE__ */ getDefault(this, dataset, config$1);
            if (dataset.value === null) {
              dataset.typed = true;
              return dataset;
            }
          }
          return this.wrapped["~run"](dataset, config$1);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nullish(wrapped, default_) {
      return {
        kind: "schema",
        type: "nullish",
        reference: nullish,
        expects: `(${wrapped.expects} | null | undefined)`,
        async: false,
        wrapped,
        default: default_,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value === null || dataset.value === void 0) {
            if (this.default !== void 0) dataset.value = /* @__PURE__ */ getDefault(this, dataset, config$1);
            if (dataset.value === null || dataset.value === void 0) {
              dataset.typed = true;
              return dataset;
            }
          }
          return this.wrapped["~run"](dataset, config$1);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function nullishAsync(wrapped, default_) {
      return {
        kind: "schema",
        type: "nullish",
        reference: nullishAsync,
        expects: `(${wrapped.expects} | null | undefined)`,
        async: true,
        wrapped,
        default: default_,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          if (dataset.value === null || dataset.value === void 0) {
            if (this.default !== void 0) dataset.value = await /* @__PURE__ */ getDefault(this, dataset, config$1);
            if (dataset.value === null || dataset.value === void 0) {
              dataset.typed = true;
              return dataset;
            }
          }
          return this.wrapped["~run"](dataset, config$1);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function number(message$1) {
      return {
        kind: "schema",
        type: "number",
        reference: number,
        expects: "number",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (typeof dataset.value === "number" && !isNaN(dataset.value)) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function object(entries$1, message$1) {
      return {
        kind: "schema",
        type: "object",
        reference: object,
        expects: "Object",
        async: false,
        entries: entries$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input && typeof input === "object") {
            dataset.typed = true;
            dataset.value = {};
            for (const key in this.entries) {
              const valueSchema = this.entries[key];
              if (key in input || (valueSchema.type === "exact_optional" || valueSchema.type === "optional" || valueSchema.type === "nullish") && valueSchema.default !== void 0) {
                const value$1 = key in input ? input[key] : /* @__PURE__ */ getDefault(valueSchema);
                const valueDataset = valueSchema["~run"]({ value: value$1 }, config$1);
                if (valueDataset.issues) {
                  const pathItem = {
                    type: "object",
                    origin: "value",
                    input,
                    key,
                    value: value$1
                  };
                  for (const issue of valueDataset.issues) {
                    if (issue.path) issue.path.unshift(pathItem);
                    else issue.path = [pathItem];
                    dataset.issues?.push(issue);
                  }
                  if (!dataset.issues) dataset.issues = valueDataset.issues;
                  if (config$1.abortEarly) {
                    dataset.typed = false;
                    break;
                  }
                }
                if (!valueDataset.typed) dataset.typed = false;
                dataset.value[key] = valueDataset.value;
              } else if (valueSchema.fallback !== void 0) dataset.value[key] = /* @__PURE__ */ getFallback(valueSchema);
              else if (valueSchema.type !== "exact_optional" && valueSchema.type !== "optional" && valueSchema.type !== "nullish") {
                _addIssue(this, "key", dataset, config$1, {
                  input: void 0,
                  expected: `"${key}"`,
                  path: [{
                    type: "object",
                    origin: "key",
                    input,
                    key,
                    value: input[key]
                  }]
                });
                if (config$1.abortEarly) break;
              }
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function objectAsync(entries$1, message$1) {
      return {
        kind: "schema",
        type: "object",
        reference: objectAsync,
        expects: "Object",
        async: true,
        entries: entries$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input && typeof input === "object") {
            dataset.typed = true;
            dataset.value = {};
            const valueDatasets = await Promise.all(Object.entries(this.entries).map(async ([key, valueSchema]) => {
              if (key in input || (valueSchema.type === "exact_optional" || valueSchema.type === "optional" || valueSchema.type === "nullish") && valueSchema.default !== void 0) {
                const value$1 = key in input ? input[key] : await /* @__PURE__ */ getDefault(valueSchema);
                return [
                  key,
                  value$1,
                  valueSchema,
                  await valueSchema["~run"]({ value: value$1 }, config$1)
                ];
              }
              return [
                key,
                input[key],
                valueSchema,
                null
              ];
            }));
            for (const [key, value$1, valueSchema, valueDataset] of valueDatasets) if (valueDataset) {
              if (valueDataset.issues) {
                const pathItem = {
                  type: "object",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of valueDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = valueDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!valueDataset.typed) dataset.typed = false;
              dataset.value[key] = valueDataset.value;
            } else if (valueSchema.fallback !== void 0) dataset.value[key] = await /* @__PURE__ */ getFallback(valueSchema);
            else if (valueSchema.type !== "exact_optional" && valueSchema.type !== "optional" && valueSchema.type !== "nullish") {
              _addIssue(this, "key", dataset, config$1, {
                input: void 0,
                expected: `"${key}"`,
                path: [{
                  type: "object",
                  origin: "key",
                  input,
                  key,
                  value: value$1
                }]
              });
              if (config$1.abortEarly) break;
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function objectWithRest(entries$1, rest, message$1) {
      return {
        kind: "schema",
        type: "object_with_rest",
        reference: objectWithRest,
        expects: "Object",
        async: false,
        entries: entries$1,
        rest,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input && typeof input === "object") {
            dataset.typed = true;
            dataset.value = {};
            for (const key in this.entries) {
              const valueSchema = this.entries[key];
              if (key in input || (valueSchema.type === "exact_optional" || valueSchema.type === "optional" || valueSchema.type === "nullish") && valueSchema.default !== void 0) {
                const value$1 = key in input ? input[key] : /* @__PURE__ */ getDefault(valueSchema);
                const valueDataset = valueSchema["~run"]({ value: value$1 }, config$1);
                if (valueDataset.issues) {
                  const pathItem = {
                    type: "object",
                    origin: "value",
                    input,
                    key,
                    value: value$1
                  };
                  for (const issue of valueDataset.issues) {
                    if (issue.path) issue.path.unshift(pathItem);
                    else issue.path = [pathItem];
                    dataset.issues?.push(issue);
                  }
                  if (!dataset.issues) dataset.issues = valueDataset.issues;
                  if (config$1.abortEarly) {
                    dataset.typed = false;
                    break;
                  }
                }
                if (!valueDataset.typed) dataset.typed = false;
                dataset.value[key] = valueDataset.value;
              } else if (valueSchema.fallback !== void 0) dataset.value[key] = /* @__PURE__ */ getFallback(valueSchema);
              else if (valueSchema.type !== "exact_optional" && valueSchema.type !== "optional" && valueSchema.type !== "nullish") {
                _addIssue(this, "key", dataset, config$1, {
                  input: void 0,
                  expected: `"${key}"`,
                  path: [{
                    type: "object",
                    origin: "key",
                    input,
                    key,
                    value: input[key]
                  }]
                });
                if (config$1.abortEarly) break;
              }
            }
            if (!dataset.issues || !config$1.abortEarly) {
              for (const key in input) if (/* @__PURE__ */ _isValidObjectKey(input, key) && !(key in this.entries)) {
                const valueDataset = this.rest["~run"]({ value: input[key] }, config$1);
                if (valueDataset.issues) {
                  const pathItem = {
                    type: "object",
                    origin: "value",
                    input,
                    key,
                    value: input[key]
                  };
                  for (const issue of valueDataset.issues) {
                    if (issue.path) issue.path.unshift(pathItem);
                    else issue.path = [pathItem];
                    dataset.issues?.push(issue);
                  }
                  if (!dataset.issues) dataset.issues = valueDataset.issues;
                  if (config$1.abortEarly) {
                    dataset.typed = false;
                    break;
                  }
                }
                if (!valueDataset.typed) dataset.typed = false;
                dataset.value[key] = valueDataset.value;
              }
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function objectWithRestAsync(entries$1, rest, message$1) {
      return {
        kind: "schema",
        type: "object_with_rest",
        reference: objectWithRestAsync,
        expects: "Object",
        async: true,
        entries: entries$1,
        rest,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input && typeof input === "object") {
            dataset.typed = true;
            dataset.value = {};
            const [normalDatasets, restDatasets] = await Promise.all([Promise.all(Object.entries(this.entries).map(async ([key, valueSchema]) => {
              if (key in input || (valueSchema.type === "exact_optional" || valueSchema.type === "optional" || valueSchema.type === "nullish") && valueSchema.default !== void 0) {
                const value$1 = key in input ? input[key] : await /* @__PURE__ */ getDefault(valueSchema);
                return [
                  key,
                  value$1,
                  valueSchema,
                  await valueSchema["~run"]({ value: value$1 }, config$1)
                ];
              }
              return [
                key,
                input[key],
                valueSchema,
                null
              ];
            })), Promise.all(Object.entries(input).filter(([key]) => /* @__PURE__ */ _isValidObjectKey(input, key) && !(key in this.entries)).map(async ([key, value$1]) => [
              key,
              value$1,
              await this.rest["~run"]({ value: value$1 }, config$1)
            ]))]);
            for (const [key, value$1, valueSchema, valueDataset] of normalDatasets) if (valueDataset) {
              if (valueDataset.issues) {
                const pathItem = {
                  type: "object",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of valueDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = valueDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!valueDataset.typed) dataset.typed = false;
              dataset.value[key] = valueDataset.value;
            } else if (valueSchema.fallback !== void 0) dataset.value[key] = await /* @__PURE__ */ getFallback(valueSchema);
            else if (valueSchema.type !== "exact_optional" && valueSchema.type !== "optional" && valueSchema.type !== "nullish") {
              _addIssue(this, "key", dataset, config$1, {
                input: void 0,
                expected: `"${key}"`,
                path: [{
                  type: "object",
                  origin: "key",
                  input,
                  key,
                  value: value$1
                }]
              });
              if (config$1.abortEarly) break;
            }
            if (!dataset.issues || !config$1.abortEarly) for (const [key, value$1, valueDataset] of restDatasets) {
              if (valueDataset.issues) {
                const pathItem = {
                  type: "object",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of valueDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = valueDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!valueDataset.typed) dataset.typed = false;
              dataset.value[key] = valueDataset.value;
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function optional(wrapped, default_) {
      return {
        kind: "schema",
        type: "optional",
        reference: optional,
        expects: `(${wrapped.expects} | undefined)`,
        async: false,
        wrapped,
        default: default_,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value === void 0) {
            if (this.default !== void 0) dataset.value = /* @__PURE__ */ getDefault(this, dataset, config$1);
            if (dataset.value === void 0) {
              dataset.typed = true;
              return dataset;
            }
          }
          return this.wrapped["~run"](dataset, config$1);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function optionalAsync(wrapped, default_) {
      return {
        kind: "schema",
        type: "optional",
        reference: optionalAsync,
        expects: `(${wrapped.expects} | undefined)`,
        async: true,
        wrapped,
        default: default_,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          if (dataset.value === void 0) {
            if (this.default !== void 0) dataset.value = await /* @__PURE__ */ getDefault(this, dataset, config$1);
            if (dataset.value === void 0) {
              dataset.typed = true;
              return dataset;
            }
          }
          return this.wrapped["~run"](dataset, config$1);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function picklist(options, message$1) {
      return {
        kind: "schema",
        type: "picklist",
        reference: picklist,
        expects: /* @__PURE__ */ _joinExpects(options.map(_stringify), "|"),
        async: false,
        options,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (this.options.includes(dataset.value)) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function promise(message$1) {
      return {
        kind: "schema",
        type: "promise",
        reference: promise,
        expects: "Promise",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value instanceof Promise) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function record(key, value$1, message$1) {
      return {
        kind: "schema",
        type: "record",
        reference: record,
        expects: "Object",
        async: false,
        key,
        value: value$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input && typeof input === "object") {
            dataset.typed = true;
            dataset.value = {};
            for (const entryKey in input) if (/* @__PURE__ */ _isValidObjectKey(input, entryKey)) {
              const entryValue = input[entryKey];
              const keyDataset = this.key["~run"]({ value: entryKey }, config$1);
              if (keyDataset.issues) {
                const pathItem = {
                  type: "object",
                  origin: "key",
                  input,
                  key: entryKey,
                  value: entryValue
                };
                for (const issue of keyDataset.issues) {
                  issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = keyDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              const valueDataset = this.value["~run"]({ value: entryValue }, config$1);
              if (valueDataset.issues) {
                const pathItem = {
                  type: "object",
                  origin: "value",
                  input,
                  key: entryKey,
                  value: entryValue
                };
                for (const issue of valueDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = valueDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!keyDataset.typed || !valueDataset.typed) dataset.typed = false;
              if (keyDataset.typed) dataset.value[keyDataset.value] = valueDataset.value;
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function recordAsync(key, value$1, message$1) {
      return {
        kind: "schema",
        type: "record",
        reference: recordAsync,
        expects: "Object",
        async: true,
        key,
        value: value$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input && typeof input === "object") {
            dataset.typed = true;
            dataset.value = {};
            const datasets = await Promise.all(Object.entries(input).filter(([key$1]) => /* @__PURE__ */ _isValidObjectKey(input, key$1)).map(([entryKey, entryValue]) => Promise.all([
              entryKey,
              entryValue,
              this.key["~run"]({ value: entryKey }, config$1),
              this.value["~run"]({ value: entryValue }, config$1)
            ])));
            for (const [entryKey, entryValue, keyDataset, valueDataset] of datasets) {
              if (keyDataset.issues) {
                const pathItem = {
                  type: "object",
                  origin: "key",
                  input,
                  key: entryKey,
                  value: entryValue
                };
                for (const issue of keyDataset.issues) {
                  issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = keyDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (valueDataset.issues) {
                const pathItem = {
                  type: "object",
                  origin: "value",
                  input,
                  key: entryKey,
                  value: entryValue
                };
                for (const issue of valueDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = valueDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!keyDataset.typed || !valueDataset.typed) dataset.typed = false;
              if (keyDataset.typed) dataset.value[keyDataset.value] = valueDataset.value;
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function set(value$1, message$1) {
      return {
        kind: "schema",
        type: "set",
        reference: set,
        expects: "Set",
        async: false,
        value: value$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input instanceof Set) {
            dataset.typed = true;
            dataset.value = /* @__PURE__ */ new Set();
            for (const inputValue of input) {
              const valueDataset = this.value["~run"]({ value: inputValue }, config$1);
              if (valueDataset.issues) {
                const pathItem = {
                  type: "set",
                  origin: "value",
                  input,
                  key: null,
                  value: inputValue
                };
                for (const issue of valueDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = valueDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!valueDataset.typed) dataset.typed = false;
              dataset.value.add(valueDataset.value);
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function setAsync(value$1, message$1) {
      return {
        kind: "schema",
        type: "set",
        reference: setAsync,
        expects: "Set",
        async: true,
        value: value$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input instanceof Set) {
            dataset.typed = true;
            dataset.value = /* @__PURE__ */ new Set();
            const valueDatasets = await Promise.all([...input].map(async (inputValue) => [inputValue, await this.value["~run"]({ value: inputValue }, config$1)]));
            for (const [inputValue, valueDataset] of valueDatasets) {
              if (valueDataset.issues) {
                const pathItem = {
                  type: "set",
                  origin: "value",
                  input,
                  key: null,
                  value: inputValue
                };
                for (const issue of valueDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = valueDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!valueDataset.typed) dataset.typed = false;
              dataset.value.add(valueDataset.value);
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function strictObject(entries$1, message$1) {
      return {
        kind: "schema",
        type: "strict_object",
        reference: strictObject,
        expects: "Object",
        async: false,
        entries: entries$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input && typeof input === "object") {
            dataset.typed = true;
            dataset.value = {};
            for (const key in this.entries) {
              const valueSchema = this.entries[key];
              if (key in input || (valueSchema.type === "exact_optional" || valueSchema.type === "optional" || valueSchema.type === "nullish") && valueSchema.default !== void 0) {
                const value$1 = key in input ? input[key] : /* @__PURE__ */ getDefault(valueSchema);
                const valueDataset = valueSchema["~run"]({ value: value$1 }, config$1);
                if (valueDataset.issues) {
                  const pathItem = {
                    type: "object",
                    origin: "value",
                    input,
                    key,
                    value: value$1
                  };
                  for (const issue of valueDataset.issues) {
                    if (issue.path) issue.path.unshift(pathItem);
                    else issue.path = [pathItem];
                    dataset.issues?.push(issue);
                  }
                  if (!dataset.issues) dataset.issues = valueDataset.issues;
                  if (config$1.abortEarly) {
                    dataset.typed = false;
                    break;
                  }
                }
                if (!valueDataset.typed) dataset.typed = false;
                dataset.value[key] = valueDataset.value;
              } else if (valueSchema.fallback !== void 0) dataset.value[key] = /* @__PURE__ */ getFallback(valueSchema);
              else if (valueSchema.type !== "exact_optional" && valueSchema.type !== "optional" && valueSchema.type !== "nullish") {
                _addIssue(this, "key", dataset, config$1, {
                  input: void 0,
                  expected: `"${key}"`,
                  path: [{
                    type: "object",
                    origin: "key",
                    input,
                    key,
                    value: input[key]
                  }]
                });
                if (config$1.abortEarly) break;
              }
            }
            if (!dataset.issues || !config$1.abortEarly) {
              for (const key in input) if (!(key in this.entries)) {
                _addIssue(this, "key", dataset, config$1, {
                  input: key,
                  expected: "never",
                  path: [{
                    type: "object",
                    origin: "key",
                    input,
                    key,
                    value: input[key]
                  }]
                });
                break;
              }
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function strictObjectAsync(entries$1, message$1) {
      return {
        kind: "schema",
        type: "strict_object",
        reference: strictObjectAsync,
        expects: "Object",
        async: true,
        entries: entries$1,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input && typeof input === "object") {
            dataset.typed = true;
            dataset.value = {};
            const valueDatasets = await Promise.all(Object.entries(this.entries).map(async ([key, valueSchema]) => {
              if (key in input || (valueSchema.type === "exact_optional" || valueSchema.type === "optional" || valueSchema.type === "nullish") && valueSchema.default !== void 0) {
                const value$1 = key in input ? input[key] : await /* @__PURE__ */ getDefault(valueSchema);
                return [
                  key,
                  value$1,
                  valueSchema,
                  await valueSchema["~run"]({ value: value$1 }, config$1)
                ];
              }
              return [
                key,
                input[key],
                valueSchema,
                null
              ];
            }));
            for (const [key, value$1, valueSchema, valueDataset] of valueDatasets) if (valueDataset) {
              if (valueDataset.issues) {
                const pathItem = {
                  type: "object",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of valueDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = valueDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!valueDataset.typed) dataset.typed = false;
              dataset.value[key] = valueDataset.value;
            } else if (valueSchema.fallback !== void 0) dataset.value[key] = await /* @__PURE__ */ getFallback(valueSchema);
            else if (valueSchema.type !== "exact_optional" && valueSchema.type !== "optional" && valueSchema.type !== "nullish") {
              _addIssue(this, "key", dataset, config$1, {
                input: void 0,
                expected: `"${key}"`,
                path: [{
                  type: "object",
                  origin: "key",
                  input,
                  key,
                  value: value$1
                }]
              });
              if (config$1.abortEarly) break;
            }
            if (!dataset.issues || !config$1.abortEarly) {
              for (const key in input) if (!(key in this.entries)) {
                _addIssue(this, "key", dataset, config$1, {
                  input: key,
                  expected: "never",
                  path: [{
                    type: "object",
                    origin: "key",
                    input,
                    key,
                    value: input[key]
                  }]
                });
                break;
              }
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function strictTuple(items, message$1) {
      return {
        kind: "schema",
        type: "strict_tuple",
        reference: strictTuple,
        expects: "Array",
        async: false,
        items,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (Array.isArray(input)) {
            dataset.typed = true;
            dataset.value = [];
            for (let key = 0; key < this.items.length; key++) {
              const value$1 = input[key];
              const itemDataset = this.items[key]["~run"]({ value: value$1 }, config$1);
              if (itemDataset.issues) {
                const pathItem = {
                  type: "array",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of itemDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = itemDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!itemDataset.typed) dataset.typed = false;
              dataset.value.push(itemDataset.value);
            }
            if (!(dataset.issues && config$1.abortEarly) && this.items.length < input.length) _addIssue(this, "type", dataset, config$1, {
              input: input[this.items.length],
              expected: "never",
              path: [{
                type: "array",
                origin: "value",
                input,
                key: this.items.length,
                value: input[this.items.length]
              }]
            });
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function strictTupleAsync(items, message$1) {
      return {
        kind: "schema",
        type: "strict_tuple",
        reference: strictTupleAsync,
        expects: "Array",
        async: true,
        items,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (Array.isArray(input)) {
            dataset.typed = true;
            dataset.value = [];
            const itemDatasets = await Promise.all(this.items.map(async (item, key) => {
              const value$1 = input[key];
              return [
                key,
                value$1,
                await item["~run"]({ value: value$1 }, config$1)
              ];
            }));
            for (const [key, value$1, itemDataset] of itemDatasets) {
              if (itemDataset.issues) {
                const pathItem = {
                  type: "array",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of itemDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = itemDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!itemDataset.typed) dataset.typed = false;
              dataset.value.push(itemDataset.value);
            }
            if (!(dataset.issues && config$1.abortEarly) && this.items.length < input.length) _addIssue(this, "type", dataset, config$1, {
              input: input[this.items.length],
              expected: "never",
              path: [{
                type: "array",
                origin: "value",
                input,
                key: this.items.length,
                value: input[this.items.length]
              }]
            });
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function string(message$1) {
      return {
        kind: "schema",
        type: "string",
        reference: string,
        expects: "string",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (typeof dataset.value === "string") dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function symbol(message$1) {
      return {
        kind: "schema",
        type: "symbol",
        reference: symbol,
        expects: "symbol",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (typeof dataset.value === "symbol") dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function tuple(items, message$1) {
      return {
        kind: "schema",
        type: "tuple",
        reference: tuple,
        expects: "Array",
        async: false,
        items,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (Array.isArray(input)) {
            dataset.typed = true;
            dataset.value = [];
            for (let key = 0; key < this.items.length; key++) {
              const value$1 = input[key];
              const itemDataset = this.items[key]["~run"]({ value: value$1 }, config$1);
              if (itemDataset.issues) {
                const pathItem = {
                  type: "array",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of itemDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = itemDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!itemDataset.typed) dataset.typed = false;
              dataset.value.push(itemDataset.value);
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function tupleAsync(items, message$1) {
      return {
        kind: "schema",
        type: "tuple",
        reference: tupleAsync,
        expects: "Array",
        async: true,
        items,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (Array.isArray(input)) {
            dataset.typed = true;
            dataset.value = [];
            const itemDatasets = await Promise.all(this.items.map(async (item, key) => {
              const value$1 = input[key];
              return [
                key,
                value$1,
                await item["~run"]({ value: value$1 }, config$1)
              ];
            }));
            for (const [key, value$1, itemDataset] of itemDatasets) {
              if (itemDataset.issues) {
                const pathItem = {
                  type: "array",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of itemDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = itemDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!itemDataset.typed) dataset.typed = false;
              dataset.value.push(itemDataset.value);
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function tupleWithRest(items, rest, message$1) {
      return {
        kind: "schema",
        type: "tuple_with_rest",
        reference: tupleWithRest,
        expects: "Array",
        async: false,
        items,
        rest,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (Array.isArray(input)) {
            dataset.typed = true;
            dataset.value = [];
            for (let key = 0; key < this.items.length; key++) {
              const value$1 = input[key];
              const itemDataset = this.items[key]["~run"]({ value: value$1 }, config$1);
              if (itemDataset.issues) {
                const pathItem = {
                  type: "array",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of itemDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = itemDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!itemDataset.typed) dataset.typed = false;
              dataset.value.push(itemDataset.value);
            }
            if (!dataset.issues || !config$1.abortEarly) for (let key = this.items.length; key < input.length; key++) {
              const value$1 = input[key];
              const itemDataset = this.rest["~run"]({ value: value$1 }, config$1);
              if (itemDataset.issues) {
                const pathItem = {
                  type: "array",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of itemDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = itemDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!itemDataset.typed) dataset.typed = false;
              dataset.value.push(itemDataset.value);
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function tupleWithRestAsync(items, rest, message$1) {
      return {
        kind: "schema",
        type: "tuple_with_rest",
        reference: tupleWithRestAsync,
        expects: "Array",
        async: true,
        items,
        rest,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (Array.isArray(input)) {
            dataset.typed = true;
            dataset.value = [];
            const [normalDatasets, restDatasets] = await Promise.all([Promise.all(this.items.map(async (item, key) => {
              const value$1 = input[key];
              return [
                key,
                value$1,
                await item["~run"]({ value: value$1 }, config$1)
              ];
            })), Promise.all(input.slice(this.items.length).map(async (value$1, key) => {
              return [
                key + this.items.length,
                value$1,
                await this.rest["~run"]({ value: value$1 }, config$1)
              ];
            }))]);
            for (const [key, value$1, itemDataset] of normalDatasets) {
              if (itemDataset.issues) {
                const pathItem = {
                  type: "array",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of itemDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = itemDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!itemDataset.typed) dataset.typed = false;
              dataset.value.push(itemDataset.value);
            }
            if (!dataset.issues || !config$1.abortEarly) for (const [key, value$1, itemDataset] of restDatasets) {
              if (itemDataset.issues) {
                const pathItem = {
                  type: "array",
                  origin: "value",
                  input,
                  key,
                  value: value$1
                };
                for (const issue of itemDataset.issues) {
                  if (issue.path) issue.path.unshift(pathItem);
                  else issue.path = [pathItem];
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) dataset.issues = itemDataset.issues;
                if (config$1.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!itemDataset.typed) dataset.typed = false;
              dataset.value.push(itemDataset.value);
            }
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function undefined_(message$1) {
      return {
        kind: "schema",
        type: "undefined",
        reference: undefined_,
        expects: "undefined",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value === void 0) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function undefinedable(wrapped, default_) {
      return {
        kind: "schema",
        type: "undefinedable",
        reference: undefinedable,
        expects: `(${wrapped.expects} | undefined)`,
        async: false,
        wrapped,
        default: default_,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value === void 0) {
            if (this.default !== void 0) dataset.value = /* @__PURE__ */ getDefault(this, dataset, config$1);
            if (dataset.value === void 0) {
              dataset.typed = true;
              return dataset;
            }
          }
          return this.wrapped["~run"](dataset, config$1);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function undefinedableAsync(wrapped, default_) {
      return {
        kind: "schema",
        type: "undefinedable",
        reference: undefinedableAsync,
        expects: `(${wrapped.expects} | undefined)`,
        async: true,
        wrapped,
        default: default_,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          if (dataset.value === void 0) {
            if (this.default !== void 0) dataset.value = await /* @__PURE__ */ getDefault(this, dataset, config$1);
            if (dataset.value === void 0) {
              dataset.typed = true;
              return dataset;
            }
          }
          return this.wrapped["~run"](dataset, config$1);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function _subIssues(datasets) {
      let issues;
      if (datasets) for (const dataset of datasets) if (issues) issues.push(...dataset.issues);
      else issues = dataset.issues;
      return issues;
    }
    // @__NO_SIDE_EFFECTS__
    function union(options, message$1) {
      return {
        kind: "schema",
        type: "union",
        reference: union,
        expects: /* @__PURE__ */ _joinExpects(options.map((option) => option.expects), "|"),
        async: false,
        options,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          let validDataset;
          let typedDatasets;
          let untypedDatasets;
          for (const schema of this.options) {
            const optionDataset = schema["~run"]({ value: dataset.value }, config$1);
            if (optionDataset.typed) if (optionDataset.issues) if (typedDatasets) typedDatasets.push(optionDataset);
            else typedDatasets = [optionDataset];
            else {
              validDataset = optionDataset;
              break;
            }
            else if (untypedDatasets) untypedDatasets.push(optionDataset);
            else untypedDatasets = [optionDataset];
          }
          if (validDataset) return validDataset;
          if (typedDatasets) {
            if (typedDatasets.length === 1) return typedDatasets[0];
            _addIssue(this, "type", dataset, config$1, { issues: /* @__PURE__ */ _subIssues(typedDatasets) });
            dataset.typed = true;
          } else if (untypedDatasets?.length === 1) return untypedDatasets[0];
          else _addIssue(this, "type", dataset, config$1, { issues: /* @__PURE__ */ _subIssues(untypedDatasets) });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function unionAsync(options, message$1) {
      return {
        kind: "schema",
        type: "union",
        reference: unionAsync,
        expects: /* @__PURE__ */ _joinExpects(options.map((option) => option.expects), "|"),
        async: true,
        options,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          let validDataset;
          let typedDatasets;
          let untypedDatasets;
          for (const schema of this.options) {
            const optionDataset = await schema["~run"]({ value: dataset.value }, config$1);
            if (optionDataset.typed) if (optionDataset.issues) if (typedDatasets) typedDatasets.push(optionDataset);
            else typedDatasets = [optionDataset];
            else {
              validDataset = optionDataset;
              break;
            }
            else if (untypedDatasets) untypedDatasets.push(optionDataset);
            else untypedDatasets = [optionDataset];
          }
          if (validDataset) return validDataset;
          if (typedDatasets) {
            if (typedDatasets.length === 1) return typedDatasets[0];
            _addIssue(this, "type", dataset, config$1, { issues: /* @__PURE__ */ _subIssues(typedDatasets) });
            dataset.typed = true;
          } else if (untypedDatasets?.length === 1) return untypedDatasets[0];
          else _addIssue(this, "type", dataset, config$1, { issues: /* @__PURE__ */ _subIssues(untypedDatasets) });
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function unknown() {
      return {
        kind: "schema",
        type: "unknown",
        reference: unknown,
        expects: "unknown",
        async: false,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset) {
          dataset.typed = true;
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function variant(key, options, message$1) {
      return {
        kind: "schema",
        type: "variant",
        reference: variant,
        expects: "Object",
        async: false,
        key,
        options,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input && typeof input === "object") {
            let outputDataset;
            let maxDiscriminatorPriority = 0;
            let invalidDiscriminatorKey = this.key;
            let expectedDiscriminators = [];
            const parseOptions = (variant$1, allKeys) => {
              for (const schema of variant$1.options) {
                if (schema.type === "variant") parseOptions(schema, new Set(allKeys).add(schema.key));
                else {
                  let keysAreValid = true;
                  let currentPriority = 0;
                  for (const currentKey of allKeys) {
                    const discriminatorSchema = schema.entries[currentKey];
                    if (currentKey in input ? discriminatorSchema["~run"]({
                      typed: false,
                      value: input[currentKey]
                    }, { abortEarly: true }).issues : discriminatorSchema.type !== "exact_optional" && discriminatorSchema.type !== "optional" && discriminatorSchema.type !== "nullish") {
                      keysAreValid = false;
                      if (invalidDiscriminatorKey !== currentKey && (maxDiscriminatorPriority < currentPriority || maxDiscriminatorPriority === currentPriority && currentKey in input && !(invalidDiscriminatorKey in input))) {
                        maxDiscriminatorPriority = currentPriority;
                        invalidDiscriminatorKey = currentKey;
                        expectedDiscriminators = [];
                      }
                      if (invalidDiscriminatorKey === currentKey) expectedDiscriminators.push(schema.entries[currentKey].expects);
                      break;
                    }
                    currentPriority++;
                  }
                  if (keysAreValid) {
                    const optionDataset = schema["~run"]({ value: input }, config$1);
                    if (!outputDataset || !outputDataset.typed && optionDataset.typed) outputDataset = optionDataset;
                  }
                }
                if (outputDataset && !outputDataset.issues) break;
              }
            };
            parseOptions(this, /* @__PURE__ */ new Set([this.key]));
            if (outputDataset) return outputDataset;
            _addIssue(this, "type", dataset, config$1, {
              input: input[invalidDiscriminatorKey],
              expected: /* @__PURE__ */ _joinExpects(expectedDiscriminators, "|"),
              path: [{
                type: "object",
                origin: "value",
                input,
                key: invalidDiscriminatorKey,
                value: input[invalidDiscriminatorKey]
              }]
            });
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function variantAsync(key, options, message$1) {
      return {
        kind: "schema",
        type: "variant",
        reference: variantAsync,
        expects: "Object",
        async: true,
        key,
        options,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          const input = dataset.value;
          if (input && typeof input === "object") {
            let outputDataset;
            let maxDiscriminatorPriority = 0;
            let invalidDiscriminatorKey = this.key;
            let expectedDiscriminators = [];
            const parseOptions = async (variant$1, allKeys) => {
              for (const schema of variant$1.options) {
                if (schema.type === "variant") await parseOptions(schema, new Set(allKeys).add(schema.key));
                else {
                  let keysAreValid = true;
                  let currentPriority = 0;
                  for (const currentKey of allKeys) {
                    const discriminatorSchema = schema.entries[currentKey];
                    if (currentKey in input ? (await discriminatorSchema["~run"]({
                      typed: false,
                      value: input[currentKey]
                    }, { abortEarly: true })).issues : discriminatorSchema.type !== "exact_optional" && discriminatorSchema.type !== "optional" && discriminatorSchema.type !== "nullish") {
                      keysAreValid = false;
                      if (invalidDiscriminatorKey !== currentKey && (maxDiscriminatorPriority < currentPriority || maxDiscriminatorPriority === currentPriority && currentKey in input && !(invalidDiscriminatorKey in input))) {
                        maxDiscriminatorPriority = currentPriority;
                        invalidDiscriminatorKey = currentKey;
                        expectedDiscriminators = [];
                      }
                      if (invalidDiscriminatorKey === currentKey) expectedDiscriminators.push(schema.entries[currentKey].expects);
                      break;
                    }
                    currentPriority++;
                  }
                  if (keysAreValid) {
                    const optionDataset = await schema["~run"]({ value: input }, config$1);
                    if (!outputDataset || !outputDataset.typed && optionDataset.typed) outputDataset = optionDataset;
                  }
                }
                if (outputDataset && !outputDataset.issues) break;
              }
            };
            await parseOptions(this, /* @__PURE__ */ new Set([this.key]));
            if (outputDataset) return outputDataset;
            _addIssue(this, "type", dataset, config$1, {
              input: input[invalidDiscriminatorKey],
              expected: /* @__PURE__ */ _joinExpects(expectedDiscriminators, "|"),
              path: [{
                type: "object",
                origin: "value",
                input,
                key: invalidDiscriminatorKey,
                value: input[invalidDiscriminatorKey]
              }]
            });
          } else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function void_(message$1) {
      return {
        kind: "schema",
        type: "void",
        reference: void_,
        expects: "void",
        async: false,
        message: message$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          if (dataset.value === void 0) dataset.typed = true;
          else _addIssue(this, "type", dataset, config$1);
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function keyof(schema, message$1) {
      return /* @__PURE__ */ picklist(Object.keys(schema.entries), message$1);
    }
    // @__NO_SIDE_EFFECTS__
    function message(schema, message_) {
      return {
        ...schema,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          return schema["~run"](dataset, {
            ...config$1,
            message: message_
          });
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function omit(schema, keys) {
      const entries$1 = { ...schema.entries };
      for (const key of keys) delete entries$1[key];
      return {
        ...schema,
        entries: entries$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        }
      };
    }
    function parse(schema, input, config$1) {
      const dataset = schema["~run"]({ value: input }, /* @__PURE__ */ getGlobalConfig(config$1));
      if (dataset.issues) throw new ValiError(dataset.issues);
      return dataset.value;
    }
    async function parseAsync(schema, input, config$1) {
      const dataset = await schema["~run"]({ value: input }, /* @__PURE__ */ getGlobalConfig(config$1));
      if (dataset.issues) throw new ValiError(dataset.issues);
      return dataset.value;
    }
    // @__NO_SIDE_EFFECTS__
    function parser(schema, config$1) {
      const func = (input) => parse(schema, input, config$1);
      func.schema = schema;
      func.config = config$1;
      return func;
    }
    // @__NO_SIDE_EFFECTS__
    function parserAsync(schema, config$1) {
      const func = (input) => parseAsync(schema, input, config$1);
      func.schema = schema;
      func.config = config$1;
      return func;
    }
    // @__NO_SIDE_EFFECTS__
    function partial(schema, keys) {
      const entries$1 = {};
      for (const key in schema.entries) entries$1[key] = !keys || keys.includes(key) ? /* @__PURE__ */ optional(schema.entries[key]) : schema.entries[key];
      return {
        ...schema,
        entries: entries$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function partialAsync(schema, keys) {
      const entries$1 = {};
      for (const key in schema.entries) entries$1[key] = !keys || keys.includes(key) ? /* @__PURE__ */ optionalAsync(schema.entries[key]) : schema.entries[key];
      return {
        ...schema,
        entries: entries$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function pick(schema, keys) {
      const entries$1 = {};
      for (const key of keys) entries$1[key] = schema.entries[key];
      return {
        ...schema,
        entries: entries$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function pipe(...pipe$1) {
      return {
        ...pipe$1[0],
        pipe: pipe$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        "~run"(dataset, config$1) {
          for (const item of pipe$1) if (item.kind !== "metadata") {
            if (dataset.issues && (item.kind === "schema" || item.kind === "transformation")) {
              dataset.typed = false;
              break;
            }
            if (!dataset.issues || !config$1.abortEarly && !config$1.abortPipeEarly) dataset = item["~run"](dataset, config$1);
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function pipeAsync(...pipe$1) {
      return {
        ...pipe$1[0],
        pipe: pipe$1,
        async: true,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        },
        async "~run"(dataset, config$1) {
          for (const item of pipe$1) if (item.kind !== "metadata") {
            if (dataset.issues && (item.kind === "schema" || item.kind === "transformation")) {
              dataset.typed = false;
              break;
            }
            if (!dataset.issues || !config$1.abortEarly && !config$1.abortPipeEarly) dataset = await item["~run"](dataset, config$1);
          }
          return dataset;
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function required(schema, arg2, arg3) {
      const keys = Array.isArray(arg2) ? arg2 : void 0;
      const message$1 = Array.isArray(arg2) ? arg3 : arg2;
      const entries$1 = {};
      for (const key in schema.entries) entries$1[key] = !keys || keys.includes(key) ? /* @__PURE__ */ nonOptional(schema.entries[key], message$1) : schema.entries[key];
      return {
        ...schema,
        entries: entries$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function requiredAsync(schema, arg2, arg3) {
      const keys = Array.isArray(arg2) ? arg2 : void 0;
      const message$1 = Array.isArray(arg2) ? arg3 : arg2;
      const entries$1 = {};
      for (const key in schema.entries) entries$1[key] = !keys || keys.includes(key) ? /* @__PURE__ */ nonOptionalAsync(schema.entries[key], message$1) : schema.entries[key];
      return {
        ...schema,
        entries: entries$1,
        get "~standard"() {
          return /* @__PURE__ */ _getStandardProps(this);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function safeParse(schema, input, config$1) {
      const dataset = schema["~run"]({ value: input }, /* @__PURE__ */ getGlobalConfig(config$1));
      return {
        typed: dataset.typed,
        success: !dataset.issues,
        output: dataset.value,
        issues: dataset.issues
      };
    }
    // @__NO_SIDE_EFFECTS__
    async function safeParseAsync(schema, input, config$1) {
      const dataset = await schema["~run"]({ value: input }, /* @__PURE__ */ getGlobalConfig(config$1));
      return {
        typed: dataset.typed,
        success: !dataset.issues,
        output: dataset.value,
        issues: dataset.issues
      };
    }
    // @__NO_SIDE_EFFECTS__
    function safeParser(schema, config$1) {
      const func = (input) => /* @__PURE__ */ safeParse(schema, input, config$1);
      func.schema = schema;
      func.config = config$1;
      return func;
    }
    // @__NO_SIDE_EFFECTS__
    function safeParserAsync(schema, config$1) {
      const func = (input) => /* @__PURE__ */ safeParseAsync(schema, input, config$1);
      func.schema = schema;
      func.config = config$1;
      return func;
    }
    // @__NO_SIDE_EFFECTS__
    function summarize(issues) {
      let summary = "";
      for (const issue of issues) {
        if (summary) summary += "\n";
        summary += `\xD7 ${issue.message}`;
        const dotPath = /* @__PURE__ */ getDotPath(issue);
        if (dotPath) summary += `
  \u2192 at ${dotPath}`;
      }
      return summary;
    }
    // @__NO_SIDE_EFFECTS__
    function unwrap(schema) {
      return schema.wrapped;
    }
    exports.BASE64_REGEX = BASE64_REGEX;
    exports.BIC_REGEX = BIC_REGEX;
    exports.CUID2_REGEX = CUID2_REGEX;
    exports.DECIMAL_REGEX = DECIMAL_REGEX;
    exports.DIGITS_REGEX = DIGITS_REGEX;
    exports.DOMAIN_REGEX = DOMAIN_REGEX;
    exports.EMAIL_REGEX = EMAIL_REGEX;
    exports.EMOJI_REGEX = EMOJI_REGEX;
    exports.HEXADECIMAL_REGEX = HEXADECIMAL_REGEX;
    exports.HEX_COLOR_REGEX = HEX_COLOR_REGEX;
    exports.IMEI_REGEX = IMEI_REGEX;
    exports.IPV4_REGEX = IPV4_REGEX;
    exports.IPV6_REGEX = IPV6_REGEX;
    exports.IP_REGEX = IP_REGEX;
    exports.ISO_DATE_REGEX = ISO_DATE_REGEX;
    exports.ISO_DATE_TIME_REGEX = ISO_DATE_TIME_REGEX;
    exports.ISO_TIMESTAMP_REGEX = ISO_TIMESTAMP_REGEX;
    exports.ISO_TIME_REGEX = ISO_TIME_REGEX;
    exports.ISO_TIME_SECOND_REGEX = ISO_TIME_SECOND_REGEX;
    exports.ISO_WEEK_REGEX = ISO_WEEK_REGEX;
    exports.ISRC_REGEX = ISRC_REGEX;
    exports.JWS_COMPACT_REGEX = JWS_COMPACT_REGEX;
    exports.MAC48_REGEX = MAC48_REGEX;
    exports.MAC64_REGEX = MAC64_REGEX;
    exports.MAC_REGEX = MAC_REGEX;
    exports.NANO_ID_REGEX = NANO_ID_REGEX;
    exports.OCTAL_REGEX = OCTAL_REGEX;
    exports.RFC_EMAIL_REGEX = RFC_EMAIL_REGEX;
    exports.SLUG_REGEX = SLUG_REGEX;
    exports.ULID_REGEX = ULID_REGEX;
    exports.UUID_REGEX = UUID_REGEX;
    exports.ValiError = ValiError;
    exports._addIssue = _addIssue;
    exports._cloneDataset = _cloneDataset;
    exports._getByteCount = _getByteCount;
    exports._getGraphemeCount = _getGraphemeCount;
    exports._getLastMetadata = _getLastMetadata;
    exports._getStandardProps = _getStandardProps;
    exports._getWordCount = _getWordCount;
    exports._isLuhnAlgo = _isLuhnAlgo;
    exports._isValidObjectKey = _isValidObjectKey;
    exports._joinExpects = _joinExpects;
    exports._stringify = _stringify;
    exports.any = any;
    exports.args = args;
    exports.argsAsync = argsAsync;
    exports.array = array;
    exports.arrayAsync = arrayAsync;
    exports.assert = assert;
    exports.awaitAsync = awaitAsync;
    exports.base64 = base642;
    exports.bic = bic;
    exports.bigint = bigint;
    exports.blob = blob;
    exports.boolean = boolean;
    exports.brand = brand;
    exports.bytes = bytes2;
    exports.cache = cache;
    exports.cacheAsync = cacheAsync;
    exports.check = check;
    exports.checkAsync = checkAsync;
    exports.checkItems = checkItems;
    exports.checkItemsAsync = checkItemsAsync;
    exports.config = config;
    exports.creditCard = creditCard;
    exports.cuid2 = cuid2;
    exports.custom = custom;
    exports.customAsync = customAsync;
    exports.date = date;
    exports.decimal = decimal;
    exports.deleteGlobalConfig = deleteGlobalConfig;
    exports.deleteGlobalMessage = deleteGlobalMessage;
    exports.deleteSchemaMessage = deleteSchemaMessage;
    exports.deleteSpecificMessage = deleteSpecificMessage;
    exports.description = description;
    exports.digits = digits;
    exports.domain = domain;
    exports.email = email;
    exports.emoji = emoji;
    exports.empty = empty;
    exports.endsWith = endsWith;
    exports.entries = entries;
    exports.entriesFromList = entriesFromList;
    exports.entriesFromObjects = entriesFromObjects;
    exports.enum = enum_;
    exports.enum_ = enum_;
    exports.everyItem = everyItem;
    exports.exactOptional = exactOptional;
    exports.exactOptionalAsync = exactOptionalAsync;
    exports.examples = examples;
    exports.excludes = excludes;
    exports.fallback = fallback;
    exports.fallbackAsync = fallbackAsync;
    exports.file = file;
    exports.filterItems = filterItems;
    exports.findItem = findItem;
    exports.finite = finite;
    exports.flatten = flatten;
    exports.flavor = flavor;
    exports.forward = forward;
    exports.forwardAsync = forwardAsync;
    exports.function = function_;
    exports.function_ = function_;
    exports.getDefault = getDefault;
    exports.getDefaults = getDefaults;
    exports.getDefaultsAsync = getDefaultsAsync;
    exports.getDescription = getDescription;
    exports.getDotPath = getDotPath;
    exports.getExamples = getExamples;
    exports.getFallback = getFallback;
    exports.getFallbacks = getFallbacks;
    exports.getFallbacksAsync = getFallbacksAsync;
    exports.getGlobalConfig = getGlobalConfig;
    exports.getGlobalMessage = getGlobalMessage;
    exports.getMetadata = getMetadata;
    exports.getSchemaMessage = getSchemaMessage;
    exports.getSpecificMessage = getSpecificMessage;
    exports.getTitle = getTitle;
    exports.graphemes = graphemes;
    exports.gtValue = gtValue;
    exports.guard = guard;
    exports.hash = hash2;
    exports.hexColor = hexColor;
    exports.hexadecimal = hexadecimal;
    exports.imei = imei;
    exports.includes = includes;
    exports.instance = instance;
    exports.integer = integer;
    exports.intersect = intersect;
    exports.intersectAsync = intersectAsync;
    exports.ip = ip;
    exports.ipv4 = ipv4;
    exports.ipv6 = ipv6;
    exports.is = is;
    exports.isOfKind = isOfKind;
    exports.isOfType = isOfType;
    exports.isValiError = isValiError;
    exports.isbn = isbn;
    exports.isoDate = isoDate;
    exports.isoDateTime = isoDateTime;
    exports.isoTime = isoTime;
    exports.isoTimeSecond = isoTimeSecond;
    exports.isoTimestamp = isoTimestamp;
    exports.isoWeek = isoWeek;
    exports.isrc = isrc;
    exports.jwsCompact = jwsCompact;
    exports.keyof = keyof;
    exports.lazy = lazy;
    exports.lazyAsync = lazyAsync;
    exports.length = length;
    exports.literal = literal;
    exports.looseObject = looseObject;
    exports.looseObjectAsync = looseObjectAsync;
    exports.looseTuple = looseTuple;
    exports.looseTupleAsync = looseTupleAsync;
    exports.ltValue = ltValue;
    exports.mac = mac;
    exports.mac48 = mac48;
    exports.mac64 = mac64;
    exports.map = map;
    exports.mapAsync = mapAsync;
    exports.mapItems = mapItems;
    exports.maxBytes = maxBytes;
    exports.maxEntries = maxEntries;
    exports.maxGraphemes = maxGraphemes;
    exports.maxLength = maxLength;
    exports.maxSize = maxSize;
    exports.maxValue = maxValue;
    exports.maxWords = maxWords;
    exports.message = message;
    exports.metadata = metadata;
    exports.mimeType = mimeType;
    exports.minBytes = minBytes;
    exports.minEntries = minEntries;
    exports.minGraphemes = minGraphemes;
    exports.minLength = minLength;
    exports.minSize = minSize;
    exports.minValue = minValue;
    exports.minWords = minWords;
    exports.multipleOf = multipleOf;
    exports.nan = nan;
    exports.nanoid = nanoid;
    exports.never = never;
    exports.nonEmpty = nonEmpty;
    exports.nonNullable = nonNullable;
    exports.nonNullableAsync = nonNullableAsync;
    exports.nonNullish = nonNullish;
    exports.nonNullishAsync = nonNullishAsync;
    exports.nonOptional = nonOptional;
    exports.nonOptionalAsync = nonOptionalAsync;
    exports.normalize = normalize2;
    exports.notBytes = notBytes;
    exports.notEntries = notEntries;
    exports.notGraphemes = notGraphemes;
    exports.notLength = notLength;
    exports.notSize = notSize;
    exports.notValue = notValue;
    exports.notValues = notValues;
    exports.notWords = notWords;
    exports.null = null_;
    exports.null_ = null_;
    exports.nullable = nullable;
    exports.nullableAsync = nullableAsync;
    exports.nullish = nullish;
    exports.nullishAsync = nullishAsync;
    exports.number = number;
    exports.object = object;
    exports.objectAsync = objectAsync;
    exports.objectWithRest = objectWithRest;
    exports.objectWithRestAsync = objectWithRestAsync;
    exports.octal = octal;
    exports.omit = omit;
    exports.optional = optional;
    exports.optionalAsync = optionalAsync;
    exports.parse = parse;
    exports.parseAsync = parseAsync;
    exports.parseBoolean = parseBoolean;
    exports.parseJson = parseJson;
    exports.parser = parser;
    exports.parserAsync = parserAsync;
    exports.partial = partial;
    exports.partialAsync = partialAsync;
    exports.partialCheck = partialCheck;
    exports.partialCheckAsync = partialCheckAsync;
    exports.pick = pick;
    exports.picklist = picklist;
    exports.pipe = pipe;
    exports.pipeAsync = pipeAsync;
    exports.promise = promise;
    exports.rawCheck = rawCheck;
    exports.rawCheckAsync = rawCheckAsync;
    exports.rawTransform = rawTransform;
    exports.rawTransformAsync = rawTransformAsync;
    exports.readonly = readonly;
    exports.record = record;
    exports.recordAsync = recordAsync;
    exports.reduceItems = reduceItems;
    exports.regex = regex;
    exports.required = required;
    exports.requiredAsync = requiredAsync;
    exports.returns = returns;
    exports.returnsAsync = returnsAsync;
    exports.rfcEmail = rfcEmail;
    exports.safeInteger = safeInteger;
    exports.safeParse = safeParse;
    exports.safeParseAsync = safeParseAsync;
    exports.safeParser = safeParser;
    exports.safeParserAsync = safeParserAsync;
    exports.set = set;
    exports.setAsync = setAsync;
    exports.setGlobalConfig = setGlobalConfig;
    exports.setGlobalMessage = setGlobalMessage;
    exports.setSchemaMessage = setSchemaMessage;
    exports.setSpecificMessage = setSpecificMessage;
    exports.size = size;
    exports.slug = slug;
    exports.someItem = someItem;
    exports.sortItems = sortItems;
    exports.startsWith = startsWith;
    exports.strictObject = strictObject;
    exports.strictObjectAsync = strictObjectAsync;
    exports.strictTuple = strictTuple;
    exports.strictTupleAsync = strictTupleAsync;
    exports.string = string;
    exports.stringifyJson = stringifyJson;
    exports.summarize = summarize;
    exports.symbol = symbol;
    exports.title = title;
    exports.toBigint = toBigint;
    exports.toBoolean = toBoolean;
    exports.toDate = toDate;
    exports.toLowerCase = toLowerCase;
    exports.toMaxValue = toMaxValue;
    exports.toMinValue = toMinValue;
    exports.toNumber = toNumber;
    exports.toString = toString;
    exports.toUpperCase = toUpperCase;
    exports.transform = transform;
    exports.transformAsync = transformAsync;
    exports.trim = trim;
    exports.trimEnd = trimEnd;
    exports.trimStart = trimStart;
    exports.tuple = tuple;
    exports.tupleAsync = tupleAsync;
    exports.tupleWithRest = tupleWithRest;
    exports.tupleWithRestAsync = tupleWithRestAsync;
    exports.ulid = ulid;
    exports.undefined = undefined_;
    exports.undefined_ = undefined_;
    exports.undefinedable = undefinedable;
    exports.undefinedableAsync = undefinedableAsync;
    exports.union = union;
    exports.unionAsync = unionAsync;
    exports.unknown = unknown;
    exports.unwrap = unwrap;
    exports.url = url;
    exports.uuid = uuid;
    exports.value = value;
    exports.values = values;
    exports.variant = variant;
    exports.variantAsync = variantAsync;
    exports.void = void_;
    exports.void_ = void_;
    exports.words = words;
  }
});

// node_modules/bip32/src/cjs/types.cjs
var require_types = __commonJS({
  "node_modules/bip32/src/cjs/types.cjs"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      var desc = Object.getOwnPropertyDescriptor(m, k);
      if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m[k];
        } };
      }
      Object.defineProperty(o, k2, desc);
    }) : (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    }));
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? (function(o, v2) {
      Object.defineProperty(o, "default", { enumerable: true, value: v2 });
    }) : function(o, v2) {
      o["default"] = v2;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule) return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.Bip32PathSchema = exports.NetworkSchema = exports.Buffer33Bytes = exports.Buffer256Bit = exports.Uint31Schema = exports.Uint32Schema = void 0;
    var v = __importStar(require_dist());
    exports.Uint32Schema = v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(4294967295));
    exports.Uint31Schema = v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(2147483647));
    var Uint8Schema = v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(255));
    exports.Buffer256Bit = v.pipe(v.instance(Uint8Array), v.length(32));
    exports.Buffer33Bytes = v.pipe(v.instance(Uint8Array), v.length(33));
    exports.NetworkSchema = v.object({
      wif: Uint8Schema,
      bip32: v.object({
        public: exports.Uint32Schema,
        private: exports.Uint32Schema
      })
    });
    exports.Bip32PathSchema = v.pipe(v.string(), v.regex(/^(m\/)?(\d+'?\/)*\d+'?$/));
  }
});

// node_modules/bs58check/node_modules/@noble/hashes/crypto.js
var require_crypto4 = __commonJS({
  "node_modules/bs58check/node_modules/@noble/hashes/crypto.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.crypto = void 0;
    exports.crypto = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0;
  }
});

// node_modules/bs58check/node_modules/@noble/hashes/utils.js
var require_utils3 = __commonJS({
  "node_modules/bs58check/node_modules/@noble/hashes/utils.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.wrapXOFConstructorWithOpts = exports.wrapConstructorWithOpts = exports.wrapConstructor = exports.Hash = exports.nextTick = exports.swap32IfBE = exports.byteSwapIfBE = exports.swap8IfBE = exports.isLE = void 0;
    exports.isBytes = isBytes4;
    exports.anumber = anumber3;
    exports.abytes = abytes4;
    exports.ahash = ahash2;
    exports.aexists = aexists2;
    exports.aoutput = aoutput2;
    exports.u8 = u8;
    exports.u32 = u322;
    exports.clean = clean2;
    exports.createView = createView2;
    exports.rotr = rotr2;
    exports.rotl = rotl;
    exports.byteSwap = byteSwap2;
    exports.byteSwap32 = byteSwap322;
    exports.bytesToHex = bytesToHex2;
    exports.hexToBytes = hexToBytes2;
    exports.asyncLoop = asyncLoop;
    exports.utf8ToBytes = utf8ToBytes;
    exports.bytesToUtf8 = bytesToUtf8;
    exports.toBytes = toBytes;
    exports.kdfInputToBytes = kdfInputToBytes;
    exports.concatBytes = concatBytes2;
    exports.checkOpts = checkOpts;
    exports.createHasher = createHasher2;
    exports.createOptHasher = createOptHasher;
    exports.createXOFer = createXOFer;
    exports.randomBytes = randomBytes2;
    var crypto_1 = require_crypto4();
    function isBytes4(a) {
      return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
    }
    function anumber3(n) {
      if (!Number.isSafeInteger(n) || n < 0)
        throw new Error("positive integer expected, got " + n);
    }
    function abytes4(b, ...lengths2) {
      if (!isBytes4(b))
        throw new Error("Uint8Array expected");
      if (lengths2.length > 0 && !lengths2.includes(b.length))
        throw new Error("Uint8Array expected of length " + lengths2 + ", got length=" + b.length);
    }
    function ahash2(h) {
      if (typeof h !== "function" || typeof h.create !== "function")
        throw new Error("Hash should be wrapped by utils.createHasher");
      anumber3(h.outputLen);
      anumber3(h.blockLen);
    }
    function aexists2(instance, checkFinished = true) {
      if (instance.destroyed)
        throw new Error("Hash instance has been destroyed");
      if (checkFinished && instance.finished)
        throw new Error("Hash#digest() has already been called");
    }
    function aoutput2(out, instance) {
      abytes4(out);
      const min = instance.outputLen;
      if (out.length < min) {
        throw new Error("digestInto() expects output buffer of length at least " + min);
      }
    }
    function u8(arr) {
      return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
    }
    function u322(arr) {
      return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
    }
    function clean2(...arrays) {
      for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
      }
    }
    function createView2(arr) {
      return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    }
    function rotr2(word, shift) {
      return word << 32 - shift | word >>> shift;
    }
    function rotl(word, shift) {
      return word << shift | word >>> 32 - shift >>> 0;
    }
    exports.isLE = (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
    function byteSwap2(word) {
      return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
    }
    exports.swap8IfBE = exports.isLE ? (n) => n : (n) => byteSwap2(n);
    exports.byteSwapIfBE = exports.swap8IfBE;
    function byteSwap322(arr) {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = byteSwap2(arr[i]);
      }
      return arr;
    }
    exports.swap32IfBE = exports.isLE ? (u) => u : byteSwap322;
    var hasHexBuiltin2 = /* @__PURE__ */ (() => (
      // @ts-ignore
      typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
    ))();
    var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
    function bytesToHex2(bytes2) {
      abytes4(bytes2);
      if (hasHexBuiltin2)
        return bytes2.toHex();
      let hex2 = "";
      for (let i = 0; i < bytes2.length; i++) {
        hex2 += hexes[bytes2[i]];
      }
      return hex2;
    }
    var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
    function asciiToBase16(ch) {
      if (ch >= asciis._0 && ch <= asciis._9)
        return ch - asciis._0;
      if (ch >= asciis.A && ch <= asciis.F)
        return ch - (asciis.A - 10);
      if (ch >= asciis.a && ch <= asciis.f)
        return ch - (asciis.a - 10);
      return;
    }
    function hexToBytes2(hex2) {
      if (typeof hex2 !== "string")
        throw new Error("hex string expected, got " + typeof hex2);
      if (hasHexBuiltin2)
        return Uint8Array.fromHex(hex2);
      const hl = hex2.length;
      const al = hl / 2;
      if (hl % 2)
        throw new Error("hex string expected, got unpadded hex of length " + hl);
      const array = new Uint8Array(al);
      for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex2.charCodeAt(hi));
        const n2 = asciiToBase16(hex2.charCodeAt(hi + 1));
        if (n1 === void 0 || n2 === void 0) {
          const char = hex2[hi] + hex2[hi + 1];
          throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2;
      }
      return array;
    }
    var nextTick = async () => {
    };
    exports.nextTick = nextTick;
    async function asyncLoop(iters, tick, cb) {
      let ts = Date.now();
      for (let i = 0; i < iters; i++) {
        cb(i);
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick)
          continue;
        await (0, exports.nextTick)();
        ts += diff;
      }
    }
    function utf8ToBytes(str2) {
      if (typeof str2 !== "string")
        throw new Error("string expected");
      return new Uint8Array(new TextEncoder().encode(str2));
    }
    function bytesToUtf8(bytes2) {
      return new TextDecoder().decode(bytes2);
    }
    function toBytes(data) {
      if (typeof data === "string")
        data = utf8ToBytes(data);
      abytes4(data);
      return data;
    }
    function kdfInputToBytes(data) {
      if (typeof data === "string")
        data = utf8ToBytes(data);
      abytes4(data);
      return data;
    }
    function concatBytes2(...arrays) {
      let sum = 0;
      for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        abytes4(a);
        sum += a.length;
      }
      const res = new Uint8Array(sum);
      for (let i = 0, pad = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
      }
      return res;
    }
    function checkOpts(defaults, opts) {
      if (opts !== void 0 && {}.toString.call(opts) !== "[object Object]")
        throw new Error("options should be object or undefined");
      const merged = Object.assign(defaults, opts);
      return merged;
    }
    var Hash = class {
    };
    exports.Hash = Hash;
    function createHasher2(hashCons) {
      const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
      const tmp = hashCons();
      hashC.outputLen = tmp.outputLen;
      hashC.blockLen = tmp.blockLen;
      hashC.create = () => hashCons();
      return hashC;
    }
    function createOptHasher(hashCons) {
      const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
      const tmp = hashCons({});
      hashC.outputLen = tmp.outputLen;
      hashC.blockLen = tmp.blockLen;
      hashC.create = (opts) => hashCons(opts);
      return hashC;
    }
    function createXOFer(hashCons) {
      const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
      const tmp = hashCons({});
      hashC.outputLen = tmp.outputLen;
      hashC.blockLen = tmp.blockLen;
      hashC.create = (opts) => hashCons(opts);
      return hashC;
    }
    exports.wrapConstructor = createHasher2;
    exports.wrapConstructorWithOpts = createOptHasher;
    exports.wrapXOFConstructorWithOpts = createXOFer;
    function randomBytes2(bytesLength = 32) {
      if (crypto_1.crypto && typeof crypto_1.crypto.getRandomValues === "function") {
        return crypto_1.crypto.getRandomValues(new Uint8Array(bytesLength));
      }
      if (crypto_1.crypto && typeof crypto_1.crypto.randomBytes === "function") {
        return Uint8Array.from(crypto_1.crypto.randomBytes(bytesLength));
      }
      throw new Error("crypto.getRandomValues must be defined");
    }
  }
});

// node_modules/bs58check/node_modules/@noble/hashes/_md.js
var require_md3 = __commonJS({
  "node_modules/bs58check/node_modules/@noble/hashes/_md.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.SHA512_IV = exports.SHA384_IV = exports.SHA224_IV = exports.SHA256_IV = exports.HashMD = void 0;
    exports.setBigUint64 = setBigUint64;
    exports.Chi = Chi2;
    exports.Maj = Maj2;
    var utils_ts_1 = require_utils3();
    function setBigUint64(view, byteOffset, value, isLE2) {
      if (typeof view.setBigUint64 === "function")
        return view.setBigUint64(byteOffset, value, isLE2);
      const _32n2 = BigInt(32);
      const _u32_max = BigInt(4294967295);
      const wh = Number(value >> _32n2 & _u32_max);
      const wl = Number(value & _u32_max);
      const h = isLE2 ? 4 : 0;
      const l = isLE2 ? 0 : 4;
      view.setUint32(byteOffset + h, wh, isLE2);
      view.setUint32(byteOffset + l, wl, isLE2);
    }
    function Chi2(a, b, c) {
      return a & b ^ ~a & c;
    }
    function Maj2(a, b, c) {
      return a & b ^ a & c ^ b & c;
    }
    var HashMD2 = class extends utils_ts_1.Hash {
      constructor(blockLen, outputLen, padOffset, isLE2) {
        super();
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE2;
        this.buffer = new Uint8Array(blockLen);
        this.view = (0, utils_ts_1.createView)(this.buffer);
      }
      update(data) {
        (0, utils_ts_1.aexists)(this);
        data = (0, utils_ts_1.toBytes)(data);
        (0, utils_ts_1.abytes)(data);
        const { view, buffer, blockLen } = this;
        const len = data.length;
        for (let pos = 0; pos < len; ) {
          const take = Math.min(blockLen - this.pos, len - pos);
          if (take === blockLen) {
            const dataView = (0, utils_ts_1.createView)(data);
            for (; blockLen <= len - pos; pos += blockLen)
              this.process(dataView, pos);
            continue;
          }
          buffer.set(data.subarray(pos, pos + take), this.pos);
          this.pos += take;
          pos += take;
          if (this.pos === blockLen) {
            this.process(view, 0);
            this.pos = 0;
          }
        }
        this.length += data.length;
        this.roundClean();
        return this;
      }
      digestInto(out) {
        (0, utils_ts_1.aexists)(this);
        (0, utils_ts_1.aoutput)(out, this);
        this.finished = true;
        const { buffer, view, blockLen, isLE: isLE2 } = this;
        let { pos } = this;
        buffer[pos++] = 128;
        (0, utils_ts_1.clean)(this.buffer.subarray(pos));
        if (this.padOffset > blockLen - pos) {
          this.process(view, 0);
          pos = 0;
        }
        for (let i = pos; i < blockLen; i++)
          buffer[i] = 0;
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
        this.process(view, 0);
        const oview = (0, utils_ts_1.createView)(out);
        const len = this.outputLen;
        if (len % 4)
          throw new Error("_sha2: outputLen should be aligned to 32bit");
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
          throw new Error("_sha2: outputLen bigger than state");
        for (let i = 0; i < outLen; i++)
          oview.setUint32(4 * i, state[i], isLE2);
      }
      digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
      }
      _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.destroyed = destroyed;
        to.finished = finished;
        to.length = length;
        to.pos = pos;
        if (length % blockLen)
          to.buffer.set(buffer);
        return to;
      }
      clone() {
        return this._cloneInto();
      }
    };
    exports.HashMD = HashMD2;
    exports.SHA256_IV = Uint32Array.from([
      1779033703,
      3144134277,
      1013904242,
      2773480762,
      1359893119,
      2600822924,
      528734635,
      1541459225
    ]);
    exports.SHA224_IV = Uint32Array.from([
      3238371032,
      914150663,
      812702999,
      4144912697,
      4290775857,
      1750603025,
      1694076839,
      3204075428
    ]);
    exports.SHA384_IV = Uint32Array.from([
      3418070365,
      3238371032,
      1654270250,
      914150663,
      2438529370,
      812702999,
      355462360,
      4144912697,
      1731405415,
      4290775857,
      2394180231,
      1750603025,
      3675008525,
      1694076839,
      1203062813,
      3204075428
    ]);
    exports.SHA512_IV = Uint32Array.from([
      1779033703,
      4089235720,
      3144134277,
      2227873595,
      1013904242,
      4271175723,
      2773480762,
      1595750129,
      1359893119,
      2917565137,
      2600822924,
      725511199,
      528734635,
      4215389547,
      1541459225,
      327033209
    ]);
  }
});

// node_modules/bs58check/node_modules/@noble/hashes/_u64.js
var require_u643 = __commonJS({
  "node_modules/bs58check/node_modules/@noble/hashes/_u64.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.toBig = exports.shrSL = exports.shrSH = exports.rotrSL = exports.rotrSH = exports.rotrBL = exports.rotrBH = exports.rotr32L = exports.rotr32H = exports.rotlSL = exports.rotlSH = exports.rotlBL = exports.rotlBH = exports.add5L = exports.add5H = exports.add4L = exports.add4H = exports.add3L = exports.add3H = void 0;
    exports.add = add2;
    exports.fromBig = fromBig2;
    exports.split = split2;
    var U32_MASK642 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
    var _32n2 = /* @__PURE__ */ BigInt(32);
    function fromBig2(n, le = false) {
      if (le)
        return { h: Number(n & U32_MASK642), l: Number(n >> _32n2 & U32_MASK642) };
      return { h: Number(n >> _32n2 & U32_MASK642) | 0, l: Number(n & U32_MASK642) | 0 };
    }
    function split2(lst, le = false) {
      const len = lst.length;
      let Ah = new Uint32Array(len);
      let Al = new Uint32Array(len);
      for (let i = 0; i < len; i++) {
        const { h, l } = fromBig2(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
      }
      return [Ah, Al];
    }
    var toBig = (h, l) => BigInt(h >>> 0) << _32n2 | BigInt(l >>> 0);
    exports.toBig = toBig;
    var shrSH2 = (h, _l, s) => h >>> s;
    exports.shrSH = shrSH2;
    var shrSL2 = (h, l, s) => h << 32 - s | l >>> s;
    exports.shrSL = shrSL2;
    var rotrSH2 = (h, l, s) => h >>> s | l << 32 - s;
    exports.rotrSH = rotrSH2;
    var rotrSL2 = (h, l, s) => h << 32 - s | l >>> s;
    exports.rotrSL = rotrSL2;
    var rotrBH2 = (h, l, s) => h << 64 - s | l >>> s - 32;
    exports.rotrBH = rotrBH2;
    var rotrBL2 = (h, l, s) => h >>> s - 32 | l << 64 - s;
    exports.rotrBL = rotrBL2;
    var rotr32H = (_h, l) => l;
    exports.rotr32H = rotr32H;
    var rotr32L = (h, _l) => h;
    exports.rotr32L = rotr32L;
    var rotlSH2 = (h, l, s) => h << s | l >>> 32 - s;
    exports.rotlSH = rotlSH2;
    var rotlSL2 = (h, l, s) => l << s | h >>> 32 - s;
    exports.rotlSL = rotlSL2;
    var rotlBH2 = (h, l, s) => l << s - 32 | h >>> 64 - s;
    exports.rotlBH = rotlBH2;
    var rotlBL2 = (h, l, s) => h << s - 32 | l >>> 64 - s;
    exports.rotlBL = rotlBL2;
    function add2(Ah, Al, Bh, Bl) {
      const l = (Al >>> 0) + (Bl >>> 0);
      return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
    }
    var add3L2 = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
    exports.add3L = add3L2;
    var add3H2 = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
    exports.add3H = add3H2;
    var add4L2 = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
    exports.add4L = add4L2;
    var add4H2 = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
    exports.add4H = add4H2;
    var add5L2 = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
    exports.add5L = add5L2;
    var add5H2 = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
    exports.add5H = add5H2;
    var u64 = {
      fromBig: fromBig2,
      split: split2,
      toBig,
      shrSH: shrSH2,
      shrSL: shrSL2,
      rotrSH: rotrSH2,
      rotrSL: rotrSL2,
      rotrBH: rotrBH2,
      rotrBL: rotrBL2,
      rotr32H,
      rotr32L,
      rotlSH: rotlSH2,
      rotlSL: rotlSL2,
      rotlBH: rotlBH2,
      rotlBL: rotlBL2,
      add: add2,
      add3L: add3L2,
      add3H: add3H2,
      add4L: add4L2,
      add4H: add4H2,
      add5H: add5H2,
      add5L: add5L2
    };
    exports.default = u64;
  }
});

// node_modules/bs58check/node_modules/@noble/hashes/sha2.js
var require_sha23 = __commonJS({
  "node_modules/bs58check/node_modules/@noble/hashes/sha2.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.sha512_224 = exports.sha512_256 = exports.sha384 = exports.sha512 = exports.sha224 = exports.sha256 = exports.SHA512_256 = exports.SHA512_224 = exports.SHA384 = exports.SHA512 = exports.SHA224 = exports.SHA256 = void 0;
    var _md_ts_1 = require_md3();
    var u64 = require_u643();
    var utils_ts_1 = require_utils3();
    var SHA256_K2 = /* @__PURE__ */ Uint32Array.from([
      1116352408,
      1899447441,
      3049323471,
      3921009573,
      961987163,
      1508970993,
      2453635748,
      2870763221,
      3624381080,
      310598401,
      607225278,
      1426881987,
      1925078388,
      2162078206,
      2614888103,
      3248222580,
      3835390401,
      4022224774,
      264347078,
      604807628,
      770255983,
      1249150122,
      1555081692,
      1996064986,
      2554220882,
      2821834349,
      2952996808,
      3210313671,
      3336571891,
      3584528711,
      113926993,
      338241895,
      666307205,
      773529912,
      1294757372,
      1396182291,
      1695183700,
      1986661051,
      2177026350,
      2456956037,
      2730485921,
      2820302411,
      3259730800,
      3345764771,
      3516065817,
      3600352804,
      4094571909,
      275423344,
      430227734,
      506948616,
      659060556,
      883997877,
      958139571,
      1322822218,
      1537002063,
      1747873779,
      1955562222,
      2024104815,
      2227730452,
      2361852424,
      2428436474,
      2756734187,
      3204031479,
      3329325298
    ]);
    var SHA256_W2 = /* @__PURE__ */ new Uint32Array(64);
    var SHA256 = class extends _md_ts_1.HashMD {
      constructor(outputLen = 32) {
        super(64, outputLen, 8, false);
        this.A = _md_ts_1.SHA256_IV[0] | 0;
        this.B = _md_ts_1.SHA256_IV[1] | 0;
        this.C = _md_ts_1.SHA256_IV[2] | 0;
        this.D = _md_ts_1.SHA256_IV[3] | 0;
        this.E = _md_ts_1.SHA256_IV[4] | 0;
        this.F = _md_ts_1.SHA256_IV[5] | 0;
        this.G = _md_ts_1.SHA256_IV[6] | 0;
        this.H = _md_ts_1.SHA256_IV[7] | 0;
      }
      get() {
        const { A, B, C: C2, D, E, F, G: G2, H } = this;
        return [A, B, C2, D, E, F, G2, H];
      }
      // prettier-ignore
      set(A, B, C2, D, E, F, G2, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C2 | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G2 | 0;
        this.H = H | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
          SHA256_W2[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
          const W15 = SHA256_W2[i - 15];
          const W2 = SHA256_W2[i - 2];
          const s0 = (0, utils_ts_1.rotr)(W15, 7) ^ (0, utils_ts_1.rotr)(W15, 18) ^ W15 >>> 3;
          const s1 = (0, utils_ts_1.rotr)(W2, 17) ^ (0, utils_ts_1.rotr)(W2, 19) ^ W2 >>> 10;
          SHA256_W2[i] = s1 + SHA256_W2[i - 7] + s0 + SHA256_W2[i - 16] | 0;
        }
        let { A, B, C: C2, D, E, F, G: G2, H } = this;
        for (let i = 0; i < 64; i++) {
          const sigma1 = (0, utils_ts_1.rotr)(E, 6) ^ (0, utils_ts_1.rotr)(E, 11) ^ (0, utils_ts_1.rotr)(E, 25);
          const T1 = H + sigma1 + (0, _md_ts_1.Chi)(E, F, G2) + SHA256_K2[i] + SHA256_W2[i] | 0;
          const sigma0 = (0, utils_ts_1.rotr)(A, 2) ^ (0, utils_ts_1.rotr)(A, 13) ^ (0, utils_ts_1.rotr)(A, 22);
          const T2 = sigma0 + (0, _md_ts_1.Maj)(A, B, C2) | 0;
          H = G2;
          G2 = F;
          F = E;
          E = D + T1 | 0;
          D = C2;
          C2 = B;
          B = A;
          A = T1 + T2 | 0;
        }
        A = A + this.A | 0;
        B = B + this.B | 0;
        C2 = C2 + this.C | 0;
        D = D + this.D | 0;
        E = E + this.E | 0;
        F = F + this.F | 0;
        G2 = G2 + this.G | 0;
        H = H + this.H | 0;
        this.set(A, B, C2, D, E, F, G2, H);
      }
      roundClean() {
        (0, utils_ts_1.clean)(SHA256_W2);
      }
      destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        (0, utils_ts_1.clean)(this.buffer);
      }
    };
    exports.SHA256 = SHA256;
    var SHA224 = class extends SHA256 {
      constructor() {
        super(28);
        this.A = _md_ts_1.SHA224_IV[0] | 0;
        this.B = _md_ts_1.SHA224_IV[1] | 0;
        this.C = _md_ts_1.SHA224_IV[2] | 0;
        this.D = _md_ts_1.SHA224_IV[3] | 0;
        this.E = _md_ts_1.SHA224_IV[4] | 0;
        this.F = _md_ts_1.SHA224_IV[5] | 0;
        this.G = _md_ts_1.SHA224_IV[6] | 0;
        this.H = _md_ts_1.SHA224_IV[7] | 0;
      }
    };
    exports.SHA224 = SHA224;
    var K5122 = /* @__PURE__ */ (() => u64.split([
      "0x428a2f98d728ae22",
      "0x7137449123ef65cd",
      "0xb5c0fbcfec4d3b2f",
      "0xe9b5dba58189dbbc",
      "0x3956c25bf348b538",
      "0x59f111f1b605d019",
      "0x923f82a4af194f9b",
      "0xab1c5ed5da6d8118",
      "0xd807aa98a3030242",
      "0x12835b0145706fbe",
      "0x243185be4ee4b28c",
      "0x550c7dc3d5ffb4e2",
      "0x72be5d74f27b896f",
      "0x80deb1fe3b1696b1",
      "0x9bdc06a725c71235",
      "0xc19bf174cf692694",
      "0xe49b69c19ef14ad2",
      "0xefbe4786384f25e3",
      "0x0fc19dc68b8cd5b5",
      "0x240ca1cc77ac9c65",
      "0x2de92c6f592b0275",
      "0x4a7484aa6ea6e483",
      "0x5cb0a9dcbd41fbd4",
      "0x76f988da831153b5",
      "0x983e5152ee66dfab",
      "0xa831c66d2db43210",
      "0xb00327c898fb213f",
      "0xbf597fc7beef0ee4",
      "0xc6e00bf33da88fc2",
      "0xd5a79147930aa725",
      "0x06ca6351e003826f",
      "0x142929670a0e6e70",
      "0x27b70a8546d22ffc",
      "0x2e1b21385c26c926",
      "0x4d2c6dfc5ac42aed",
      "0x53380d139d95b3df",
      "0x650a73548baf63de",
      "0x766a0abb3c77b2a8",
      "0x81c2c92e47edaee6",
      "0x92722c851482353b",
      "0xa2bfe8a14cf10364",
      "0xa81a664bbc423001",
      "0xc24b8b70d0f89791",
      "0xc76c51a30654be30",
      "0xd192e819d6ef5218",
      "0xd69906245565a910",
      "0xf40e35855771202a",
      "0x106aa07032bbd1b8",
      "0x19a4c116b8d2d0c8",
      "0x1e376c085141ab53",
      "0x2748774cdf8eeb99",
      "0x34b0bcb5e19b48a8",
      "0x391c0cb3c5c95a63",
      "0x4ed8aa4ae3418acb",
      "0x5b9cca4f7763e373",
      "0x682e6ff3d6b2b8a3",
      "0x748f82ee5defb2fc",
      "0x78a5636f43172f60",
      "0x84c87814a1f0ab72",
      "0x8cc702081a6439ec",
      "0x90befffa23631e28",
      "0xa4506cebde82bde9",
      "0xbef9a3f7b2c67915",
      "0xc67178f2e372532b",
      "0xca273eceea26619c",
      "0xd186b8c721c0c207",
      "0xeada7dd6cde0eb1e",
      "0xf57d4f7fee6ed178",
      "0x06f067aa72176fba",
      "0x0a637dc5a2c898a6",
      "0x113f9804bef90dae",
      "0x1b710b35131c471b",
      "0x28db77f523047d84",
      "0x32caab7b40c72493",
      "0x3c9ebe0a15c9bebc",
      "0x431d67c49c100d4c",
      "0x4cc5d4becb3e42b6",
      "0x597f299cfc657e2a",
      "0x5fcb6fab3ad6faec",
      "0x6c44198c4a475817"
    ].map((n) => BigInt(n))))();
    var SHA512_Kh2 = /* @__PURE__ */ (() => K5122[0])();
    var SHA512_Kl2 = /* @__PURE__ */ (() => K5122[1])();
    var SHA512_W_H2 = /* @__PURE__ */ new Uint32Array(80);
    var SHA512_W_L2 = /* @__PURE__ */ new Uint32Array(80);
    var SHA512 = class extends _md_ts_1.HashMD {
      constructor(outputLen = 64) {
        super(128, outputLen, 16, false);
        this.Ah = _md_ts_1.SHA512_IV[0] | 0;
        this.Al = _md_ts_1.SHA512_IV[1] | 0;
        this.Bh = _md_ts_1.SHA512_IV[2] | 0;
        this.Bl = _md_ts_1.SHA512_IV[3] | 0;
        this.Ch = _md_ts_1.SHA512_IV[4] | 0;
        this.Cl = _md_ts_1.SHA512_IV[5] | 0;
        this.Dh = _md_ts_1.SHA512_IV[6] | 0;
        this.Dl = _md_ts_1.SHA512_IV[7] | 0;
        this.Eh = _md_ts_1.SHA512_IV[8] | 0;
        this.El = _md_ts_1.SHA512_IV[9] | 0;
        this.Fh = _md_ts_1.SHA512_IV[10] | 0;
        this.Fl = _md_ts_1.SHA512_IV[11] | 0;
        this.Gh = _md_ts_1.SHA512_IV[12] | 0;
        this.Gl = _md_ts_1.SHA512_IV[13] | 0;
        this.Hh = _md_ts_1.SHA512_IV[14] | 0;
        this.Hl = _md_ts_1.SHA512_IV[15] | 0;
      }
      // prettier-ignore
      get() {
        const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
      }
      // prettier-ignore
      set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
        this.Ah = Ah | 0;
        this.Al = Al | 0;
        this.Bh = Bh | 0;
        this.Bl = Bl | 0;
        this.Ch = Ch | 0;
        this.Cl = Cl | 0;
        this.Dh = Dh | 0;
        this.Dl = Dl | 0;
        this.Eh = Eh | 0;
        this.El = El | 0;
        this.Fh = Fh | 0;
        this.Fl = Fl | 0;
        this.Gh = Gh | 0;
        this.Gl = Gl | 0;
        this.Hh = Hh | 0;
        this.Hl = Hl | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4) {
          SHA512_W_H2[i] = view.getUint32(offset);
          SHA512_W_L2[i] = view.getUint32(offset += 4);
        }
        for (let i = 16; i < 80; i++) {
          const W15h = SHA512_W_H2[i - 15] | 0;
          const W15l = SHA512_W_L2[i - 15] | 0;
          const s0h = u64.rotrSH(W15h, W15l, 1) ^ u64.rotrSH(W15h, W15l, 8) ^ u64.shrSH(W15h, W15l, 7);
          const s0l = u64.rotrSL(W15h, W15l, 1) ^ u64.rotrSL(W15h, W15l, 8) ^ u64.shrSL(W15h, W15l, 7);
          const W2h = SHA512_W_H2[i - 2] | 0;
          const W2l = SHA512_W_L2[i - 2] | 0;
          const s1h = u64.rotrSH(W2h, W2l, 19) ^ u64.rotrBH(W2h, W2l, 61) ^ u64.shrSH(W2h, W2l, 6);
          const s1l = u64.rotrSL(W2h, W2l, 19) ^ u64.rotrBL(W2h, W2l, 61) ^ u64.shrSL(W2h, W2l, 6);
          const SUMl = u64.add4L(s0l, s1l, SHA512_W_L2[i - 7], SHA512_W_L2[i - 16]);
          const SUMh = u64.add4H(SUMl, s0h, s1h, SHA512_W_H2[i - 7], SHA512_W_H2[i - 16]);
          SHA512_W_H2[i] = SUMh | 0;
          SHA512_W_L2[i] = SUMl | 0;
        }
        let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        for (let i = 0; i < 80; i++) {
          const sigma1h = u64.rotrSH(Eh, El, 14) ^ u64.rotrSH(Eh, El, 18) ^ u64.rotrBH(Eh, El, 41);
          const sigma1l = u64.rotrSL(Eh, El, 14) ^ u64.rotrSL(Eh, El, 18) ^ u64.rotrBL(Eh, El, 41);
          const CHIh = Eh & Fh ^ ~Eh & Gh;
          const CHIl = El & Fl ^ ~El & Gl;
          const T1ll = u64.add5L(Hl, sigma1l, CHIl, SHA512_Kl2[i], SHA512_W_L2[i]);
          const T1h = u64.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh2[i], SHA512_W_H2[i]);
          const T1l = T1ll | 0;
          const sigma0h = u64.rotrSH(Ah, Al, 28) ^ u64.rotrBH(Ah, Al, 34) ^ u64.rotrBH(Ah, Al, 39);
          const sigma0l = u64.rotrSL(Ah, Al, 28) ^ u64.rotrBL(Ah, Al, 34) ^ u64.rotrBL(Ah, Al, 39);
          const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
          const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
          Hh = Gh | 0;
          Hl = Gl | 0;
          Gh = Fh | 0;
          Gl = Fl | 0;
          Fh = Eh | 0;
          Fl = El | 0;
          ({ h: Eh, l: El } = u64.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
          Dh = Ch | 0;
          Dl = Cl | 0;
          Ch = Bh | 0;
          Cl = Bl | 0;
          Bh = Ah | 0;
          Bl = Al | 0;
          const All = u64.add3L(T1l, sigma0l, MAJl);
          Ah = u64.add3H(All, T1h, sigma0h, MAJh);
          Al = All | 0;
        }
        ({ h: Ah, l: Al } = u64.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
        ({ h: Bh, l: Bl } = u64.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
        ({ h: Ch, l: Cl } = u64.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
        ({ h: Dh, l: Dl } = u64.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
        ({ h: Eh, l: El } = u64.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
        ({ h: Fh, l: Fl } = u64.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
        ({ h: Gh, l: Gl } = u64.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
        ({ h: Hh, l: Hl } = u64.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
        this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
      }
      roundClean() {
        (0, utils_ts_1.clean)(SHA512_W_H2, SHA512_W_L2);
      }
      destroy() {
        (0, utils_ts_1.clean)(this.buffer);
        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      }
    };
    exports.SHA512 = SHA512;
    var SHA384 = class extends SHA512 {
      constructor() {
        super(48);
        this.Ah = _md_ts_1.SHA384_IV[0] | 0;
        this.Al = _md_ts_1.SHA384_IV[1] | 0;
        this.Bh = _md_ts_1.SHA384_IV[2] | 0;
        this.Bl = _md_ts_1.SHA384_IV[3] | 0;
        this.Ch = _md_ts_1.SHA384_IV[4] | 0;
        this.Cl = _md_ts_1.SHA384_IV[5] | 0;
        this.Dh = _md_ts_1.SHA384_IV[6] | 0;
        this.Dl = _md_ts_1.SHA384_IV[7] | 0;
        this.Eh = _md_ts_1.SHA384_IV[8] | 0;
        this.El = _md_ts_1.SHA384_IV[9] | 0;
        this.Fh = _md_ts_1.SHA384_IV[10] | 0;
        this.Fl = _md_ts_1.SHA384_IV[11] | 0;
        this.Gh = _md_ts_1.SHA384_IV[12] | 0;
        this.Gl = _md_ts_1.SHA384_IV[13] | 0;
        this.Hh = _md_ts_1.SHA384_IV[14] | 0;
        this.Hl = _md_ts_1.SHA384_IV[15] | 0;
      }
    };
    exports.SHA384 = SHA384;
    var T224_IV2 = /* @__PURE__ */ Uint32Array.from([
      2352822216,
      424955298,
      1944164710,
      2312950998,
      502970286,
      855612546,
      1738396948,
      1479516111,
      258812777,
      2077511080,
      2011393907,
      79989058,
      1067287976,
      1780299464,
      286451373,
      2446758561
    ]);
    var T256_IV2 = /* @__PURE__ */ Uint32Array.from([
      573645204,
      4230739756,
      2673172387,
      3360449730,
      596883563,
      1867755857,
      2520282905,
      1497426621,
      2519219938,
      2827943907,
      3193839141,
      1401305490,
      721525244,
      746961066,
      246885852,
      2177182882
    ]);
    var SHA512_224 = class extends SHA512 {
      constructor() {
        super(28);
        this.Ah = T224_IV2[0] | 0;
        this.Al = T224_IV2[1] | 0;
        this.Bh = T224_IV2[2] | 0;
        this.Bl = T224_IV2[3] | 0;
        this.Ch = T224_IV2[4] | 0;
        this.Cl = T224_IV2[5] | 0;
        this.Dh = T224_IV2[6] | 0;
        this.Dl = T224_IV2[7] | 0;
        this.Eh = T224_IV2[8] | 0;
        this.El = T224_IV2[9] | 0;
        this.Fh = T224_IV2[10] | 0;
        this.Fl = T224_IV2[11] | 0;
        this.Gh = T224_IV2[12] | 0;
        this.Gl = T224_IV2[13] | 0;
        this.Hh = T224_IV2[14] | 0;
        this.Hl = T224_IV2[15] | 0;
      }
    };
    exports.SHA512_224 = SHA512_224;
    var SHA512_256 = class extends SHA512 {
      constructor() {
        super(32);
        this.Ah = T256_IV2[0] | 0;
        this.Al = T256_IV2[1] | 0;
        this.Bh = T256_IV2[2] | 0;
        this.Bl = T256_IV2[3] | 0;
        this.Ch = T256_IV2[4] | 0;
        this.Cl = T256_IV2[5] | 0;
        this.Dh = T256_IV2[6] | 0;
        this.Dl = T256_IV2[7] | 0;
        this.Eh = T256_IV2[8] | 0;
        this.El = T256_IV2[9] | 0;
        this.Fh = T256_IV2[10] | 0;
        this.Fl = T256_IV2[11] | 0;
        this.Gh = T256_IV2[12] | 0;
        this.Gl = T256_IV2[13] | 0;
        this.Hh = T256_IV2[14] | 0;
        this.Hl = T256_IV2[15] | 0;
      }
    };
    exports.SHA512_256 = SHA512_256;
    exports.sha256 = (0, utils_ts_1.createHasher)(() => new SHA256());
    exports.sha224 = (0, utils_ts_1.createHasher)(() => new SHA224());
    exports.sha512 = (0, utils_ts_1.createHasher)(() => new SHA512());
    exports.sha384 = (0, utils_ts_1.createHasher)(() => new SHA384());
    exports.sha512_256 = (0, utils_ts_1.createHasher)(() => new SHA512_256());
    exports.sha512_224 = (0, utils_ts_1.createHasher)(() => new SHA512_224());
  }
});

// node_modules/bs58check/node_modules/@noble/hashes/sha256.js
var require_sha2563 = __commonJS({
  "node_modules/bs58check/node_modules/@noble/hashes/sha256.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.sha224 = exports.SHA224 = exports.sha256 = exports.SHA256 = void 0;
    var sha2_ts_1 = require_sha23();
    exports.SHA256 = sha2_ts_1.SHA256;
    exports.sha256 = sha2_ts_1.sha256;
    exports.SHA224 = sha2_ts_1.SHA224;
    exports.sha224 = sha2_ts_1.sha224;
  }
});

// node_modules/base-x/src/cjs/index.cjs
var require_cjs = __commonJS({
  "node_modules/base-x/src/cjs/index.cjs"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    function base(ALPHABET) {
      if (ALPHABET.length >= 255) {
        throw new TypeError("Alphabet too long");
      }
      const BASE_MAP = new Uint8Array(256);
      for (let j = 0; j < BASE_MAP.length; j++) {
        BASE_MAP[j] = 255;
      }
      for (let i = 0; i < ALPHABET.length; i++) {
        const x = ALPHABET.charAt(i);
        const xc = x.charCodeAt(0);
        if (BASE_MAP[xc] !== 255) {
          throw new TypeError(x + " is ambiguous");
        }
        BASE_MAP[xc] = i;
      }
      const BASE = ALPHABET.length;
      const LEADER = ALPHABET.charAt(0);
      const FACTOR = Math.log(BASE) / Math.log(256);
      const iFACTOR = Math.log(256) / Math.log(BASE);
      function encode(source) {
        if (source instanceof Uint8Array) {
        } else if (ArrayBuffer.isView(source)) {
          source = new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
        } else if (Array.isArray(source)) {
          source = Uint8Array.from(source);
        }
        if (!(source instanceof Uint8Array)) {
          throw new TypeError("Expected Uint8Array");
        }
        if (source.length === 0) {
          return "";
        }
        let zeroes = 0;
        let length = 0;
        let pbegin = 0;
        const pend = source.length;
        while (pbegin !== pend && source[pbegin] === 0) {
          pbegin++;
          zeroes++;
        }
        const size = (pend - pbegin) * iFACTOR + 1 >>> 0;
        const b58 = new Uint8Array(size);
        while (pbegin !== pend) {
          let carry = source[pbegin];
          let i = 0;
          for (let it1 = size - 1; (carry !== 0 || i < length) && it1 !== -1; it1--, i++) {
            carry += 256 * b58[it1] >>> 0;
            b58[it1] = carry % BASE >>> 0;
            carry = carry / BASE >>> 0;
          }
          if (carry !== 0) {
            throw new Error("Non-zero carry");
          }
          length = i;
          pbegin++;
        }
        let it2 = size - length;
        while (it2 !== size && b58[it2] === 0) {
          it2++;
        }
        let str2 = LEADER.repeat(zeroes);
        for (; it2 < size; ++it2) {
          str2 += ALPHABET.charAt(b58[it2]);
        }
        return str2;
      }
      function decodeUnsafe(source) {
        if (typeof source !== "string") {
          throw new TypeError("Expected String");
        }
        if (source.length === 0) {
          return new Uint8Array();
        }
        let psz = 0;
        let zeroes = 0;
        let length = 0;
        while (source[psz] === LEADER) {
          zeroes++;
          psz++;
        }
        const size = (source.length - psz) * FACTOR + 1 >>> 0;
        const b256 = new Uint8Array(size);
        while (psz < source.length) {
          const charCode = source.charCodeAt(psz);
          if (charCode > 255) {
            return;
          }
          let carry = BASE_MAP[charCode];
          if (carry === 255) {
            return;
          }
          let i = 0;
          for (let it3 = size - 1; (carry !== 0 || i < length) && it3 !== -1; it3--, i++) {
            carry += BASE * b256[it3] >>> 0;
            b256[it3] = carry % 256 >>> 0;
            carry = carry / 256 >>> 0;
          }
          if (carry !== 0) {
            throw new Error("Non-zero carry");
          }
          length = i;
          psz++;
        }
        let it4 = size - length;
        while (it4 !== size && b256[it4] === 0) {
          it4++;
        }
        const vch = new Uint8Array(zeroes + (size - it4));
        let j = zeroes;
        while (it4 !== size) {
          vch[j++] = b256[it4++];
        }
        return vch;
      }
      function decode(string) {
        const buffer = decodeUnsafe(string);
        if (buffer) {
          return buffer;
        }
        throw new Error("Non-base" + BASE + " character");
      }
      return {
        encode,
        decodeUnsafe,
        decode
      };
    }
    exports.default = base;
  }
});

// node_modules/bs58/src/cjs/index.cjs
var require_cjs2 = __commonJS({
  "node_modules/bs58/src/cjs/index.cjs"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    var base_x_1 = __importDefault(require_cjs());
    var ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    exports.default = (0, base_x_1.default)(ALPHABET);
  }
});

// node_modules/bs58check/src/cjs/base.cjs
var require_base = __commonJS({
  "node_modules/bs58check/src/cjs/base.cjs"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.default = default_1;
    var bs58_1 = __importDefault(require_cjs2());
    function default_1(checksumFn) {
      function encode(payload) {
        var payloadU8 = Uint8Array.from(payload);
        var checksum2 = checksumFn(payloadU8);
        var length = payloadU8.length + 4;
        var both = new Uint8Array(length);
        both.set(payloadU8, 0);
        both.set(checksum2.subarray(0, 4), payloadU8.length);
        return bs58_1.default.encode(both);
      }
      function decodeRaw(buffer) {
        var payload = buffer.slice(0, -4);
        var checksum2 = buffer.slice(-4);
        var newChecksum = checksumFn(payload);
        if (checksum2[0] ^ newChecksum[0] | checksum2[1] ^ newChecksum[1] | checksum2[2] ^ newChecksum[2] | checksum2[3] ^ newChecksum[3])
          return;
        return payload;
      }
      function decodeUnsafe(str2) {
        var buffer = bs58_1.default.decodeUnsafe(str2);
        if (buffer == null)
          return;
        return decodeRaw(buffer);
      }
      function decode(str2) {
        var buffer = bs58_1.default.decode(str2);
        var payload = decodeRaw(buffer);
        if (payload == null)
          throw new Error("Invalid checksum");
        return payload;
      }
      return {
        encode,
        decode,
        decodeUnsafe
      };
    }
  }
});

// node_modules/bs58check/src/cjs/index.cjs
var require_cjs3 = __commonJS({
  "node_modules/bs58check/src/cjs/index.cjs"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    var sha256_1 = require_sha2563();
    var base_js_1 = __importDefault(require_base());
    function sha256x2(buffer) {
      return (0, sha256_1.sha256)((0, sha256_1.sha256)(buffer));
    }
    exports.default = (0, base_js_1.default)(sha256x2);
  }
});

// node_modules/wif/src/cjs/index.cjs
var require_cjs4 = __commonJS({
  "node_modules/wif/src/cjs/index.cjs"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.encode = exports.decode = exports.encodeRaw = exports.decodeRaw = void 0;
    var bs58check_1 = __importDefault(require_cjs3());
    function decodeRaw(buffer, version) {
      if (version !== void 0 && buffer[0] !== version)
        throw new Error("Invalid network version");
      if (buffer.length === 33) {
        return {
          version: buffer[0],
          privateKey: buffer.slice(1, 33),
          compressed: false
        };
      }
      if (buffer.length !== 34)
        throw new Error("Invalid WIF length");
      if (buffer[33] !== 1)
        throw new Error("Invalid compression flag");
      return {
        version: buffer[0],
        privateKey: buffer.slice(1, 33),
        compressed: true
      };
    }
    exports.decodeRaw = decodeRaw;
    function encodeRaw(version, privateKey, compressed) {
      if (privateKey.length !== 32)
        throw new TypeError("Invalid privateKey length");
      var result = new Uint8Array(compressed ? 34 : 33);
      var view = new DataView(result.buffer);
      view.setUint8(0, version);
      result.set(privateKey, 1);
      if (compressed) {
        result[33] = 1;
      }
      return result;
    }
    exports.encodeRaw = encodeRaw;
    function decode(str2, version) {
      return decodeRaw(bs58check_1.default.decode(str2), version);
    }
    exports.decode = decode;
    function encode(wif) {
      return bs58check_1.default.encode(encodeRaw(wif.version, wif.privateKey, wif.compressed));
    }
    exports.encode = encode;
  }
});

// node_modules/bip32/src/cjs/bip32.cjs
var require_bip32 = __commonJS({
  "node_modules/bip32/src/cjs/bip32.cjs"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      var desc = Object.getOwnPropertyDescriptor(m, k);
      if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m[k];
        } };
      }
      Object.defineProperty(o, k2, desc);
    }) : (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    }));
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? (function(o, v2) {
      Object.defineProperty(o, "default", { enumerable: true, value: v2 });
    }) : function(o, v2) {
      o["default"] = v2;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule) return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.BIP32Factory = BIP32Factory;
    var crypto = __importStar(require_crypto3());
    var testecc_js_1 = require_testecc();
    var base_1 = require_lib();
    var sha256_1 = require_sha2562();
    var v = __importStar(require_dist());
    var types_js_1 = require_types();
    var wif = __importStar(require_cjs4());
    var tools = __importStar((init_browser(), __toCommonJS(browser_exports)));
    var _bs58check = (0, base_1.base58check)(sha256_1.sha256);
    var bs58check = {
      encode: (data) => _bs58check.encode(data),
      decode: (str2) => _bs58check.decode(str2)
    };
    function BIP32Factory(ecc) {
      (0, testecc_js_1.testEcc)(ecc);
      const BITCOIN = {
        messagePrefix: "Bitcoin Signed Message:\n",
        bech32: "bc",
        bip32: {
          public: 76067358,
          private: 76066276
        },
        pubKeyHash: 0,
        scriptHash: 5,
        wif: 128
      };
      const HIGHEST_BIT = 2147483648;
      function toXOnly(pubKey) {
        return pubKey.length === 32 ? pubKey : pubKey.slice(1, 33);
      }
      class Bip32Signer {
        __D;
        __Q;
        lowR = false;
        constructor(__D, __Q) {
          this.__D = __D;
          this.__Q = __Q;
        }
        get publicKey() {
          if (this.__Q === void 0)
            this.__Q = ecc.pointFromScalar(this.__D, true);
          return this.__Q;
        }
        get privateKey() {
          return this.__D;
        }
        sign(hash2, lowR) {
          if (!this.privateKey)
            throw new Error("Missing private key");
          if (lowR === void 0)
            lowR = this.lowR;
          if (lowR === false) {
            return ecc.sign(hash2, this.privateKey);
          } else {
            let sig = ecc.sign(hash2, this.privateKey);
            const extraData = new Uint8Array(32);
            let counter = 0;
            while (sig[0] > 127) {
              counter++;
              tools.writeUInt32(extraData, 0, counter, "LE");
              sig = ecc.sign(hash2, this.privateKey, extraData);
            }
            return sig;
          }
        }
        signSchnorr(hash2) {
          if (!this.privateKey)
            throw new Error("Missing private key");
          if (!ecc.signSchnorr)
            throw new Error("signSchnorr not supported by ecc library");
          return ecc.signSchnorr(hash2, this.privateKey);
        }
        verify(hash2, signature) {
          return ecc.verify(hash2, this.publicKey, signature);
        }
        verifySchnorr(hash2, signature) {
          if (!ecc.verifySchnorr)
            throw new Error("verifySchnorr not supported by ecc library");
          return ecc.verifySchnorr(hash2, this.publicKey.subarray(1, 33), signature);
        }
      }
      class BIP32 extends Bip32Signer {
        chainCode;
        network;
        __DEPTH;
        __INDEX;
        __PARENT_FINGERPRINT;
        constructor(__D, __Q, chainCode, network, __DEPTH = 0, __INDEX = 0, __PARENT_FINGERPRINT = 0) {
          super(__D, __Q);
          this.chainCode = chainCode;
          this.network = network;
          this.__DEPTH = __DEPTH;
          this.__INDEX = __INDEX;
          this.__PARENT_FINGERPRINT = __PARENT_FINGERPRINT;
          v.parse(types_js_1.NetworkSchema, network);
        }
        get depth() {
          return this.__DEPTH;
        }
        get index() {
          return this.__INDEX;
        }
        get parentFingerprint() {
          return this.__PARENT_FINGERPRINT;
        }
        get identifier() {
          return crypto.hash160(this.publicKey);
        }
        get fingerprint() {
          return this.identifier.slice(0, 4);
        }
        get compressed() {
          return true;
        }
        // Private === not neutered
        // Public === neutered
        isNeutered() {
          return this.__D === void 0;
        }
        neutered() {
          return fromPublicKeyLocal(this.publicKey, this.chainCode, this.network, this.depth, this.index, this.parentFingerprint);
        }
        toBase58() {
          const network = this.network;
          const version = !this.isNeutered() ? network.bip32.private : network.bip32.public;
          const buffer = new Uint8Array(78);
          tools.writeUInt32(buffer, 0, version, "BE");
          tools.writeUInt8(buffer, 4, this.depth);
          tools.writeUInt32(buffer, 5, this.parentFingerprint, "BE");
          tools.writeUInt32(buffer, 9, this.index, "BE");
          buffer.set(this.chainCode, 13);
          if (!this.isNeutered()) {
            tools.writeUInt8(buffer, 45, 0);
            buffer.set(this.privateKey, 46);
          } else {
            buffer.set(this.publicKey, 45);
          }
          return bs58check.encode(buffer);
        }
        toWIF() {
          if (!this.privateKey)
            throw new TypeError("Missing private key");
          return wif.encode({
            version: this.network.wif,
            privateKey: this.privateKey,
            compressed: true
          });
        }
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
        derive(index) {
          v.parse(types_js_1.Uint32Schema, index);
          const isHardened = index >= HIGHEST_BIT;
          const data = new Uint8Array(37);
          if (isHardened) {
            if (this.isNeutered())
              throw new TypeError("Missing private key for hardened child key");
            data[0] = 0;
            data.set(this.privateKey, 1);
            tools.writeUInt32(data, 33, index, "BE");
          } else {
            data.set(this.publicKey, 0);
            tools.writeUInt32(data, 33, index, "BE");
          }
          const I2 = crypto.hmacSHA512(this.chainCode, data);
          const IL = I2.slice(0, 32);
          const IR = I2.slice(32);
          if (!ecc.isPrivate(IL))
            return this.derive(index + 1);
          let hd;
          if (!this.isNeutered()) {
            const ki = ecc.privateAdd(this.privateKey, IL);
            if (ki == null)
              return this.derive(index + 1);
            hd = fromPrivateKeyLocal(ki, IR, this.network, this.depth + 1, index, tools.readUInt32(this.fingerprint, 0, "BE"));
          } else {
            const Ki = ecc.pointAddScalar(this.publicKey, IL, true);
            if (Ki === null)
              return this.derive(index + 1);
            hd = fromPublicKeyLocal(Ki, IR, this.network, this.depth + 1, index, tools.readUInt32(this.fingerprint, 0, "BE"));
          }
          return hd;
        }
        deriveHardened(index) {
          if (typeof v.parse(types_js_1.Uint31Schema, index) === "number")
            return this.derive(index + HIGHEST_BIT);
          throw new TypeError("Expected UInt31, got " + index);
        }
        derivePath(path) {
          v.parse(types_js_1.Bip32PathSchema, path);
          let splitPath = path.split("/");
          if (splitPath[0] === "m") {
            if (this.parentFingerprint)
              throw new TypeError("Expected master, got child");
            splitPath = splitPath.slice(1);
          }
          return splitPath.reduce((prevHd, indexStr) => {
            let index;
            if (indexStr.slice(-1) === `'`) {
              index = parseInt(indexStr.slice(0, -1), 10);
              return prevHd.deriveHardened(index);
            } else {
              index = parseInt(indexStr, 10);
              return prevHd.derive(index);
            }
          }, this);
        }
        tweak(t) {
          if (this.privateKey)
            return this.tweakFromPrivateKey(t);
          return this.tweakFromPublicKey(t);
        }
        tweakFromPublicKey(t) {
          const xOnlyPubKey = toXOnly(this.publicKey);
          if (!ecc.xOnlyPointAddTweak)
            throw new Error("xOnlyPointAddTweak not supported by ecc library");
          const tweakedPublicKey = ecc.xOnlyPointAddTweak(xOnlyPubKey, t);
          if (!tweakedPublicKey || tweakedPublicKey.xOnlyPubkey === null)
            throw new Error("Cannot tweak public key!");
          const parityByte = Uint8Array.from([
            tweakedPublicKey.parity === 0 ? 2 : 3
          ]);
          const tweakedPublicKeyCompresed = tools.concat([
            parityByte,
            tweakedPublicKey.xOnlyPubkey
          ]);
          return new Bip32Signer(void 0, tweakedPublicKeyCompresed);
        }
        tweakFromPrivateKey(t) {
          const hasOddY = this.publicKey[0] === 3 || this.publicKey[0] === 4 && (this.publicKey[64] & 1) === 1;
          const privateKey = (() => {
            if (!hasOddY)
              return this.privateKey;
            else if (!ecc.privateNegate)
              throw new Error("privateNegate not supported by ecc library");
            else
              return ecc.privateNegate(this.privateKey);
          })();
          const tweakedPrivateKey = ecc.privateAdd(privateKey, t);
          if (!tweakedPrivateKey)
            throw new Error("Invalid tweaked private key!");
          return new Bip32Signer(tweakedPrivateKey, void 0);
        }
      }
      function fromBase58(inString, network) {
        const buffer = bs58check.decode(inString);
        if (buffer.length !== 78)
          throw new TypeError("Invalid buffer length");
        network = network || BITCOIN;
        const version = tools.readUInt32(buffer, 0, "BE");
        if (version !== network.bip32.private && version !== network.bip32.public)
          throw new TypeError("Invalid network version");
        const depth = buffer[4];
        const parentFingerprint = tools.readUInt32(buffer, 5, "BE");
        if (depth === 0) {
          if (parentFingerprint !== 0)
            throw new TypeError("Invalid parent fingerprint");
        }
        const index = tools.readUInt32(buffer, 9, "BE");
        if (depth === 0 && index !== 0)
          throw new TypeError("Invalid index");
        const chainCode = buffer.slice(13, 45);
        let hd;
        if (version === network.bip32.private) {
          if (buffer[45] !== 0)
            throw new TypeError("Invalid private key");
          const k = buffer.slice(46, 78);
          hd = fromPrivateKeyLocal(k, chainCode, network, depth, index, parentFingerprint);
        } else {
          const X = buffer.slice(45, 78);
          hd = fromPublicKeyLocal(X, chainCode, network, depth, index, parentFingerprint);
        }
        return hd;
      }
      function fromPrivateKey(privateKey, chainCode, network) {
        return fromPrivateKeyLocal(privateKey, chainCode, network);
      }
      function fromPrivateKeyLocal(privateKey, chainCode, network, depth, index, parentFingerprint) {
        v.parse(types_js_1.Buffer256Bit, privateKey);
        v.parse(types_js_1.Buffer256Bit, chainCode);
        network = network || BITCOIN;
        if (!ecc.isPrivate(privateKey))
          throw new TypeError("Private key not in range [1, n)");
        return new BIP32(privateKey, void 0, chainCode, network, depth, index, parentFingerprint);
      }
      function fromPublicKey(publicKey, chainCode, network) {
        return fromPublicKeyLocal(publicKey, chainCode, network);
      }
      function fromPublicKeyLocal(publicKey, chainCode, network, depth, index, parentFingerprint) {
        v.parse(types_js_1.Buffer33Bytes, publicKey);
        v.parse(types_js_1.Buffer256Bit, chainCode);
        network = network || BITCOIN;
        if (!ecc.isPoint(publicKey))
          throw new TypeError("Point is not on the curve");
        return new BIP32(void 0, publicKey, chainCode, network, depth, index, parentFingerprint);
      }
      function fromSeed(seed, network) {
        v.parse(v.instance(Uint8Array), seed);
        if (seed.length < 16)
          throw new TypeError("Seed should be at least 128 bits");
        if (seed.length > 64)
          throw new TypeError("Seed should be at most 512 bits");
        network = network || BITCOIN;
        const I2 = crypto.hmacSHA512(tools.fromUtf8("Bitcoin seed"), seed);
        const IL = I2.slice(0, 32);
        const IR = I2.slice(32);
        return fromPrivateKey(IL, IR, network);
      }
      return {
        fromSeed,
        fromBase58,
        fromPublicKey,
        fromPrivateKey
      };
    }
  }
});

// node_modules/bip32/src/cjs/index.cjs
var require_cjs5 = __commonJS({
  "node_modules/bip32/src/cjs/index.cjs"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.BIP32Factory = exports.default = void 0;
    var bip32_js_1 = require_bip32();
    Object.defineProperty(exports, "default", { enumerable: true, get: function() {
      return bip32_js_1.BIP32Factory;
    } });
    Object.defineProperty(exports, "BIP32Factory", { enumerable: true, get: function() {
      return bip32_js_1.BIP32Factory;
    } });
  }
});

// lib/wallet/derive.js
var require_derive = __commonJS({
  "lib/wallet/derive.js"(exports, module) {
    "use strict";
    var bip39 = require_src();
    var bip32 = require_cjs5();
    var ecc = require_ecc_noble();
    var {
      compressedPublicKeyToTronAddress,
      tronAddressBase58ToHex
    } = require_address();
    var {
      TRON_DERIVATION_PATH,
      TRON_PATH_RE,
      ALLOWED_ENTROPY_BITS
    } = require_constants();
    function zeroBuffer(buf) {
      if (buf && typeof buf.fill === "function") {
        buf.fill(0);
      }
    }
    function deriveWalletFromMnemonic(mnemonic, passphrase = "", derivationPath = TRON_DERIVATION_PATH) {
      const normalized = mnemonic.trim().replace(/\s+/g, " ");
      if (!bip39.validateMnemonic(normalized)) {
        throw new Error("Invalid BIP39 mnemonic");
      }
      if (typeof derivationPath !== "string" || !TRON_PATH_RE.test(derivationPath.trim())) {
        throw new Error(
          `Invalid derivation path (expected e.g. m/44'/195'/0'/0/0): ${derivationPath}`
        );
      }
      const pathUsed = derivationPath.trim();
      const seed = bip39.mnemonicToSeedSync(normalized, passphrase);
      try {
        const root = bip32.BIP32Factory(ecc).fromSeed(seed);
        const child = root.derivePath(pathUsed);
        const privateKey = child.privateKey;
        if (!privateKey || privateKey.every((b) => b === 0)) {
          throw new Error(
            "Derived node has no private key or zero key (unexpected for standard path)"
          );
        }
        const address = compressedPublicKeyToTronAddress(child.publicKey);
        const addressHex = tronAddressBase58ToHex(address);
        const privateKeyHex = Buffer.from(privateKey).toString("hex");
        return {
          mnemonic: normalized,
          derivationPath: pathUsed,
          privateKeyHex,
          address,
          addressHex
        };
      } finally {
        zeroBuffer(seed);
      }
    }
    function generateTronWallet(entropyBits, passphrase = "") {
      if (!ALLOWED_ENTROPY_BITS.has(entropyBits)) {
        throw new Error(
          `entropyBits must be one of: ${[...ALLOWED_ENTROPY_BITS].join(", ")}`
        );
      }
      const mnemonic = bip39.generateMnemonic(entropyBits);
      const a = deriveWalletFromMnemonic(mnemonic, passphrase);
      const b = deriveWalletFromMnemonic(mnemonic, passphrase);
      if (a.address !== b.address || a.privateKeyHex !== b.privateKeyHex) {
        throw new Error(
          "Determinism check failed: two derivation passes produced different results"
        );
      }
      return a;
    }
    module.exports = {
      deriveWalletFromMnemonic,
      generateTronWallet,
      zeroBuffer
    };
  }
});

// lib/tron/transaction/verify-tx-id.js
var require_verify_tx_id = __commonJS({
  "lib/tron/transaction/verify-tx-id.js"(exports, module) {
    "use strict";
    var { sha256: sha2562 } = (init_sha2(), __toCommonJS(sha2_exports));
    var MAX_RAW_DATA_HEX_LENGTH = 16 * 1024 * 1024;
    function parseStrictHex(label, hexWithOptional0x, exactByteLen) {
      if (typeof hexWithOptional0x !== "string") {
        throw new Error(`Transaction has no valid ${label}`);
      }
      const h = hexWithOptional0x.replace(/^0x/i, "");
      if (label === "raw_data_hex" && h.length > MAX_RAW_DATA_HEX_LENGTH) {
        throw new Error(
          `${label} is too long (max ${MAX_RAW_DATA_HEX_LENGTH} hex characters) \u2014 refusing to parse`
        );
      }
      if (h.length < 64) {
        throw new Error(`Transaction has no valid ${label}`);
      }
      if (h.length % 2 !== 0) {
        throw new Error(`${label} must be even-length hex`);
      }
      if (!/^[0-9a-fA-F]+$/.test(h)) {
        throw new Error(`${label} must contain only hexadecimal characters`);
      }
      const rawBytes = Buffer.from(h, "hex");
      if (rawBytes.length * 2 !== h.length) {
        throw new Error(`${label} hex decoding failed`);
      }
      if (exactByteLen !== void 0 && rawBytes.length !== exactByteLen) {
        throw new Error(`${label} must be ${exactByteLen} bytes (${exactByteLen * 2} hex chars)`);
      }
      return rawBytes;
    }
    function verifyTxIdBinding(tx) {
      const rawBytes = parseStrictHex("raw_data_hex", tx.raw_data_hex);
      const digest = Buffer.from(sha2562(rawBytes));
      const expected = parseStrictHex("txID", String(tx.txID || ""), 32);
      if (digest.length !== 32 || !digest.equals(expected)) {
        throw new Error(
          "txID does not match SHA256(raw_data_hex). Transaction may have been tampered with \u2014 signing refused."
        );
      }
    }
    module.exports = {
      verifyTxIdBinding,
      MAX_RAW_DATA_HEX_LENGTH,
      parseStrictHex
    };
  }
});

// lib/tron/transaction/sign-tron-tx-id.js
var require_sign_tron_tx_id = __commonJS({
  "lib/tron/transaction/sign-tron-tx-id.js"(exports, module) {
    "use strict";
    var secp = (init_secp256k1(), __toCommonJS(secp256k1_exports));
    var { hmac: hmac2 } = (init_hmac(), __toCommonJS(hmac_exports));
    var { sha256: sha2562 } = (init_sha2(), __toCommonJS(sha2_exports));
    var { parseStrictHex } = require_verify_tx_id();
    secp.hashes.hmacSha256 = (key, msg) => hmac2(sha2562, key, msg);
    secp.hashes.sha256 = sha2562;
    function signTronTxId(txIdHex, privateKey) {
      if (!Buffer.isBuffer(privateKey) || privateKey.length !== 32) {
        throw new Error("privateKey must be a 32-byte Buffer");
      }
      const msgHash = parseStrictHex("txID", String(txIdHex), 32);
      const sig65 = secp.sign(new Uint8Array(msgHash), new Uint8Array(privateKey), {
        prehash: false,
        format: "recovered"
      });
      const r = Buffer.from(sig65.subarray(1, 33)).toString("hex");
      const s = Buffer.from(sig65.subarray(33, 65)).toString("hex");
      const v = sig65[0] + 27;
      const vHex = v.toString(16).padStart(2, "0").toUpperCase();
      return r + s + vHex;
    }
    module.exports = { signTronTxId };
  }
});

// lib/tron/transaction/constants.js
var require_constants2 = __commonJS({
  "lib/tron/transaction/constants.js"(exports, module) {
    "use strict";
    var SUN = 1e6;
    var SEL_TRANSFER = "a9059cbb";
    var SEL_TRANSFER_FROM = "23b872dd";
    module.exports = {
      SUN,
      SEL_TRANSFER,
      SEL_TRANSFER_FROM
    };
  }
});

// lib/tron/transaction/normalize-address.js
var require_normalize_address = __commonJS({
  "lib/tron/transaction/normalize-address.js"(exports, module) {
    "use strict";
    var { createBase58check: createBase58check2 } = (init_base(), __toCommonJS(base_exports));
    var { sha256: sha2562 } = (init_sha2(), __toCommonJS(sha2_exports));
    var {
      decodeTronAddressBase58Checked,
      encodeTronBase58CheckPayload
    } = require_address();
    var { TRON_ADDRESS_VERSION_BYTE } = require_constants();
    var tronBase58Check = createBase58check2((data) => sha2562(data));
    function normalizeTronAddress(value, label) {
      if (value === void 0 || value === null) {
        throw new Error(`Contract field missing: ${label}`);
      }
      const s = String(value).trim();
      if (s.startsWith("T")) {
        const raw = decodeTronAddressBase58Checked(s);
        return encodeTronBase58CheckPayload(raw);
      }
      let h = s.replace(/^0x/i, "");
      if (h.length === 40) {
        h = "41" + h;
      }
      const buf = Buffer.from(h, "hex");
      if (buf.length !== 21 || buf[0] !== TRON_ADDRESS_VERSION_BYTE) {
        throw new Error(
          `${label}: invalid TRON hex address (expected 21 bytes starting with 0x41)`
        );
      }
      return tronBase58Check.encode(buf);
    }
    module.exports = { normalizeTronAddress };
  }
});

// lib/tron/transaction/parse-trc20.js
var require_parse_trc20 = __commonJS({
  "lib/tron/transaction/parse-trc20.js"(exports, module) {
    "use strict";
    var { normalizeTronAddress } = require_normalize_address();
    var { SEL_TRANSFER, SEL_TRANSFER_FROM } = require_constants2();
    function parseTrc20CallData(dataHex) {
      const h = String(dataHex).replace(/^0x/i, "").toLowerCase();
      if (h.length < 8) {
        return { kind: "unknown", selector: h || "(empty)" };
      }
      const sel = h.slice(0, 8);
      if (sel === SEL_TRANSFER && h.length >= 8 + 128) {
        const addrPadded = h.slice(8, 8 + 64);
        const to20 = addrPadded.slice(24);
        if (!/^[0-9a-f]{40}$/.test(to20)) {
          return { kind: "unknown", selector: sel };
        }
        let to;
        try {
          to = normalizeTronAddress("41" + to20, "to");
        } catch {
          return { kind: "unknown", selector: sel };
        }
        const amount = BigInt("0x" + h.slice(8 + 64, 8 + 128));
        return { kind: "transfer", to, amount };
      }
      if (sel === SEL_TRANSFER_FROM && h.length >= 8 + 192) {
        const from20 = h.slice(8 + 24, 8 + 64);
        const to20 = h.slice(8 + 64 + 24, 8 + 128);
        if (!/^[0-9a-f]{40}$/.test(from20) || !/^[0-9a-f]{40}$/.test(to20)) {
          return { kind: "unknown", selector: sel };
        }
        let from;
        let to;
        try {
          from = normalizeTronAddress("41" + from20, "from");
          to = normalizeTronAddress("41" + to20, "to");
        } catch {
          return { kind: "unknown", selector: sel };
        }
        const amount = BigInt("0x" + h.slice(8 + 128, 8 + 192));
        return { kind: "transferFrom", from, to, amount };
      }
      return { kind: "unknown", selector: sel };
    }
    module.exports = { parseTrc20CallData };
  }
});

// lib/tron/transaction/format-summary.js
var require_format_summary = __commonJS({
  "lib/tron/transaction/format-summary.js"(exports, module) {
    "use strict";
    var { SUN } = require_constants2();
    var { normalizeTronAddress } = require_normalize_address();
    var { parseTrc20CallData } = require_parse_trc20();
    var SUN_PER_TRX = BigInt(SUN);
    function parseNonNegativeSun(value, fieldLabel) {
      if (value === void 0 || value === null) {
        throw new Error(`${fieldLabel}: invalid amount`);
      }
      if (typeof value === "bigint") {
        if (value < 0n) {
          throw new Error(`${fieldLabel}: invalid amount`);
        }
        return value;
      }
      if (typeof value === "number") {
        if (!Number.isFinite(value) || value < 0 || !Number.isInteger(value)) {
          throw new Error(`${fieldLabel}: invalid amount`);
        }
        if (value > Number.MAX_SAFE_INTEGER) {
          throw new Error(
            `${fieldLabel}: amount exceeds safe JSON number range \u2014 use a decimal string`
          );
        }
        return BigInt(value);
      }
      if (typeof value === "string") {
        const t = value.trim();
        if (t === "" || !/^[0-9]+$/.test(t)) {
          throw new Error(`${fieldLabel}: invalid amount`);
        }
        return BigInt(t);
      }
      throw new Error(`${fieldLabel}: invalid amount`);
    }
    function formatTrxFromSun(sun) {
      const whole = sun / SUN_PER_TRX;
      const frac = sun % SUN_PER_TRX;
      const fracStr = frac.toString().padStart(6, "0");
      return `${whole}.${fracStr}`;
    }
    function formatHumanSummary(rawData) {
      const lines = [];
      const contracts = rawData.contract;
      if (!Array.isArray(contracts) || contracts.length === 0) {
        throw new Error("raw_data.contract is missing or empty");
      }
      for (let i = 0; i < contracts.length; i++) {
        const c = contracts[i];
        const type = c.type || "?";
        const val = c.parameter && c.parameter.value;
        if (type === "TransferContract" && val) {
          const from = normalizeTronAddress(val.owner_address, "owner_address");
          const to = normalizeTronAddress(val.to_address, "to_address");
          const amountSun = parseNonNegativeSun(val.amount, "TransferContract amount");
          lines.push(`Contract #${i + 1}: TransferContract (TRX)`);
          lines.push(`  From:    ${from}`);
          lines.push(`  To:      ${to}`);
          lines.push(
            `  Amount:  ${formatTrxFromSun(amountSun)} TRX  (${amountSun.toString()} SUN)`
          );
        } else if (type === "TriggerSmartContract" && val) {
          const owner = normalizeTronAddress(val.owner_address, "owner_address");
          const token = normalizeTronAddress(val.contract_address, "contract_address");
          lines.push(
            `Contract #${i + 1}: TriggerSmartContract (contract call, often TRC20)`
          );
          lines.push(`  Owner:            ${owner}`);
          lines.push(`  Contract address: ${token}`);
          const cv = val.call_value;
          if (cv !== void 0 && cv !== null) {
            const cvSun = parseNonNegativeSun(cv, "call_value");
            if (cvSun > 0n) {
              lines.push(
                `  TRX with call:    ${formatTrxFromSun(cvSun)} TRX  (${cvSun.toString()} SUN)`
              );
            }
          }
          const data = val.data;
          if (typeof data === "string" && data.length > 0) {
            const parsed = parseTrc20CallData(data);
            if (parsed.kind === "transfer") {
              lines.push(`  Call:             transfer(address,uint256)`);
              lines.push(`  To (token):       ${parsed.to}`);
              lines.push(`  Amount (raw):     ${parsed.amount.toString()} smallest units`);
              lines.push(
                `                    (human amount = raw / 10^decimals; decimals not queried offline)`
              );
            } else if (parsed.kind === "transferFrom") {
              lines.push(`  Call:             transferFrom(address,address,uint256)`);
              lines.push(`  From (token):     ${parsed.from}`);
              lines.push(`  To (token):       ${parsed.to}`);
              lines.push(`  Amount (raw):     ${parsed.amount.toString()} smallest units`);
              lines.push(
                `                    (human amount = raw / 10^decimals; decimals not queried offline)`
              );
            } else {
              lines.push(`  data (selector):  0x${parsed.selector}`);
              lines.push(
                `  Not transfer / transferFrom \u2014 verify calldata in an explorer or raw_data_hex.`
              );
            }
          } else {
            lines.push(`  data:             (empty \u2014 not TRC20 transfer by calldata)`);
          }
        } else {
          lines.push(`Contract #${i + 1}: ${type}`);
          lines.push(
            `  (details not parsed \u2014 verify raw_data_hex / contract in a trusted viewer)`
          );
        }
      }
      const fee = rawData.fee_limit;
      if (fee !== void 0 && fee !== null) {
        try {
          const feeSun = parseNonNegativeSun(fee, "fee_limit");
          lines.push(
            `Fee limit (fee_limit): ${feeSun.toString()} SUN (${formatTrxFromSun(feeSun)} TRX)`
          );
        } catch {
          lines.push(`Fee limit (fee_limit): ${String(fee)} (unparsed)`);
        }
      } else {
        lines.push(`Fee limit (fee_limit): (not set in JSON)`);
      }
      return lines.join("\n");
    }
    function buildUiSummaryFromRawData(rawData) {
      const warnings = [
        "Summary is derived from raw_data JSON; the signature binds only to raw_data_hex. Verify hex independently if unsure."
      ];
      const contracts = rawData.contract;
      if (!Array.isArray(contracts) || contracts.length === 0) {
        throw new Error("raw_data.contract is missing or empty");
      }
      let feeLimitText = "(not set in JSON)";
      const fee = rawData.fee_limit;
      if (fee !== void 0 && fee !== null) {
        try {
          const feeSun = parseNonNegativeSun(fee, "fee_limit");
          feeLimitText = `${formatTrxFromSun(feeSun)} TRX (${feeSun.toString()} SUN)`;
        } catch {
          feeLimitText = `${String(fee)} (unparsed)`;
        }
      }
      if (contracts.length > 1) {
        warnings.push(
          "Multiple contracts in one transaction \u2014 review raw_data_hex or a block explorer."
        );
        return {
          summary: {
            typeLabel: `${contracts.length} contracts (multi)`,
            from: "\u2014",
            to: "\u2014",
            amountText: "\u2014",
            feeLimitText
          },
          warnings
        };
      }
      const c = contracts[0];
      const type = c.type || "?";
      const val = c.parameter && c.parameter.value;
      if (type === "TransferContract" && val) {
        const from = normalizeTronAddress(val.owner_address, "owner_address");
        const to = normalizeTronAddress(val.to_address, "to_address");
        const amountSun = parseNonNegativeSun(val.amount, "TransferContract amount");
        return {
          summary: {
            typeLabel: "TransferContract (TRX)",
            from,
            to,
            amountText: `${formatTrxFromSun(amountSun)} TRX (${amountSun.toString()} SUN)`,
            feeLimitText
          },
          warnings
        };
      }
      if (type === "TriggerSmartContract" && val) {
        const owner = normalizeTronAddress(val.owner_address, "owner_address");
        const token = normalizeTronAddress(val.contract_address, "contract_address");
        const data = val.data;
        if (typeof data === "string" && data.length > 0) {
          const parsed = parseTrc20CallData(data);
          if (parsed.kind === "transfer") {
            return {
              summary: {
                typeLabel: "TriggerSmartContract (TRC20 transfer)",
                from: owner,
                to: parsed.to,
                tokenContract: token,
                tokenLabel: "TRC20",
                amountText: `${parsed.amount.toString()} (smallest units; decimals unknown offline)`,
                feeLimitText
              },
              warnings
            };
          }
          if (parsed.kind === "transferFrom") {
            return {
              summary: {
                typeLabel: "TriggerSmartContract (TRC20 transferFrom)",
                from: parsed.from,
                to: parsed.to,
                tokenContract: token,
                tokenLabel: "TRC20",
                amountText: `${parsed.amount.toString()} (smallest units; decimals unknown offline)`,
                feeLimitText
              },
              warnings
            };
          }
        }
        let amountText = "\u2014";
        const cv = val.call_value;
        if (cv !== void 0 && cv !== null) {
          try {
            const cvSun = parseNonNegativeSun(cv, "call_value");
            if (cvSun > 0n) {
              amountText = `TRX with call: ${formatTrxFromSun(cvSun)} TRX`;
            }
          } catch {
            amountText = String(cv);
          }
        }
        warnings.push(
          "Contract call is not a standard TRC20 transfer \u2014 verify calldata and raw_data_hex."
        );
        return {
          summary: {
            typeLabel: "TriggerSmartContract",
            from: owner,
            to: token,
            tokenContract: token,
            amountText,
            feeLimitText
          },
          warnings
        };
      }
      warnings.push(
        "Contract type not fully parsed in the UI \u2014 verify raw_data_hex in a trusted viewer."
      );
      return {
        summary: {
          typeLabel: String(type),
          from: "\u2014",
          to: "\u2014",
          amountText: "\u2014",
          feeLimitText
        },
        warnings
      };
    }
    module.exports = { formatHumanSummary, buildUiSummaryFromRawData };
  }
});

// lib/index.js
var require_index = __commonJS({
  "lib/index.js"(exports, module) {
    var { CliError } = require_errors();
    var {
      TRON_DERIVATION_PATH,
      TRON_PATH_RE,
      ALLOWED_ENTROPY_BITS,
      TRON_ADDRESS_VERSION_BYTE
    } = require_constants();
    var {
      asBuffer,
      publicKeyUncompressedToTronAddress,
      compressedPublicKeyToTronAddress,
      tronAddressBase58ToHex,
      decodeTronAddressBase58Checked,
      encodeTronBase58CheckPayload
    } = require_address();
    var {
      deriveWalletFromMnemonic,
      generateTronWallet,
      zeroBuffer
    } = require_derive();
    var { signTronTxId } = require_sign_tron_tx_id();
    var { verifyTxIdBinding } = require_verify_tx_id();
    var {
      formatHumanSummary,
      buildUiSummaryFromRawData
    } = require_format_summary();
    var { normalizeTronAddress } = require_normalize_address();
    var { parseTrc20CallData } = require_parse_trc20();
    module.exports = {
      CliError,
      TRON_DERIVATION_PATH,
      TRON_PATH_RE,
      ALLOWED_ENTROPY_BITS,
      TRON_ADDRESS_VERSION_BYTE,
      asBuffer,
      publicKeyUncompressedToTronAddress,
      compressedPublicKeyToTronAddress,
      tronAddressBase58ToHex,
      decodeTronAddressBase58Checked,
      encodeTronBase58CheckPayload,
      deriveWalletFromMnemonic,
      generateTronWallet,
      zeroBuffer,
      signTronTxId,
      verifyTxIdBinding,
      formatHumanSummary,
      buildUiSummaryFromRawData,
      normalizeTronAddress,
      parseTrc20CallData
    };
    module.exports.default = module.exports;
  }
});
export default require_index();
/*! Bundled license information:

@noble/secp256k1/index.js:
  (*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) *)

@noble/hashes/utils.js:
@noble/hashes/utils.js:
@noble/hashes/utils.js:
@noble/hashes/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@scure/base/index.js:
@scure/base/lib/index.js:
  (*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
