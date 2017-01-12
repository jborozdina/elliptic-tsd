// Type definitions for elliptic.js v6.3.2
// Project: https://github.com/indutny/lib/elliptic.js
// Definitions by: Synereo Team <https://github.com/synereo>
// Definitions: https://github.com/synereo/elliptic-tsd

export as namespace elliptic;
export = elliptic;

declare namespace elliptic {

    export var eddsa: EDDSAStatic;
    export var ec: ECStatic;
    export var hmacDRBG: HmacDRBGStatic;
    /*
     * Supported curves: p192, p224, p256, p384, p521, curve25519, ed25519, secp256k1
     */
    export var curves: {[key:string]: PresetCurve;}
    export const version: string;
    export function rand(len: number): Uint8Array;

    type Curve = curve.EdwardsCurve | curve.MontCurve | curve.ShortCurve;
    type Point = curve.edwards.Point | curve.mont.Point | curve.short.Point | curve.short.JPoint;

    // ---------------------------- hash.js module types
    /*
     * Supported hash functions: SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160
     */
    interface Hash {
        blockSize: number;
        hmacStrength: number;
        outSize: number;
        padLength: number;
        pendingTotal: number;
        pending: number[];
        endian: string;
        h: number[];
        k?: number[];
        W?: number[];

        update(msg: ArrayOrString, enc?: EncType): Hash;
        digest(enc?: EncType): ArrayOrString; 
    }

    // ---------------------------- bn.js module types
    interface BN {
        length: number;
        negative: number;
        red: Red;
        words: number[];

        _countBits(w: number): number;
        _expand(size: number): BN;
        _forceRed(ctx: BN): BN;
        _iaddn(num: number): BN;
        _init(number: number | string | string[], base: number | string, endian: string): BN;
        _initArray(number: number[], base: number, endian: string): BN;
        _initNumber(number: number, base: number, endian: string): BN;
        _invmp(p: BN): BN;
        _ishlnsubmul(num: BN, mul: number, shift: number): BN;
        _normSign(): BN;
        _parseBase(number: BN, base: number, start: number): BN;
        _parseHex(number: BN, start: number): BN;
        _wordDiv(num: BN, mode: string): DivModObj;
        _zeroBits(w: number): number;
        abs(): BN;
        add(num: BN): BN;
        addn(num: number): BN;
        and(num: BN): BN;
        andln(num: number): number;
        bincn(bit: number): BN;
        bitLength(): number;
        byteLength(): number;
        clone(): BN;
        cmp(num: BN): number;
        cmpn(num: BN): number;
        copy(dest: BN): void;
        div(num: BN): BN;
        divRound(num: BN): BN;
        divmod(num: BN, mode?: string, positive?: boolean): DivModObj;
        divn(num: number): BN;
        egcd(p: BN): BN;
        eq(num: BN): boolean;
        eqn(num: BN): boolean;
        forceRed(ctx: BN): BN;
        fromRed(): BN;
        fromTwos(width: number): BN;
        gcd(p: BN): Object;
        gt(num: BN): boolean;
        gte(num: BN): boolean;
        gten(num: BN): boolean;
        gtn(num: BN): boolean;
        iabs(): BN;
        iadd(num: BN): BN;
        iaddn(num: number): BN;
        iand(num: BN): BN;
        idivn(num: number): BN;
        imaskn(bits: number): BN;
        imul(num: BN): BN;
        imuln(num: number): BN;
        ineg(): BN;
        inotn(width: number): BN;
        inspect(): string;
        invm(num: BN): BN;
        ior(num: BN): BN;
        isEven(): boolean;
        isNeg(): boolean;
        isOdd(): boolean;
        isZero(): boolean;
        ishln(bits: number): BN;
        ishrn(bits: number, hint?: number, extended?: boolean): BN;
        isqr(): BN;
        isub(num: BN): BN;
        isubn(num: number): BN;
        iuand(num: BN): BN;
        iuor(num: BN): BN;
        iushln(bits: number): BN;
        iushrn(bits: number, hint?: number, extended?: boolean): BN;
        iuxor(num: BN): BN;
        ixor(num: BN): BN;
        lt(num: BN): boolean;
        lte(num: BN): boolean;
        lten(num: BN): boolean;
        ltn(num: BN): boolean;
        maskn(bits: number): BN;
        mod(num: BN): BN;
        modn(num: number): BN;
        mul(num: BN): BN;
        mulTo(num: BN, out: BN): BN;
        mulf(num: BN): BN;
        muln(num: number): BN;
        neg(): BN;
        notn(width: number): BN;
        or(num: BN): BN;
        pow(num: BN): BN;
        redAdd(num: BN): BN;
        redIAdd(num: BN): BN;
        redIMul(num: BN): BN;
        redISqr(): BN;
        redISub(num: BN): BN;
        redInvm(): BN;
        redMul(num: BN): BN;
        redNeg(): BN;
        redPow(num: BN): BN;
        redShl(num: number): BN;
        redSqr(): BN;
        redSqrt(): BN;
        redSub(num: BN): BN;
        setn(bit: number, val: boolean): BN;
        shln(bits: number): BN;
        shrn(bits: number): BN;
        sqr(a: BN): BN;
        strip(): BN;
        sub(num: BN): BN;
        subn(num: number): BN;
        testn(bit: number): boolean;
        toArray(endian: string, length?: number): number[];
        toBuffer(endian: string, length?: number): any;
        toJSON(): string;
        toNumber(): number;
        toRed(ctx: BN): BN;
        toString(base?: number | string, padding?: number): string;
        toTwos(width: number): BN;
        uand(num: BN): BN;
        ucmp(num: BN): number;
        umod(num: BN): BN;
        uor(num: BN): BN;
        ushln(bits: number): BN;
        ushrn(bits: number): BN;
        uxor(num: BN): BN;
        xor(num: BN): BN;
        zeroBits(): number;
    }
    interface DivModObj {
        div: BN;
        mod: BN;
    }
    interface MPrime {
        name: string;
        p: BN;
        n: number;
        k: BN;
        tmp: BN;

        ireduce(num: BN): BN;
        split(input: BN, output: boolean): BN;
        imulK(num: BN): BN;
    }
    interface Red {
        m: BN;
        prime: MPrime;

        imod(a: BN): BN;
        neg(a: BN): BN;
        add(a: BN, b: BN): BN;
        iadd(a: BN, b: BN): BN;
        sub(a: BN, b: BN): BN;
        isub(a: BN, b: BN): BN;
        shl(a: BN, num: number): BN;
        imul(a: BN, b: BN): BN;
        mul(a: BN, b: BN): BN;
        isqr(a: BN): BN;
        sqr(a: BN): BN;
        sqrt(a: BN): BN;
        invm(a: BN): BN;
        pow(a: BN, num: BN): BN;
        convertTo(num: BN): BN;
        convertFrom(num: BN): BN;
    }
    interface Mont extends Red {
        shift: number;
        r: BN;
        r2: BN;
        rinv: BN;
        minv: BN;
    }

    // ---------------------------- auxillary types
    interface Vector {
        a: BNConstructedType;
        b: BNConstructedType;
    }

    type EncType = string | number;
    type BNConstructedType = number | string | number[] | BN;
    type ArrayOrString = number[] | string;

    // ---------------------------- ec module types
    interface ECStatic {
        new(options: string | PresetCurve): EC;
    }

    interface EC {
        curve: Curve;
        n: BN;
        nh: BN;
        g: Point;
        hash: Hash;

        genKeyPair(options?: KeyPairGeneratorOptions): KeyPair1;
        getKeyRecoveryParam(e: BNConstructedType, signature: SignatureOptions, Q: BN, enc: EncType): number;
        keyFromPrivate(priv: KeyPair1 | BNConstructedType, enc: EncType): KeyPair1;
        keyFromPublic(pub: KeyPair1 | BNConstructedType, enc: EncType): KeyPair1;
        keyPair(options: KeyPairOptions): KeyPair1;
        recoverPubKey(msg: BNConstructedType, signature: SignatureOptions, j: number, enc: EncType): BN;
        sign(msg: BNConstructedType, key: KeyPair1 | BN, enc: EncType, options?: any): Signature1;
        verify(msg: BNConstructedType, signature: SignatureOptions, key: KeyPair1 | BN, enc: EncType): boolean;
    }

    interface KeyPairGeneratorOptions {
        pers: string;
        entropy?: ArrayOrString;
    }

    interface KeyPairOptions {
        priv?: BNConstructedType;
        pub?: BNConstructedType;
        privEnc?: EncType;
        pubEnc?: EncType;
    }

    interface SignatureParams {
        r: BNConstructedType;
        s: BNConstructedType;
        recoveryParam?: number;
    }

    interface ValidationResult {
        result: boolean;
        reason: string;
    }

    type SignatureOptions = ArrayOrString | SignatureParams | Signature1;

    class KeyPair1 {
        ec: EC;
        /**
         * @nullable
         */
        priv: BN;
        /**
         * @nullable
         */
        pub: BN;

        constructor(ec: EC, options: KeyPairOptions);
        fromPublic(ec: EC, pub: BNConstructedType | KeyPair1, enc: EncType): KeyPair1;
        fromPrivate(ec: EC, priv: BNConstructedType | KeyPair1, enc: EncType): KeyPair1;
        validate(): ValidationResult;
        getPublic(compact?: string, enc?: EncType): BN;
        getPrivate(enc?: string): BN | string;
        _importPrivate(key: BNConstructedType, enc?: EncType): void;
        _importPublic(key: BNConstructedType, enc?: EncType): void;
        derive(pub: BN): BN;
        sign(msg: BNConstructedType, enc?: EncType, options?: any): Signature1;
        verify(msg: BNConstructedType, signature: SignatureOptions): boolean;
        inspect(): string;
    }

    class Signature1 {
        r: BN;
        s: BN;
        /**
         * @nullable
         */
        recoveryParam: any;
        place?: number;

        constructor(options: SignatureOptions, enc: EncType);
        toDER(enc?: EncType): ArrayOrString;
    }

    // ---------------------------- eddsa module types
    interface EDDSAStatic {
        new(curve: string | PresetCurve): EDDSA;
    }

    interface EDDSA {
        curve: Curve;
        g: Point;
        pointClass: string;
        encodingLength: number;
        hash: Hash;

        decodeInt(bytes: BNConstructedType): BN;
        decodePoint(bytes: ArrayOrString): Point;
        encodeInt(num: BN): number[];
        encodePoint(point: Point): number[];
        hashInt(...args: any[]): BN;
        isPoint(val: any): boolean;
        keyFromPublic(pub: any, enc?: EncType): KeyPair2;
        keyFromSecret(secret: any): KeyPair2;
        makeSignature(sig: any): Signature2;
        sign(message: ArrayOrString, secret: ArrayOrString | KeyPair2): Signature2;
        verify(message: number[], sig: ArrayOrString | Signature2, pub: ArrayOrString | Point | KeyPair2): boolean;
    }

    interface KeyPairParams {
        secret?: ArrayOrString;
        pub?: Point | ArrayOrString;
    }

    interface SignatureObject {
        R: number[] | Point;
        S: number[] | BN;
        Rencoded?: number[];
        Sencoded?: number[];
    }

    class KeyPair2 {
        _secret: number[];
        _pub: Point;
        _priv: BN;
        _pubBytes: number[];
        _privBytes: number[];
        _hash: number[];
        _messagePrefix: number[];

        constructor(eddsa: EDDSA, params: KeyPairParams);
        fromPublic(eddsa: EDDSA, pub: KeyPair2): KeyPair2;
        fromSecret(eddsa: EDDSA, pub: KeyPair2): KeyPair2;
        secret(): number[];
        sign(message: ArrayOrString): Signature2;
        verify(message: number[], sig: ArrayOrString | Signature2): boolean;
        getSecret(enc: EncType): ArrayOrString;
        getPublic(enc: EncType): ArrayOrString;
    }

    class Signature2 {
        _R: Point;
        _S: BN;
        _Rencoded: number[];
        _Sencoded: number[];

        constructor(eddsa: EDDSA, sig: ArrayOrString | SignatureObject)
        toBytes(): number[];
        toHex(): string;
    }

    // ---------------------------- hmac-drbg module types
    interface HmacDRBGOptions {
        hash: Hash;
        predResist: any;
        minEntropy: number;
        entropy: ArrayOrString;
        entropyEnc: EncType;
        nonce: ArrayOrString;
        nonceEnc: EncType;
        pers: ArrayOrString;
        persEnc: EncType;
    }

    interface HmacDRBGStatic {
        new (options: HmacDRBGOptions): HmacDRBG;
        reseed(entropy: ArrayOrString, entropyEnc: EncType, add: ArrayOrString, addEnc: EncType): void;
    }

    interface HmacDRBG {
        hash: Hash;
        predResist: boolean;
        outLen: number;
        minEntropy: number;
        /**
         * @nullable
         */
        reseed: number;
        /**
         * @nullable
         */
        reseedInterval: number;
        /**
         * @nullable
         */
        K: number[];
        /**
         * @nullable
         */
        V: number[];
        
        generate(len: any, enc: EncType, add: any, addEnc: EncType): ArrayOrString;        
    }

    // ---------------------------- curve module types
    export namespace curve {
        interface CurveConf {
            p: BNConstructedType;
            prime?: number;
            n: BNConstructedType;
            g: string[];
            gRed: BN;
            a?: BNConstructedType;
            b?: BNConstructedType;
            c?: BNConstructedType;
            d?: BNConstructedType;
        }
        interface Precomputed {
            doubles: PrecomputedObj;
            naf: PrecomputedObj;
            /**
             * @nullable
             */
            beta: any;
        }
        interface PrecomputedObj {
            step?: number;
            wnd?: number;
            points: Point[];
        }
        interface Endomorphism {
            beta?: BNConstructedType;
            lambda?: BNConstructedType;
            basis?: Vector[];
        }
        class BaseCurve {
            type: string;
            p: BN;
            red: Red;
            zero: BN;
            one: BN;
            two: BN;
            n?: BN;
            g?: Point;
            /**
             * @nullable
             */
            redN: Red;

            constructor(type: string, conf: CurveConf);
            decodePoint(bytes: ArrayOrString, enc: EncType): Point;
            point(x?: BNConstructedType, y?: BNConstructedType, z?: BNConstructedType, t?: BNConstructedType, isRed?: boolean): Point;
            validate(point?: Point): boolean;
            pointFromJSON(obj: Object, isRed?: boolean): Point;
        }
        export class MontCurve extends BaseCurve {
            a: Red;
            b: Red;
            i4: BN;
            a24: BN;

            constructor(conf: CurveConf);
            decodePoint(bytes: ArrayOrString, enc: EncType): Point;
            point(x?: BNConstructedType, y?: BNConstructedType, z?: BNConstructedType, t?: BNConstructedType, isRed?: boolean): Point;
            validate(point?: Point): boolean;
            pointFromJSON(obj: Object, isRed?: boolean): Point;
        }
        export class EdwardsCurve extends BaseCurve {
            twisted: boolean;
            mOneA: boolean;
            extended: boolean;
            oneC: boolean;
            a: BN;
            c: BN;
            c2: BN;
            d: BN;
            dd: BN;

            constructor(conf: CurveConf);
            jpoint(x: BNConstructedType, y: BNConstructedType, z: BNConstructedType, t: BNConstructedType): Point;
            pointFromX(x: BNConstructedType, odd: boolean): Point;
            pointFromY(y: BNConstructedType, odd: boolean): Point;
            decodePoint(bytes: ArrayOrString, enc: EncType): Point;
            point(x?: BNConstructedType, y?: BNConstructedType, z?: BNConstructedType, t?: BNConstructedType, isRed?: boolean): Point;
            validate(point?: Point): boolean;
            pointFromJSON(obj: Object, isRed?: boolean): Point;
        }
        export class ShortCurve extends BaseCurve {
            a: BN;
            b: BN;
            tinv: any;
            zeroA: boolean;
            threeA: boolean;
            endo: Endomorphism;

            constructor(conf: any);
            decodePoint(bytes: ArrayOrString, enc: EncType): Point;
            point(x?: BNConstructedType, y?: BNConstructedType, z?: BNConstructedType, t?: BNConstructedType, isRed?: boolean): Point;
            jpoint(x: BNConstructedType, y: BNConstructedType, z: BNConstructedType): short.JPoint;
            validate(point?: Point): boolean;
            pointFromJSON(obj: Object, red?: boolean): Point;
            pointFromX(x: BNConstructedType, odd: boolean): Point;
        }
        class BasePoint {
            curve: Curve;
            type: string;
            /**
             * @nullable
             */
            precomputed: Precomputed;

            constructor(curve: Curve, type: string);

            dblp(k: number): Point;
            encode(enc: EncType, compact: boolean): ArrayOrString;
            encodeCompressed(enc: EncType): ArrayOrString;

            dbl(): Point;
            eq(other: Point): boolean;
            precompute(power: number): Point;
            validate(): boolean;
        }
        namespace mont {
            export class Point extends BasePoint {
                x: BN;
                z: BN;

                constructor(curve: Curve, x: BNConstructedType, z: BNConstructedType);
                fromJSON(curve: Curve, obj: Object): Point;
                dbl(): Point;
                eq(other: Point): boolean;
                precompute(power: number): Point;
                validate(): boolean;
                inspect(): string;
                isInfinity(): boolean;
                add(p: Point): Point;
                diffAdd(p: Point, diff: Point): Point;
                mulAdd(): Point;
                jumlAdd(): Point;
                normalize(): Point;
                getX(): BN;
            }
        }
        namespace edwards {
            export class Point extends BasePoint {
                x: BN;
                y: BN;
                z: BN;
                t: BN;
                zOne: boolean;

                constructor(curve: Curve, x: BNConstructedType, y: BNConstructedType, z: BNConstructedType, t: BNConstructedType);
                fromJSON(curve: Curve, obj: Object): Point;
                inspect(): string;
                isInfinity(): boolean;
                dbl(): Point;
                add(p: Point): Point;
                mul(k: BN): Point;
                mulAdd(k1: BN, p: Point, k2: BN): Point;
                jmulAdd(k1: BN, p: Point, k2: BN): Point;
                normalize(): Point;
                neg(): Point;
                getX(): BN;
                getY(): BN;
                eq(other: Point): boolean;
                eqXToP(x: BN): boolean;
                precompute(power: number): Point;
                validate(): boolean;
                toP(): Point;
                mixedAdd(p: Point): Point;
            }
        }
        namespace short {
            export class Point extends BasePoint {
                x: BN;
                y: BN;
                inf: boolean;

                constructor(curve: Curve, x: BNConstructedType, y: BNConstructedType, isRed: boolean);
                dbl(): Point;
                eq(other: Point): boolean;
                toJSON(): Object[];
                fromJSON(curve: Curve, obj: Object, red: boolean): Point;
                validate(): boolean;
                toJ(): JPoint;
                inspect(): string;
                isInfinity(): boolean;
                add(p: Point): Point;
                mul(k: BNConstructedType): Point;
                mulAdd(k1: BN, p2: Point, k2: BN): Point;
                jmulAdd(k1: BN, p2: Point, k2: BN): Point;
                neg(_precompute?: boolean): Point;
                getX(): BN;
                getY(): BN;
            }
            export class JPoint extends BasePoint {
                x: BN;
                y: BN;
                z: BN;
                zOne: boolean;

                constructor(curve: Curve, x: BNConstructedType, y: BNConstructedType, z: BNConstructedType);
                eq(other: JPoint): boolean;
                toP(): JPoint;
                neg(): JPoint;
                add(p: JPoint): JPoint;
                mixedAdd(p: JPoint): JPoint;
                dblp(pow: number): JPoint;
                dbl(): JPoint;
                trpl(): JPoint;
                mul(k: BN, kbase: EncType): JPoint;
                eqXToP(x: BN): boolean;
                inspect(): string;
                isInfinity(): boolean;
            }
        }
    }

    // ---------------------------- curves module
    class PresetCurve {
        curve: Curve;
        g: Point;
        hash: Hash;
        n: BN;

        constructor(options: PresetCurveOptions)
        validate(point: Point): boolean;
    }

    interface PresetCurveOptions {
        type: string;
        /**
         * @nullable
         */
        prime: string;
        p: ArrayOrString;
        a: ArrayOrString;
        b: ArrayOrString;
        n: ArrayOrString;
        h?: string;
        hash: Hash;
        gRed: boolean;
        g: Point;

        // Precomputed endomorphism
        beta?: BNConstructedType;
        lambda?: BNConstructedType;
        basis?: Vector[];
    }

    // ---------------------------- utils module
    export namespace utils {
        function assert(val: boolean, msg: string): void;
        function encode(arr: ArrayOrString, enc: EncType): ArrayOrString;
        function getJSF(k1: BN, k2: BN): number[][];
        function getNAF(num: BN, w: number): number[];
        function intFromLE(bytes: BNConstructedType): BN;
        function parseBytes(bytes: ArrayOrString): number[];
        function toArray(msg: ArrayOrString | Object, enc: EncType): number[];
        function toHex(msg: ArrayOrString): string;
        function zero2(word: string): string;
    }
}