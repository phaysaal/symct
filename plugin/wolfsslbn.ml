(* WolfSSL sp_int Big Number format:
 *
 *   typedef struct sp_int {
 *       sp_size_t    used;     -- unsigned int, number of used digits
 *       sp_sign_t    sign;     -- uint8, sign indicator
 *       sp_int_digit dp[];     -- digit array (XALIGNED to SP_WORD_SIZEOF)
 *   };
 *
 *   sp_int_digit is uint32_t (32-bit) or uint64_t (64-bit).
 *
 *   Field offsets (fixed, independent of platform):
 *     used:  0  (4 bytes, unsigned int)
 *     sign:  4  (1 byte, uint8)
 *     dp[]:  8  (aligned to SP_WORD_SIZEOF: 4 or 8)
 *
 *   Digit size (platform-dependent):
 *     32-bit: 4 bytes (uint32_t), key_size/32 digits
 *     64-bit: 8 bytes (uint64_t), key_size/64 digits
 *)

open CryptoBN

open Binsec
open Libsse
open Types
open BnScript

module WolfSSLBN : CryptoBN = struct

  (*
     pushBN: Convert sp_int big number to bitvector

     Reads:
       used = @[bnp, 2]               (low 16 bits of unsigned int)
       sign = @[bnp + 4, 1]           (uint8, 1 = negative)
       data = @[bnp + 8, n * ws]      (sp_int_digit[], little-endian)

     If sign == 1, the bitvector value is negated.
  *)
  let pushBN env bv_stack bnp =
    let (dir, bvws, _, _, _, _, bv_zero, _) = CryptoBN.get_constants env in
    let ws = env.wordsize / 8 in
    let offset_sign = 4 in
    let offset_dp = 8 in
    let n_digits = !CryptoBN.key_size / 8 / ws in
    let bvx = CryptoBN.prefix_var "bv_" bnp in
    let var = eval_loc ~size:!CryptoBN.key_size bvx env in
    let rval = eval_expr bnp env in

    (* dp[]: data at fixed offset 8 *)
    let d = Dba.Expr.add rval (Dba.Expr.constant (bvws offset_dp)) in

    (* ITE chain: select data based on used count *)
    let rec read_gen sz n falsep =
      if n <= 1 then
        let truep = Dba.Expr.constant bv_zero in
        let cond = Dba.Expr.binary Dba.Binary_op.Eq sz
            (Dba.Expr.constant (bvws 0)) in
        Dba.Expr.ite cond truep falsep
      else
        let p = Dba.Expr.load (Size.Byte.create ((n - 1) * ws)) dir d in
        let truep = Dba.Expr.unary (Dba.Unary_op.Uext !CryptoBN.key_size) p in
        let cond = Dba.Expr.binary Dba.Binary_op.Eq sz
            (Dba.Expr.constant (bvws (n - 1))) in
        read_gen sz (n - 1) (Dba.Expr.ite cond truep falsep)
    in

    (* Load full data from dp *)
    let p = Dba.Expr.load (Size.Byte.create (!CryptoBN.key_size / 8)) dir d in

    (* Load used count: @[bnp, ws/2] then uext to env.wordsize *)
    let sz = Dba.Expr.unary (Dba.Unary_op.Uext env.wordsize)
        (Dba.Expr.load (Size.Byte.create (ws / 2)) dir rval) in

    let rval_data = read_gen sz n_digits p in
    let evar = lval2exp var in

    (* Load sign: @[bnp + 4, 1] (uint8) *)
    let sign_addr = Dba.Expr.add rval
        (Dba.Expr.constant (bvws offset_sign)) in
    let sign_val = Dba.Expr.load (Size.Byte.create 1) dir sign_addr in
    let is_negative = Dba.Expr.equal sign_val
        (Dba.Expr.constant (Bitvector.create (Z.of_int 1) 8)) in
    let rval_with_sign = Dba.Expr.ite is_negative
        (Dba.Expr.uminus evar) evar in
    Stack.push rval_with_sign bv_stack;

    (match var with
     | Var var ->
       let assign_data = Ir.Assign {var; rval = rval_data} in
       let assign_final = Ir.Assign {var; rval = evar} in
       [assign_data; assign_final]
     | _ -> failwith "Invalid Variable"
    )

  (*
     popBN: Convert bitvector to sp_int big number

     Writes:
       @[bnp + 4, 1]  := sign (uint8: 1 if negative, 0 otherwise)
       @[bnp, 2]      := used digit count (truncated to 16-bit unsigned short)
       @[bnp + 8, ..] := abs(bvx) as sp_int_digit[] (little-endian)
  *)
  let popBN env bv_stack bnp' =
    let (dir, bvws, _, _, _, _, _, bv_one) = CryptoBN.get_constants env in
    let ws = env.wordsize / 8 in
    let offset_sign = 4 in
    let offset_dp = 8 in
    let n_digits = !CryptoBN.key_size / 8 / ws in

    (* Compute digit count: ITE chain checking how many digits contain data *)
    let rec len_gen n z i bvx f =
      if n <= 0 then
        f (Dba.Expr.constant i)
      else
        let cond = Dba.Expr.binary Dba.Binary_op.LtU bvx
            (Dba.Expr.constant z) in
        let truep = Dba.Expr.constant i in
        let c = fun g -> f (Dba.Expr.ite cond truep g) in
        len_gen (n - 1) (Bitvector.shift_left z env.wordsize)
            (Bitvector.add i (bvws 1)) bvx c
    in

    let bvx = Stack.pop bv_stack in
    let bnp : Expr.t = eval_expr bnp' env in

    (* sign: @[bnp + 4, 1] := MSB(bvx) ? 1 : 0 *)
    let is_msb_set = Dba.Expr.equal
        (Dba.Expr.bit_restrict (!CryptoBN.key_size - 1) bvx)
        (Dba.Expr.constant (Bitvector.create (Z.of_int 1) 1)) in
    let sign_val = Dba.Expr.ite is_msb_set
        (Dba.Expr.constant (Bitvector.create (Z.of_int 1) 8))
        (Dba.Expr.constant (Bitvector.create (Z.of_int 0) 8)) in
    let sign_addr = Dba.Expr.add bnp
        (Dba.Expr.constant (Bitvector.create (Z.of_int offset_sign) env.wordsize)) in
    let store_sign = Ir.Store {base = None; dir; addr = sign_addr; rval = sign_val} in

    (* Compute abs(bvx) for data storage *)
    let bvx = Dba.Expr.ite is_msb_set
        (Dba.Expr.unary Dba.Unary_op.UMinus bvx) bvx in

    (* used: @[bnp, 2] := digit count (truncated to 16-bit unsigned short) *)
    let used_word = len_gen n_digits bv_one (bvws 0) bvx (fun x -> x) in
    let used_val = Dba.Expr.restrict 0 15 used_word in
    let store_used = Ir.Store {base = None; dir; addr = bnp; rval = used_val} in

    (* dp[]: @[bnp + 8, key_size] := data *)
    let dp_addr = Dba.Expr.add bnp
        (Dba.Expr.constant (Bitvector.create (Z.of_int offset_dp) env.wordsize)) in
    let store_data = Ir.Store {base = None; dir; addr = dp_addr; rval = bvx} in

    Format.printf "store_sign: %a\n" Ir.pp_fallthrough store_sign;
    Format.printf "store_used: %a\n" Ir.pp_fallthrough store_used;
    Format.printf "store_data: %a\n" Ir.pp_fallthrough store_data;
    [store_sign; store_used; store_data]
end

let () =
  Registry.register "wolfssl" (module WolfSSLBN : CryptoBN)
