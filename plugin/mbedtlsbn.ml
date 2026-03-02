(* mbedTLS Big Number (mbedtls_mpi) format:
 *
 *   typedef struct mbedtls_mpi {
 *       mbedtls_mpi_uint *p;  -- pointer to limbs array (little-endian)
 *       signed short s;       -- sign: 1 (positive), -1 (negative)
 *       unsigned short n;     -- number of valid limbs
 *   } mbedtls_mpi;
 *
 *   mbedtls_mpi_uint is uint32_t (32-bit) or uint64_t (64-bit).
 *
 *   Field offsets (ws = pointer size = env.wordsize/8):
 *     p:  0           (pointer, ws bytes)
 *     s:  ws          (signed short, 2 bytes)   (4 for 32-bit, 8 for 64-bit)
 *     n:  ws + 2      (unsigned short, 2 bytes) (6 for 32-bit, 10 for 64-bit)
 *
 *   Limb size (platform-dependent):
 *     32-bit: 4 bytes (uint32_t), key_size/32 limbs
 *     64-bit: 8 bytes (uint64_t), key_size/64 limbs
 *)

open CryptoBN

open Binsec
open Libsse
open Types
open BnScript

module MbedTLSBN : CryptoBN = struct

  (*
     pushBN: Convert mbedtls_mpi to bitvector

     Reads:
       p    = @[bnp, ws]         (pointer to limbs array)
       s    = @[bnp + ws, 2]     (signed short, sign field)
       n    = @[bnp + ws + 2, 2] (unsigned short, limb count)
       data = @[p, n * ws]       (limbs in little-endian order)

     If s == -1 (0xFFFF), the bitvector value is negated.
  *)
  let pushBN env bv_stack bnp =
    let (dir, bvws, word_size, _, _, _, bv_zero, _) = CryptoBN.get_constants env in
    let ws = env.wordsize / 8 in
    let offset_s = ws in
    let offset_n = ws + 2 in
    let n_limbs = !CryptoBN.key_size / 8 / ws in
    let bvx = CryptoBN.prefix_var "bv_" bnp in
    let var = eval_loc ~size:!CryptoBN.key_size bvx env in
    let rval = eval_expr bnp env in

    (* Load pointer to data: p = @[bnp, ws] *)
    let d = Dba.Expr.load word_size dir rval in

    (* ITE chain: select data based on limb count *)
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

    (* Load full data from pointer *)
    let p = Dba.Expr.load (Size.Byte.create (!CryptoBN.key_size / 8)) dir d in

    (* Load n (limb count): @[bnp + ws + 2, 2] (unsigned short) *)
    let n_addr = Dba.Expr.add rval (Dba.Expr.constant (bvws offset_n)) in
    let sz = Dba.Expr.unary (Dba.Unary_op.Uext env.wordsize)
        (Dba.Expr.load (Size.Byte.create 2) dir n_addr) in

    let rval_data = read_gen sz n_limbs p in
    let evar = lval2exp var in

    (* Load sign: s = @[bnp + ws, 2] (signed short) *)
    let s_addr = Dba.Expr.add rval (Dba.Expr.constant (bvws offset_s)) in
    let s_short = Dba.Expr.load (Size.Byte.create 2) dir s_addr in
    let s = Dba.Expr.unary (Dba.Unary_op.Sext env.wordsize) s_short in

    (* If s == -1, negate the value *)
    let neg_one = Bitvector.create (Z.of_int (-1)) env.wordsize in
    let rval_with_sign = Dba.Expr.ite
        (Dba.Expr.equal s (Dba.Expr.constant neg_one))
        (Dba.Expr.uminus evar) rval_data in
    Stack.push rval_with_sign bv_stack;

    (match var with
     | Var var ->
       let assign_data = Ir.Assign {var; rval = rval_with_sign} in
       [assign_data]
     | _ -> failwith "Invalid Variable"
    )

  (*
     popBN: Convert bitvector to mbedtls_mpi

     Writes:
       @[bnp + ws, 2]     := s (signed short: -1 if negative, 1 otherwise)
       @[bnp + ws + 2, 2] := n (unsigned short: limb count)
       @[p, key_size]     := abs(bvx) in little-endian limb order

     p = @[bnp, ws] is read-only (already allocated).
  *)
  let popBN env bv_stack bnp' =
    let (dir, bvws, word_size, _, _, _, _, bv_one) = CryptoBN.get_constants env in
    let ws = env.wordsize / 8 in
    let offset_s = ws in
    let offset_n = ws + 2 in
    let n_limbs = !CryptoBN.key_size / 8 / ws in

    (* Compute limb count: ITE chain checking how many limbs contain data *)
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

    (* s: @[bnp + ws, 2] := MSB(bvx) ? -1 : 1 (signed short) *)
    let is_msb_set = Dba.Expr.equal
        (Dba.Expr.bit_restrict (!CryptoBN.key_size - 1) bvx)
        (Dba.Expr.constant (Bitvector.create (Z.of_int 1) 1)) in
    let neg_one_short = Bitvector.create (Z.of_int (-1)) 16 in
    let pos_one_short = Bitvector.create (Z.of_int 1) 16 in
    let s_val = Dba.Expr.ite is_msb_set
        (Dba.Expr.constant neg_one_short) (Dba.Expr.constant pos_one_short) in
    let s_addr = Dba.Expr.add bnp (Dba.Expr.constant (bvws offset_s)) in
    let store_sign = Ir.Store {base = None; dir; addr = s_addr; rval = s_val} in

    (* Compute absolute value for storage *)
    let var = match bvx with Dba.Expr.Var v -> v | _ -> failwith "Invalid bvx" in
    let compute_abs = Ir.Assign {var; rval = bvx} in

    (* n: @[bnp + ws + 2, 2] := limb count (truncated to 16-bit unsigned short) *)
    let n_addr = Dba.Expr.add bnp (Dba.Expr.constant (bvws offset_n)) in
    let n_val_word = len_gen n_limbs bv_one (bvws 0) bvx (fun x -> x) in
    let n_val = Dba.Expr.restrict 0 15 n_val_word in
    let store_n = Ir.Store {base = None; dir; addr = n_addr; rval = n_val} in

    (* data: @[p, key_size] := bvx via pointer dereference *)
    let p_addr = Dba.Expr.load word_size dir bnp in
    let store_data = Ir.Store {base = None; dir; addr = p_addr;
                               rval = Dba.Expr.v var} in

    Format.printf "store_sign: %a\n" Ir.pp_fallthrough store_sign;
    Format.printf "compute_abs: %a\n" Ir.pp_fallthrough compute_abs;
    Format.printf "store_n: %a\n" Ir.pp_fallthrough store_n;
    Format.printf "store_data: %a\n" Ir.pp_fallthrough store_data;
    [store_sign; compute_abs; store_n; store_data]
end

let () =
  Registry.register "mbedtls" (module MbedTLSBN : CryptoBN)
