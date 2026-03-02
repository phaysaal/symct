(* OpenSSL BIGNUM struct layout:
 *
 *   struct bignum_st {
 *       BN_ULONG *d;    -- pointer to word array
 *       int top;         -- index of last used word + 1
 *       int dmax;        -- allocated size of d (in words)
 *       int neg;         -- sign: 1 if negative, 0 otherwise
 *       int flags;
 *   };
 *
 *   Field offsets (ws = pointer size = env.wordsize/8):
 *     d:     0
 *     top:   ws        (4 for 32-bit, 8 for 64-bit)
 *     dmax:  ws + 4    (8 for 32-bit, 12 for 64-bit)
 *     neg:   ws + 8    (12 for 32-bit, 16 for 64-bit)
 *     flags: ws + 12   (16 for 32-bit, 20 for 64-bit)
 *)

open CryptoBN

open Binsec
open Libsse
open Types
open BnScript

let bv32 n = Bitvector.create (Z.of_int n) 32
let int_size = Size.Byte.create 4

module OpenSSLBN : CryptoBN = struct
  let pushBN env bv_stack bnp =
    let (dir, bvws, word_size, _, _, _, bv_zero, _) = CryptoBN.get_constants env in
    let ws = env.wordsize / 8 in
    let offset_top = ws in
    let offset_neg = ws + 8 in
    let bvx = CryptoBN.prefix_var "bv_" bnp in
    let var = eval_loc ~size:!CryptoBN.key_size bvx env in
    let rval = eval_expr bnp env in
    let d = Dba.Expr.load word_size dir rval in
    let rec read_gen sz n falsep =
      if n <= 1 then
        let truep = Dba.Expr.constant bv_zero in
        let cond = Dba.Expr.binary Dba.Binary_op.Eq sz (Dba.Expr.constant (bv32 0)) in
        Dba.Expr.ite cond truep falsep
      else
        let p = Dba.Expr.load (Size.Byte.create ((n - 1) * ws)) dir d in
        let truep = Dba.Expr.unary (Dba.Unary_op.Uext !CryptoBN.key_size) p in
        let cond = Dba.Expr.binary Dba.Binary_op.Eq sz (Dba.Expr.constant (bv32 (n - 1))) in
        read_gen sz (n - 1) (Dba.Expr.ite cond truep falsep)
    in

    let p = Dba.Expr.load (Size.Byte.create (!CryptoBN.key_size / 8)) dir d in
    let szaddr = Dba.Expr.binary Dba.Binary_op.Plus rval (Dba.Expr.constant (bvws offset_top)) in
    let bnp_base = rval in
    let sz = Dba.Expr.load int_size dir szaddr in
    let rval = read_gen sz (!CryptoBN.key_size / 8 / ws) p in
    let evar = lval2exp var in

    (* neg: if bn->neg == 1, negate the value *)
    let neg_addr =
      Dba.Expr.binary Dba.Binary_op.Plus bnp_base (Dba.Expr.constant (bvws offset_neg))
    in
    let is_negative =
      Dba.Expr.equal
        (Dba.Expr.load int_size dir neg_addr)
        (Dba.Expr.constant (bv32 1))
    in
    let rval_with_sign = Dba.Expr.ite is_negative (Dba.Expr.uminus evar) evar in
    Stack.push evar bv_stack;

    (match var with
     | Var var ->
       let assign_data = Ir.Assign {var; rval} in
       let assign_sign = Ir.Assign {var; rval = rval_with_sign} in
       [assign_data; assign_sign]
     | _ -> failwith "Invalid Variable"
    )

  let popBN env bv_stack bnp' =
    let (dir, _, word_size, _, _, _, _bv_zero, bv_one) = CryptoBN.get_constants env in
    let ws = env.wordsize / 8 in
    let offset_top = ws in
    let offset_dmax = ws + 4 in
    let offset_neg = ws + 8 in
    let offset_flags = ws + 12 in

    let rec len_gen n z i bvx f =
      if n <= 0 then
        let falsep = Dba.Expr.constant (Bitvector.create (Z.of_int (Bitvector.to_uint i)) env.wordsize) in
        f falsep
      else
        let cond = (Dba.Expr.binary Dba.Binary_op.LtU bvx (Dba.Expr.constant z)) in
        let truep = Dba.Expr.constant (Bitvector.create (Z.of_int (Bitvector.to_uint i)) env.wordsize) in
        let c = (fun g -> f (Dba.Expr.ite cond truep g)) in
        len_gen (n - 1) (Bitvector.shift_left z env.wordsize) (Bitvector.add i (bv32 1)) bvx c
    in

    let bvx = Stack.pop bv_stack in
    let bnp : Expr.t = eval_expr bnp' env in

    (* dmax: number of allocated words *)
    let rval = Dba.Expr.constant (bv32 (256 / ws)) in
    let offset = Dba.Expr.constant (Bitvector.create (Z.of_int offset_dmax) env.wordsize) in
    let addr = Dba.Expr.add bnp offset in
    let store_dmax = Ir.Store {base = None; dir; addr; rval} in

    (* flags *)
    let rval = Dba.Expr.constant (bv32 0x1) in
    let offset = Dba.Expr.constant (Bitvector.create (Z.of_int offset_flags) env.wordsize) in
    let addr = Dba.Expr.add bnp offset in
    let store_flags = Ir.Store {base = None; dir; addr; rval} in

    (* neg: set from MSB of bvx *)
    let is_msb_set =
      Dba.Expr.equal
        (Dba.Expr.bit_restrict (!CryptoBN.key_size - 1) bvx)
        (Dba.Expr.constant (Bitvector.create (Z.of_int 1) 1))
    in
    let rval = Dba.Expr.ite is_msb_set (Dba.Expr.constant (bv32 1)) (Dba.Expr.constant (bv32 0)) in
    let offset = Dba.Expr.constant (Bitvector.create (Z.of_int offset_neg) env.wordsize) in
    let addr = Dba.Expr.add bnp offset in
    let store_neg = Ir.Store {base = None; dir; addr; rval} in

    (* compute abs(bvx) *)
    let var = match bvx with Dba.Expr.Var v -> v | _ -> failwith "Invalid bvx" in
    let abs_addr = addr in
    let neg_field = Dba.Expr.load int_size dir abs_addr in
    let cond = Dba.Expr.binary Dba.Binary_op.Eq neg_field (Dba.Expr.constant (bv32 1)) in
    let rval = Dba.Expr.ite cond (Dba.Expr.unary Dba.Unary_op.UMinus bvx) bvx in
    let compute_abs = Ir.Assign {var; rval} in

    (* top: number of significant words *)
    let offset = Dba.Expr.constant (Bitvector.create (Z.of_int offset_top) env.wordsize) in
    let addr = Dba.Expr.add bnp offset in
    let rval = Dba.Expr.restrict 0 31
        (len_gen (!CryptoBN.key_size / 8 / ws) bv_one (bv32 0) bvx (fun x -> x)) in
    let store_top = Ir.Store {base = None; dir; addr; rval} in

    (* data: store bvx words via d pointer *)
    let addr = Dba.Expr.load word_size dir bnp in
    let rval = Dba.Expr.v var in
    let store_data = Ir.Store {base = None; dir; addr; rval} in

    Format.printf "store_dmax: %a\n" Ir.pp_fallthrough store_dmax;
    Format.printf "store_neg: %a\n" Ir.pp_fallthrough store_neg;
    Format.printf "compute_abs: %a\n" Ir.pp_fallthrough compute_abs;
    Format.printf "store top: %a\n" Ir.pp_fallthrough store_top;
    Format.printf "store_data: %a\n" Ir.pp_fallthrough store_data;
    Format.printf "store_flags: %a\n" Ir.pp_fallthrough store_flags;
    [store_dmax; store_neg; compute_abs; store_top; store_data; store_flags]
end

let () =
  Registry.register "openssl" (module OpenSSLBN : CryptoBN)
