(* BearSSL br_i31 Big Number format:
 *
 *   BearSSL represents big integers in br_i31 format: arrays of uint32_t
 *   with 31-bit limbs, regardless of platform word size.
 *
 *   Memory Layout (fixed for both 32-bit and 64-bit):
 *     Offset 0: size (uint32_t, 4 bytes)  - encoded bit count
 *     Offset 4: dp[] (uint32_t[])         - 31-bit limbs in 32-bit words
 *
 *   The size field encodes: (word_count << 5) | significant_bits_in_last_word
 *   Word count is derived as: (size + 31) >> 5
 *
 *   Number of 32-bit words = key_size / 32
 *)

open CryptoBN

open Binsec
open Libsse
open Types
open BnScript

let bv32 n = Bitvector.create (Z.of_int n) 32
let uint32_size = Size.Byte.create 4

module BearSSLBN : CryptoBN = struct

  let n_words () = !CryptoBN.key_size / 32

  (*
     pushBN: Convert br_i31 big number to bitvector

     Reads:
       size       = @[bnp, 4]         (uint32_t, encoded bit count)
       word_count = (size + 31) >> 5
       data       = @[bnp + 4, n * 4] (uint32_t[], 31-bit limbs)

     Each 32-bit data word contributes bits 30..0 (31-bit limb).
     Assembled as: word[n-1]{30..0} :: ... :: word[0]{30..0}
  *)
  let pushBN env bv_stack bnp =
    let (dir, bvws, _, _, _, _, bv_zero, _) = CryptoBN.get_constants env in
    let offset_dp = 4 in
    let bvx = CryptoBN.prefix_var "bv_" bnp in
    let var = eval_loc ~size:!CryptoBN.key_size bvx env in
    let rval = eval_expr bnp env in

    (* data address: bnp + 4 *)
    let d_addr = Dba.Expr.add rval (Dba.Expr.constant (bvws offset_dp)) in
    let d = Dba.Expr.load
        (Size.Byte.create (!CryptoBN.key_size / 8 + 4)) dir d_addr in

    (* Extract 31-bit limbs from 32-bit words *)
    let rec mk_br_31_data f i x =
      if i = 1 then f (Dba.Expr.restrict 0 30 x)
      else
        let y = Dba.Expr.restrict ((i - 1) * 32) (i * 32 - 2) x in
        mk_br_31_data (fun z -> f (Dba.Expr.append y z)) (i - 1) x
    in
    let p = mk_br_31_data (fun x -> x) (n_words ()) d in

    (* ITE chain: select data based on word count *)
    let rec read_gen sz n falsep =
      if n <= 1 then
        let truep = Dba.Expr.constant bv_zero in
        let cond = Dba.Expr.equal sz (Dba.Expr.constant (bv32 0)) in
        Dba.Expr.ite cond truep falsep
      else
        let p = mk_br_31_data (fun x -> x) (n - 1) d in
        let truep = Dba.Expr.uext !CryptoBN.key_size p in
        let cond = Dba.Expr.equal sz (Dba.Expr.constant (bv32 (n - 1))) in
        read_gen sz (n - 1) (Dba.Expr.ite cond truep falsep)
    in

    (* Load size field: @[bnp, 4] (always uint32_t) *)
    let sz_raw = Dba.Expr.load uint32_size dir rval in
    (* word_count = (size + 31) >> 5 *)
    let sz = Dba.Expr.shift_right
        (Dba.Expr.add sz_raw (Dba.Expr.constant (bv32 31)))
        (Dba.Expr.constant (bv32 5)) in

    let rval = read_gen sz (n_words ()) (Dba.Expr.uext !CryptoBN.key_size p) in
    let evar = lval2exp var in
    Stack.push evar bv_stack;

    (match var with
     | Var var ->
       let assign_data = Ir.Assign {var; rval} in
       [assign_data]
     | _ -> failwith "Invalid Variable"
    )

  (*
     popBN: Convert bitvector to br_i31 big number

     Writes:
       @[bnp, 4]      := encoded size (word_count * 32 + significant_bits)
       @[bnp + 4, ..] := data words (31-bit limbs packed into 32-bit words)
       carry32        := overflow bit at position n_words * 31
  *)
  let popBN env bv_stack bnp' =
    let (dir, bvws, _, _, _, _, _, bv_one) = CryptoBN.get_constants env in
    let offset_dp = 4 in
    let bvx = Stack.pop bv_stack in
    let bnp : Expr.t = eval_expr bnp' env in

    (* Compute word count: how many 31-bit limbs contain data *)
    let rec len_gen n z i bvx f =
      if n <= 1 then
        f (Dba.Expr.constant (Bitvector.mul i (bv32 31)))
      else
        let cond = Dba.Expr.binary Dba.Binary_op.LtU bvx
            (Dba.Expr.constant z) in
        let truep = Dba.Expr.constant i in
        let c = fun g -> f (Dba.Expr.ite cond truep g) in
        len_gen (n - 1) (Bitvector.shift_left z 31) (Bitvector.succ i) bvx c
    in
    let sz = len_gen (n_words ())
        (Bitvector.shift_left bv_one 31) (bv32 0) bvx (fun x -> x) in
    let size_var = Dba.Var.create "size_tmp"
        ~bitsize:(Size.Bit.create 32) ~tag:Dba.Var.Tag.Temp in
    let compute_sz = Ir.Assign {var = size_var; rval = sz} in

    (* Find the last used 31-bit limb at word index sz *)
    let rec get_last_word bvx sz i f =
      let truep = Dba.Expr.restrict (i * 31) ((i + 1) * 31 - 1) bvx in
      if i = 0 then f truep
      else
        let cond = Dba.Expr.equal sz (Dba.Expr.constant (bv32 i)) in
        let ite = fun x -> f (Dba.Expr.ite cond truep x) in
        get_last_word bvx sz (i - 1) ite
    in
    let last_word = get_last_word bvx
        (Dba.Expr.v size_var) (n_words () - 1) (fun x -> x) in
    let bvx_last = Dba.Var.create "bvx_last"
        ~bitsize:(Size.Bit.create 31) ~tag:Dba.Var.Tag.Temp in
    let compute_last = Ir.Assign {var = bvx_last; rval = last_word} in

    (* Count significant bits in last limb *)
    let rec len_gen_bit x n i f =
      if i = 2 then f (Dba.Expr.constant (bv32 i))
      else
        let cond = Dba.Expr.binary Dba.Binary_op.LtU x
            (Dba.Expr.constant n) in
        let truep = Dba.Expr.constant (bv32 i) in
        let c = fun g -> f (Dba.Expr.ite cond truep g) in
        len_gen_bit x (Bitvector.shift_left n 1) (i + 1) c
    in
    let bit_sz = len_gen_bit
        (Dba.Expr.uext 32 (Dba.Expr.v bvx_last)) (bv32 1) 0 (fun x -> x) in
    let bits_var = Dba.Var.create "bits_of_last"
        ~bitsize:(Size.Bit.create 32) ~tag:Dba.Var.Tag.Temp in
    let compute_bits = Ir.Assign {var = bits_var; rval = bit_sz} in

    (* Encode size: word_count * 32 + significant_bits -> @[bnp, 4] *)
    let sz_expr = Dba.Expr.add
        (Dba.Expr.mul (Dba.Expr.v size_var) (Dba.Expr.constant (bv32 32)))
        (Dba.Expr.v bits_var) in
    let store_size = Ir.Store {base = None; dir; addr = bnp; rval = sz_expr} in

    (* Pack 31-bit limbs into 32-bit words *)
    let rec data_gen f i x =
      let y = Dba.Expr.uext 32
          (Dba.Expr.restrict ((i - 1) * 31) (i * 31 - 1) x) in
      if i = 1 then f y
      else data_gen (fun z -> f (Dba.Expr.append y z)) (i - 1) x
    in
    let data = data_gen (fun x -> x) (n_words ()) bvx in

    (* Store packed data -> @[bnp + 4, ..] *)
    let offset = Dba.Expr.constant
        (Bitvector.create (Z.of_int offset_dp) env.wordsize) in
    let addr = Dba.Expr.add bnp offset in
    let store_data = Ir.Store {base = None; dir; addr; rval = data} in

    (* Carry bit at position n_words * 31 *)
    let msb = n_words () * 31 in
    let carry_var = Dba.Var.create "carry32"
        ~bitsize:(Size.Bit.create 32) ~tag:Dba.Var.Tag.Temp in
    let carry_expr = Dba.Expr.uext 32 (Dba.Expr.restrict msb msb bvx) in
    let compute_carry = Ir.Assign {var = carry_var; rval = carry_expr} in

    Format.printf "compute_sz: %a\n" Ir.pp_fallthrough compute_sz;
    Format.printf "compute_last: %a\n" Ir.pp_fallthrough compute_last;
    Format.printf "compute_bits: %a\n" Ir.pp_fallthrough compute_bits;
    Format.printf "store_size: %a\n" Ir.pp_fallthrough store_size;
    Format.printf "store_data: %a\n" Ir.pp_fallthrough store_data;
    Format.printf "compute_carry: %a\n" Ir.pp_fallthrough compute_carry;
    [compute_sz; compute_last; compute_bits; store_size; store_data; compute_carry]
end

let () =
  Registry.register "bearssl" (module BearSSLBN : CryptoBN)
