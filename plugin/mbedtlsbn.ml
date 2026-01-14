(*
  mbedTLS Big Number (mbedtls_mpi) Structure:

  typedef struct mbedtls_mpi
  {
      mbedtls_mpi_uint *p;  // Pointer to limbs array (little-endian)
      signed short s;       // Sign: 1 (positive), -1 (negative)
      unsigned short n;     // Number of valid limbs (words)
  }
  mbedtls_mpi;

  Memory Layout (32-bit):
    Offset 0: p (pointer, 4 bytes)      - Pointer to data array
    Offset 4: s (signed short, 2 bytes) - Sign field
    Offset 6: n (unsigned short, 2 bytes) - Number of limbs

  Memory Layout (64-bit):
    Offset 0: p (pointer, 8 bytes)      - Pointer to data array
    Offset 8: s (signed short, 2 bytes) - Sign field
    Offset 10: n (unsigned short, 2 bytes) - Number of limbs

  Limbs are stored in little-endian order (least significant limb first).
  Each limb is mbedtls_mpi_uint: uint32_t (32-bit) or uint64_t (64-bit).
*)

open CryptoBN

open Binsec
open Libsse
open Types
open BnScript

module MbedTLSBN : CryptoBN = struct

  (*
     pushBN: Convert mbedtls_mpi to bitvector

     Reads from mbedtls_mpi structure:
     - p = @[bnp, wordsize]     (pointer to data)
     - s = @[bnp+wordsize, 2]   (sign - signed short, 2 bytes)
     - n = @[bnp+wordsize+2, 2] (number of limbs - unsigned short, 2 bytes)
     - data = @[p, n*wordsize] (limbs in little-endian order)
  *)
  let pushBN env bv_stack bnp =
    let (dir, bvws, word_size, bv32_zero, _, _, bv_zero, _) = CryptoBN.get_constants env in
    let bvx = CryptoBN.prefix_var "bv_" bnp in
    let var = eval_loc ~size:!CryptoBN.key_size bvx env in
    let rval = eval_expr bnp env in

    (* Load the pointer to data: p = @[bnp, wordsize] *)
    let d = Dba.Expr.load word_size dir rval in (* d = pointer to limbs array *)

    Format.printf "d (data pointer): %a\n" Dba_printer.Ascii.pp_bl_term d;

    (* Read limbs in little-endian order and construct bitvector *)
    let rec read_gen sz n falsep =
      if n <= 1 then
        let truep = Dba.Expr.constant bv_zero in
        let cond = Dba.Expr.binary Dba.Binary_op.Eq sz (Dba.Expr.constant bv32_zero) in
        Dba.Expr.ite cond truep falsep
      else
        (* Load (n-1) words from the data array *)
        let p = Dba.Expr.load (Size.Byte.create ((n-1)*(env.wordsize/8))) dir d in
        let truep = Dba.Expr.unary (Dba.Unary_op.Uext !CryptoBN.key_size) p in
        let cond = Dba.Expr.binary Dba.Binary_op.Eq sz (Dba.Expr.constant (bvws (n-1))) in
        read_gen sz (n-1) (Dba.Expr.ite cond truep falsep)
    in

    (* Load full key_size bytes from data pointer *)
    let p = Dba.Expr.load (Size.Byte.create (!CryptoBN.key_size/8)) dir d in
    Format.printf "p (data): %a\nrval: %a\n" Dba_printer.Ascii.pp_bl_term p Dba_printer.Ascii.pp_bl_term rval;

    (* Load n (number of limbs): n = @[bnp + wordsize + 2, 2] (unsigned short) *)
    let n_offset = Dba.Expr.constant (bvws (env.wordsize / 8 + 2)) in
    let n_addr = Dba.Expr.binary Dba.Binary_op.Plus rval n_offset in
    let sz_short = Dba.Expr.load (Size.Byte.create 2) dir n_addr in
    (* Extend to word_size for comparisons *)
    let sz = Dba.Expr.unary (Dba.Unary_op.Uext (env.wordsize)) sz_short in
    Format.printf "sz (number of limbs): %a\n" Dba_printer.Ascii.pp_bl_term sz;

    (* Generate the bitvector value based on actual size *)
    let rval_data = read_gen sz (!CryptoBN.key_size/8/(env.wordsize/8)) p in
    let evar = lval2exp var in

    (* Load sign field: s = @[bnp + wordsize, 2] (signed short) *)
    let s_offset = Dba.Expr.constant (bvws (env.wordsize / 8)) in
    let s_addr = Dba.Expr.binary Dba.Binary_op.Plus rval s_offset in
    let s_short = Dba.Expr.load (Size.Byte.create 2) dir s_addr in
    (* Sign extend to word_size for comparison *)
    let s = Dba.Expr.unary (Dba.Unary_op.Sext (env.wordsize)) s_short in

    (* Apply sign: if s == -1 (0xFFFF as signed short), negate the value *)
    let neg_one = Bitvector.create (Z.of_int (-1)) (env.wordsize) in
    let rval2 = (Dba.Expr.ite
                   (Dba.Expr.equal s (Dba.Expr.constant neg_one))
                   (Dba.Expr.uminus evar)
                   (rval_data)) in

    Stack.push rval2 bv_stack;

    (match var with
       Var var ->
       (* let i = Ir.Assign {var; rval=rval_data} in *)
       let i2 = Ir.Assign {var; rval=rval2} in
       (* Format.printf "i: %a\n" Ir.pp_fallthrough i; *)
       Format.printf "i2: %a\n" Ir.pp_fallthrough i2;
       [i2]
     | _ -> failwith "Invalid Variable"
    )

  (*
     popBN: Convert bitvector to mbedtls_mpi

     Writes to mbedtls_mpi structure:
     - p = @[bnp, wordsize] (pointer to data - read only, already allocated)
     - s = @[bnp+wordsize, 2] := (bvx < 0) ? -1 : 1 (signed short, 2 bytes)
     - n = @[bnp+wordsize+2, 2] := calculated number of limbs (unsigned short, 2 bytes)
     - @[p, key_size] := abs(bvx) in little-endian limb order
  *)
  let popBN env bv_stack bnp' =
    let (dir, bvws, word_size, bv32_zero, bv32_one, one, _bv_zero, bv_one) = CryptoBN.get_constants env in

    (* Calculate the number of limbs needed *)
    let rec len_gen n z i bvx f =
      if n <= 0 then (
        let falsep = Dba.Expr.constant i in
        f falsep
      ) else (
        let cond = Dba.Expr.binary Dba.Binary_op.LtU bvx (Dba.Expr.constant z) in
        let truep = Dba.Expr.constant i in
        let c = (fun g -> f (Dba.Expr.ite cond truep g)) in
        len_gen (n-1) (Bitvector.shift_left z (env.wordsize)) (Bitvector.add i bv32_one) bvx c
      )
    in

    let bvx = Stack.pop bv_stack in
    let bnp : Expr.t = eval_expr bnp' env in

    (* Sign field: s = @[bnp + wordsize, 2] (signed short, 2 bytes) *)
    let cond = Dba.Expr.equal (Dba.Expr.bit_restrict (!CryptoBN.key_size-1) bvx) (Dba.Expr.constant (Bitvector.create (Z.of_int 1) 1)) in
    let neg_one_short = Bitvector.create (Z.of_int (-1)) 16 in
    let pos_one_short = Bitvector.create (Z.of_int 1) 16 in
    let s_val = Dba.Expr.ite cond (Dba.Expr.constant neg_one_short) (Dba.Expr.constant pos_one_short) in
    let s_offset = Dba.Expr.constant (bvws (env.wordsize / 8)) in
    let s_addr = Dba.Expr.binary Dba.Binary_op.Plus bnp s_offset in
    let i1 = Ir.Store {base=None; dir; addr=s_addr; rval=s_val} in

    (* Compute absolute value for storage *)
    let var = match bvx with Dba.Expr.Var v -> v | _ -> failwith "Invalid bvx" in
    let falsep = bvx in
    let rval_abs = falsep in
    let i2 = Ir.Assign {var; rval=rval_abs} in

    (* Calculate number of limbs: n = @[bnp + wordsize + 2, 2] (unsigned short, 2 bytes) *)
    let n_offset = Dba.Expr.constant (bvws (env.wordsize / 8 + 2)) in
    let n_addr = Dba.Expr.binary Dba.Binary_op.Plus bnp n_offset in
    let n_val_word = len_gen (!CryptoBN.key_size/8/(env.wordsize/8)) bv_one bv32_zero bvx (fun x -> x) in
    (* Truncate to 16 bits (unsigned short) *)
    let n_val = Dba.Expr.unary (Dba.Unary_op.Restrict {lo=0; hi=15}) n_val_word in
    let i3 = Ir.Store {base=None; dir; addr=n_addr; rval=n_val} in

    (* Load pointer to data: p = @[bnp, wordsize] *)
    let p_addr = Dba.Expr.load word_size dir bnp in

    (* Store data to @[p, key_size] *)
    let rval_data = Dba.Expr.v var in
    let i4 = Ir.Store {base=None; dir; addr=p_addr; rval=rval_data} in

    [i1; i2; i3; i4]
end

let () =
  Registry.register "mbedtls" (module MbedTLSBN : CryptoBN)
