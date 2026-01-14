open CryptoBN

open Binsec
open Libsse
open Types
open BnScript

module WolfSSLBN : CryptoBN = struct
  let pushBN env bv_stack bnp =
    let (dir, bvws, word_size, bv32_zero, bv32_one, _, bv_zero, _) = CryptoBN.get_constants env in
    let bvx = CryptoBN.prefix_var "bv_" bnp in
    let var = eval_loc ~size:!CryptoBN.key_size bvx env in
    let rval = eval_expr bnp env in
    let d = Dba.Expr.binary Dba.Binary_op.Plus rval (Dba.Expr.constant (bvws ((env.wordsize/8)+4)))   (* rval+8 for 32-bit or rval+12 *) in
    let sign_byte = (Dba.Expr.binary Dba.Binary_op.Plus rval (Dba.Expr.constant (bvws (env.wordsize/8)))) in
    (*  Format.printf "d: %a\n" Dba_printer.Ascii.pp_bl_term d; *)
    let rec read_gen sz n falsep =
      if n <= 1 then
        let truep = Dba.Expr.constant bv_zero in
        let cond = Dba.Expr.binary Dba.Binary_op.Eq sz (Dba.Expr.constant bv32_zero) in
        Dba.Expr.ite cond truep falsep
      else
        let p = Dba.Expr.load (Size.Byte.create ((n-1)*(env.wordsize/8))) dir d in
        (* Format.printf "p: %a\n" Dba_printer.Ascii.pp_bl_term p; *)
        let truep = Dba.Expr.unary (Dba.Unary_op.Uext !CryptoBN.key_size) p in
        let cond = Dba.Expr.binary Dba.Binary_op.Eq sz (Dba.Expr.constant (bvws (n-1)) ) in
        read_gen sz (n-1) (Dba.Expr.ite cond truep falsep)
    in

    let p = Dba.Expr.load (Size.Byte.create (!CryptoBN.key_size/8)) dir d (* @[d, 0x20] *) in
    (* Format.printf "p: %a\nrval: %a\n" Dba_printer.Ascii.pp_bl_term p Dba_printer.Ascii.pp_bl_term rval; *)
    let szaddr = rval in
    (* Format.printf "szaddr: %a\n" Dba_printer.Ascii.pp_bl_term szaddr; *)
    (* let trval = rval in *)
    let sz = Dba.Expr.unary (Dba.Unary_op.Uext (env.wordsize)) (Dba.Expr.load (Size.Byte.create (env.wordsize/16)) dir szaddr) (* @[rval,4] *) in
    (* Format.printf "sz: %a\n" Dba_printer.Ascii.pp_bl_term sz; *)
    let rval = read_gen sz (!CryptoBN.key_size/8/(env.wordsize/8)) p (* Dba.Expr.unary (Dba.Unary_op.Uext key_size) p *) in
    let evar = lval2exp var in

    let vall = (Dba.Expr.load
                         (Size.Byte.create 1)
                         dir
                         sign_byte
                      ) in
    let cond = (Dba.Expr.equal
                      vall
                      (Dba.Expr.constant (Bitvector.create (Z.of_int 1) 8))) in
    
    let rval2 = (Dba.Expr.ite
                   cond
                   (Dba.Expr.uminus evar)
                   (evar)) in (* @[d+12,4] = 1 ? ~evar + 1 : evar *)
    Stack.push rval2 bv_stack;

    (match var with
       Var var ->
       let i = Ir.Assign {var; rval} in
       let i2 = Ir.Assign {var; rval=evar} in
       (* let ip = Ir.Print (Output.Value (Output.Hex, evar)) in *)
       Format.printf "i: %a\n" Ir.pp_fallthrough i;
       Format.printf "i2: %a\n" Ir.pp_fallthrough i2;
       [i; i2 (*; ip *)]
     | _ -> failwith "Invalid Variable"
    )

    
  let popBN env bv_stack bnp' =
    let (dir, _, word_size, bv32_zero, bv32_one, one, _bv_zero, bv_one) = CryptoBN.get_constants env in
    
    let rec len_gen n z i bvx f =
      if n <= 0 then (
        let falsep = Dba.Expr.constant i in 
        f falsep
      ) else (
        let cond  = Dba.Expr.binary Dba.Binary_op.LtU bvx (Dba.Expr.constant z) in
        let truep = Dba.Expr.constant i in
        let c = (fun g -> f (Dba.Expr.ite cond truep g)) in
        len_gen (n-1) (Bitvector.shift_left z 32) (Bitvector.add i bv32_one) bvx c
      )
    in

    let bvx = Stack.pop bv_stack in (* lval2exp bvx in *)
    let bnp : Expr.t = eval_expr bnp' env in

    Format.printf "Pop 1\n";
    (* (* size : size depends on operations and so should be generic *) 
    let rval   = Dba.Expr.constant (Bitvector.create (Z.of_int ((!CryptoBN.key_size/8)/(env.wordsize/8))) (env.wordsize/2)) in (* 0x40 (16-bit) or ? *)
    let offset = Dba.Expr.constant (Bitvector.create (Z.of_int ((env.wordsize/8)/2))     (env.wordsize)) in (* 2 for 32-bit, 4 for 64-bit*)
    let addr   = Dba.Expr.add bnp offset in                                                               (* bn_p+2 (32-bit), bn_p+16 (64-bit) *)
       let i1 = Ir.Store {base=None; dir; addr; rval} in                                                     (* dmax = @[bn_p+2,4]:=0x40/ @[bn_p+16,8]:=0x20 *) *)
    
    (* Sign *)
    let cond = Dba.Expr.equal (Dba.Expr.bit_restrict (!CryptoBN.key_size-1) bvx) (Dba.Expr.constant (Bitvector.create (Z.of_int 1) 1)) in (* bv_x{MSB} = 1 *)
    let truep = Dba.Expr.constant (Bitvector.create (Z.of_int 1) 8) in (* 1 *)
    let falsep = Dba.Expr.constant (Bitvector.create (Z.of_int 0) (8)) in (* 0 (8-bit) *)
    let rval = Dba.Expr.ite cond truep falsep in (* bv_x = 1 ? 1 : 0 *)
    let offset = Dba.Expr.constant (Bitvector.create (Z.of_int (env.wordsize/8)) (env.wordsize)) in (* 4 or 8 *)
    let addr   = Dba.Expr.add bnp offset in (* bn_p+4 for 32-bit *)
    let i2 = Ir.Store {base=None; dir; addr; rval} in (* neg = @[bn_p+4,4] := bv_x{MSB} < 0 ? 1 : 0 *)
    Format.printf "Pop 2\n";
    
    (* compute used *)
    (* let var  = match bvx with Dba.Expr.Var v -> v | _ -> failwith "Invalid bvx" in *)
    
    let bvx = Dba.Expr.ite cond (Dba.Expr.unary Dba.Unary_op.UMinus bvx) bvx in 

    Format.printf "Pop 4\n";
    let addr   = bnp in (* Dba.Expr.add bnp offset in (* bn_p *) *)
    let rval'  = len_gen (!CryptoBN.key_size/8/(env.wordsize/8)) bv_one bv32_zero bvx (fun x -> x) in
    let rval : Dba.Expr.t = Dba.Expr.restrict 0 15 rval' in
    Format.printf "Pop 5\n";
    let i4 = Ir.Store {base=None; dir; addr; rval} in (* @[bn_p,2]  := 0x40 *)
    Format.printf "Pop 6\n";

     
    let offset = Dba.Expr.constant (Bitvector.create (Z.of_int (2*env.wordsize/8)) (env.wordsize)) in (* 8 for 32-bit *)
    let addr   = Dba.Expr.add bnp offset in (* bn_p+8 for 32-bit *)
    
    (* let addr = Dba.Expr.load word_size dir bnp in *)
    let rval = bvx (*  Dba.Expr.ite cond (Dba.Expr.unary Dba.Unary_op.UMinus bvx) bvx in (* Dba.Expr.v var in (* bv_x in *) *) *) in

    let i5 = Ir.Store {base=None; dir; addr; rval} in (* @[pn_p+8, 64] := bv_x *)
    Format.printf "i: %a\n" Ir.pp_fallthrough i5;
    [i2;i4;i5]
end

let () =
  Registry.register "wolfssl" (module WolfSSLBN : CryptoBN)
    
