open CryptoBN

open Binsec
open Libsse
open Types
open BnScript

module OpenSSLBN : CryptoBN = struct
  let pushBN env bv_stack bnp =
    let (dir, bvws, word_size, _, _, _, bv_zero, _) = CryptoBN.get_constants env in
    let bvx = CryptoBN.prefix_var "bv_" bnp in
    let var = eval_loc ~size:!CryptoBN.key_size bvx env in
    let rval = eval_expr bnp env in
    let d = Dba.Expr.load word_size dir rval (* @[rval,4] *) in
    let bv32_zero = Bitvector.create (Z.of_int 0) 32 in
    Format.printf "d: %a\n" Dba_printer.Ascii.pp_bl_term d;
    let rec read_gen sz n falsep =
      if n <= 1 then
        let truep = Dba.Expr.constant bv_zero in
        let cond = Dba.Expr.binary Dba.Binary_op.Eq sz (Dba.Expr.constant bv32_zero) in
        Dba.Expr.ite cond truep falsep
      else
        let p = Dba.Expr.load (Size.Byte.create ((n-1)*(env.wordsize/8))) dir d in
        (* Format.printf "p: %a\n" Dba_printer.Ascii.pp_bl_term p; *)
        let truep = Dba.Expr.unary (Dba.Unary_op.Uext !CryptoBN.key_size) p in
        let cond = Dba.Expr.binary Dba.Binary_op.Eq sz (Dba.Expr.constant (Bitvector.create (Z.of_int (n-1)) 32) ) in
        read_gen sz (n-1) (Dba.Expr.ite cond truep falsep)
    in

    let p = Dba.Expr.load (Size.Byte.create (!CryptoBN.key_size/8)) dir d (* @[d, 0x20] *) in
    Format.printf "p: %a\nrval: %a\n" Dba_printer.Ascii.pp_bl_term p Dba_printer.Ascii.pp_bl_term rval;
    let szaddr = Dba.Expr.binary Dba.Binary_op.Plus rval (Dba.Expr.constant (bvws (env.wordsize/8))) in
    let trval = rval in
    Format.printf "szaddr: %a\n" Dba_printer.Ascii.pp_bl_term szaddr;
    let sz = Dba.Expr.load (Size.Byte.create 4) dir szaddr (* @[rval,4] *) in
    Format.printf "sz: %a\n" Dba_printer.Ascii.pp_bl_term sz;
    let rval = read_gen sz (!CryptoBN.key_size/8/(env.wordsize/8)) p (* Dba.Expr.unary (Dba.Unary_op.Uext key_size) p *) in
    let evar = lval2exp var in
    let bv32_one = Bitvector.create (Z.of_int 1) 32 in
    
	let rval2 = (Dba.Expr.ite
                   (Dba.Expr.equal
                      (Dba.Expr.load
                         (Size.Byte.create 4)
                         dir
                         (Dba.Expr.binary Dba.Binary_op.Plus trval (Dba.Expr.constant (bvws (8+(env.wordsize/8)))))
                      )
                      (Dba.Expr.constant bv32_one))
                   (Dba.Expr.uminus evar)
                   (evar)) in
                   (* (rval)) in (* @[d+12,4] = 1 ? ~evar + 1 : evar *) *)
    Stack.push evar bv_stack;

    (match var with
       Var var ->
       let i = Ir.Assign {var; rval} in 
       let i2 = Ir.Assign {var; rval=rval2} in (* var := var OR var := -var *)
       (* let ip = Ir.Print (Output.Value (Output.Hex, Dba.Expr.load
                         word_size (* (Size.Byte.create 4) *)
                         dir
                         (Dba.Expr.binary Dba.Binary_op.Plus trval (Dba.Expr.constant (bvws (env.wordsize*3/8)))))) in *)
       (* Format.printf "i: %a\n" Ir.pp_fallthrough i;
       Format.printf "i2: %a\n" Ir.pp_fallthrough i2; *)
       [i; i2 ]
     | _ -> failwith "Invalid Variable"
    )

    
  let popBN env bv_stack bnp' =
    let (dir, _, word_size, bvpl_zero, _, one, _bv_zero, bv_one) = CryptoBN.get_constants env in

    let bv32_one = Bitvector.create (Z.of_int 1) 32 in
    let rec len_gen n z i bvx f =
      if n <= 0 then (
          let falsep = Dba.Expr.constant i in 
          f falsep
        ) else (
          let cond  = Dba.Expr.binary Dba.Binary_op.LtU bvx (Dba.Expr.constant z) in
          let truep = Dba.Expr.constant i in
          let c = (fun g -> f (Dba.Expr.ite cond truep g)) in
          len_gen (n-1) (Bitvector.shift_left z env.wordsize) (Bitvector.add i bv32_one) bvx c
        )
    in

    let bvx = Stack.pop bv_stack in (* lval2exp bvx in *)
    let bnp : Expr.t = eval_expr bnp' env in

    (* dmax *)
    let rval   = Dba.Expr.constant (Bitvector.create (Z.of_int (256/(env.wordsize/8))) 32) in (* 0x40 (32-bit) or 0x20 (64-bit) *)
    let offset = Dba.Expr.constant (Bitvector.create (Z.of_int (4+(env.wordsize/8)))     (env.wordsize)) in (* 8 for 32-bit, 16 for 64-bit*)
    let addr   = Dba.Expr.add bnp offset in                                                               (* bn_p+8 (32-bit), bn_p+16 (64-bit) *)
    let i1 = Ir.Store {base=None; dir; addr; rval} in                                                     (* dmax = @[bn_p+8,4]:=0x40/ @[bn_p+16,8]:=0x20 *)
    
    (* flags *)
    let rval = Dba.Expr.constant (Bitvector.create (Z.of_int 0x1) 32) in (* 1 *)
    let offset = Dba.Expr.constant (Bitvector.create (Z.of_int (12+(env.wordsize/8))) (env.wordsize)) in     (* 16 (32-bit) or 32 (64-bit) *)
    let addr   = Dba.Expr.add bnp offset in                                          (* bn_p+16 or bn_p+32 *)
    let i6 = Ir.Store {base=None; dir; addr; rval} in                                (* flags = @[bn_p+16,4] = 1 *)
    
    (* neg *)
    let cond = Dba.Expr.equal (Dba.Expr.bit_restrict (!CryptoBN.key_size-1) bvx) (Dba.Expr.constant (Bitvector.create (Z.of_int 1) 1)) in (* bv_x{MSB} = 1 *)
    let truep = Dba.Expr.constant (Bitvector.create (Z.of_int 1) 32) in (* 1 *)
    let falsep = Dba.Expr.constant (Bitvector.create (Z.of_int 0) 32) in (* 0 *)
    let rval = Dba.Expr.ite cond truep falsep in (* bv_x = 1 ? 1 : 0 *) 
    let offset = Dba.Expr.constant (Bitvector.create (Z.of_int (8+(env.wordsize/8))) (env.wordsize)) in (* 12 or 24 *)
    let addr   = Dba.Expr.add bnp offset in (* bn_p+12 or bn_p+24 *)
    let i2 = Ir.Store {base=None; dir; addr; rval} in (* neg = @[bn_p+12,4] := bv_x{MSB} < 0 ? 1 : 0 *)

    (* compute abs *)
    let var  = match bvx with Dba.Expr.Var v -> v | _ -> failwith "Invalid bvx" in
    (* let e2  = Dba.Expr.load word_size dir addr in  (* unsigned *) *)
    (* let cond = Dba.Expr.binary Dba.Binary_op.Eq e2 one in  (* unsigned *) *)
    let e2  = Dba.Expr.load (Size.Byte.create 4) dir addr in
    let cond = Dba.Expr.binary Dba.Binary_op.Eq e2 (Dba.Expr.constant (Bitvector.create (Z.of_int 1) 32)) in 
    let truep = Dba.Expr.unary Dba.Unary_op.UMinus bvx in  (* unsigned *)
    let falsep = bvx in
    let rval = Dba.Expr.ite cond truep falsep in  (* unsigned *)
    (* let i3 = Ir.Assign {var; rval} in (* bv2bn_tmp1<1024> := @[bn_p+12,4] = 1 ? 0 - bv_x : bv_x *) *) (* unsigned *)
    let i3 = Ir.Assign {var; rval} in

    (* top *)
    let offset = Dba.Expr.constant (Bitvector.create (Z.of_int (env.wordsize/8)) (env.wordsize)) in
    let addr   = Dba.Expr.add bnp offset in (* bn_p+4 *)
    let bv32_zero = Bitvector.create (Z.of_int 0) 32 in
    let rval  = len_gen (!CryptoBN.key_size/8/(env.wordsize/8)) bv_one bv32_zero bvx (fun x -> x) in
    let i4 = Ir.Store {base=None; dir; addr; rval} in (* @[bn_p+8,4]  := 0x40 *)

    let addr = Dba.Expr.load word_size dir bnp in
    let rval = Dba.Expr.v var in (* bv_x in *)
    let i5 = Ir.Store {base=None; dir; addr; rval} in (* @[@[pn_p,4], 64] := bv_x *)
   
    [i1;i2;i3;i4;i5;i6]
end

let () =
  Registry.register "openssl" (module OpenSSLBN : CryptoBN)
    
