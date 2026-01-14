open Binsec
open Libsse
open Types
open BnScript
open CryptoBN
    
module Expr = Dba.Expr
module Var = Dba.Var
module Binary_op = Dba.Binary_op

module BearSSLBN : CryptoBN.CryptoBN = struct

  let words _wordsize = (!CryptoBN.key_size/8/(_wordsize/8))
    
  (*
     size = @[bnp,4]
     bv = (@[bnp+4,4]){31..0}::(@[bnp+8,4]){31..0}::(@[bnp+12,4]){31..0}
  *)
  let pushBN env bv_stack bnp =
    let (dir, bvws, word_size, bv32_zero, _, one, bv_zero, _) = CryptoBN.get_constants env in
    let bvx = CryptoBN.prefix_var "bv_" bnp in
    let var = eval_loc ~size:!CryptoBN.key_size bvx env in
    let rval = eval_expr bnp env in
    
    (* rval + 4 *)
    let d_addr = Expr.binary Binary_op.Plus rval (Expr.constant (bvws (env.wordsize/8))) in

    (* d is bnp+4,0x20
    *)
    let d = Expr.load (Size.Byte.create ((!CryptoBN.key_size/8) + (env.wordsize/8))) dir d_addr (* @[bnp+4,0x20] *) in
    (* Format.printf "d: %a\n" Dba_printer.Ascii.pp_bl_term d; *)

    let rec mk_br_31_data f i x =
      if i = 1 then
        f (Expr.restrict 0 30 x)
      else
        let y = Expr.restrict ((i-1)*32) (i*32-2) x in
        mk_br_31_data (fun z -> f (Expr.append y z)) (i-1) x
    in
    let p = mk_br_31_data (fun x -> x) (words env.wordsize) d in (* 32 / words *)
    
    let rec read_gen sz n falsep =
      if n <= 1 then
        let truep = Expr.constant bv_zero in
        let cond = Expr.binary Binary_op.Eq sz (Expr.constant bv32_zero) in
        Expr.ite cond truep falsep
      else
        let p = mk_br_31_data (fun x -> x) (n-1) d in
        (* Format.printf "p: %a\n" Dba_printer.Ascii.pp_bl_term p;  *)
        let truep = Expr.uext !CryptoBN.key_size p in
        let cond = Expr.binary Binary_op.Eq sz (Expr.constant (bvws (n-1)) ) in
        read_gen sz (n-1) (Expr.ite cond truep falsep)
    in

    (* Format.printf "p: %a\nrval: %a\n" Dba_printer.Ascii.pp_bl_term p Dba_printer.Ascii.pp_bl_term rval; *)
    
    let szaddr = rval in (* bnp *)
    (* Format.printf "szaddr: %a\n" Dba_printer.Ascii.pp_bl_term szaddr; *)
    let sz' = Expr.load word_size dir szaddr (* @[rval,4] *) in (* @[bnp,4] *)
    (* let sz = Expr.sub (Expr.shift_right (Expr.add (sz')
                                  (Expr.constant (Bitvector.create (Z.of_int 63) (env.wordsize)))) (Expr.constant (Bitvector.create (Z.of_int 5) (env.wordsize)))) one in *)
let sz = Expr.shift_right (Expr.add (sz')
                                  (Expr.constant (Bitvector.create (Z.of_int 31) (env.wordsize)))) (Expr.constant (Bitvector.create (Z.of_int 5) (env.wordsize))) in
    (* Format.printf "sz: %a\n" Dba_printer.Ascii.pp_bl_term sz; *)
    
    let rval = read_gen sz (words env.wordsize) (Expr.uext !CryptoBN.key_size p) in
    let evar = lval2exp var in
    
    Stack.push evar bv_stack;

    (match var with
       Var var ->
       let _i = Ir.Assign {var; rval} in
       let _ip = Ir.Print (Output.Value (Output.Hex, evar)) in
let _ip2 = Ir.Print (Output.Value (Output.Hex, sz)) in
       Options.Logger.info "%a\n" Ir.pp_fallthrough _i;
       Options.Logger.info "%a\n" Ir.pp_fallthrough _ip;
Options.Logger.info "%a\n" Ir.pp_fallthrough _ip2;
       [_i ; _ip; _ip2]
     | _ -> failwith "Invalid Variable"
    )
  
  let popBN env bv_stack bnp' =
    let (dir, bvws, _word_size, bv32_zero, _, _one, _, bv_one) = CryptoBN.get_constants env in
    
    let rec len_gen n z i bvx f =
      if n <= 1 then (
        let x = Bitvector.mul i (bvws 31) in
        let falsep = Expr.constant x (* (Bitvector.add (Bitvector.mul (i) (bvws 31)) (len_gen_bit 32 bv_one bv32_zero () (fun x->x))) *) in
        f falsep
        ) else (
          (* Format.printf "bvx: %a z : %a\n" Dba_printer.Ascii.pp_bl_term bvx Dba_printer.Ascii.pp_bl_term (Expr.constant z); *)
          let cond  = Expr.binary Binary_op.LtU bvx (Expr.constant z) in
          let truep = Expr.constant ((* Bitvector.mul*) (i) (* (bvws 31) *)) in
          (* Format.printf "cond: %a truep:%a\n" Dba_printer.Ascii.pp_bl_term cond Dba_printer.Ascii.pp_bl_term truep; *)
          let c = (fun g -> f (Expr.ite cond truep g)) in
          len_gen (n-1) (Bitvector.shift_left z 31) (Bitvector.succ i) bvx c
        )
    in
    let bvx = Stack.pop bv_stack in (* lval2exp bvx in *)
    let bnp : Expr.t = eval_expr bnp' env in
    let sz = len_gen (words env.wordsize) (Bitvector.shift_left bv_one 31) bv32_zero bvx (fun x -> x) in
    let size_var = Var.create "size_tmp" ~bitsize:(Size.Bit.create 32) ~tag:Var.Tag.Temp  in
    let _sz_i = Ir.Assign {var=size_var; rval=sz} in
    let _ip1 = Ir.Print (Output.Value (Output.Hex, Expr.v size_var)) in

    let rec get_last_word bvx sz i f =
      let truep = Expr.restrict ((i)*31) ((i+1)*31-1) (* (i*31) ((i-1)*31-1) *) bvx in      
      if i = 0 then f truep
      else let cond = Expr.equal sz (Expr.constant (bvws i)) in
        let ite = fun x -> f (Expr.ite cond truep x) in
        get_last_word bvx sz (i-1) ite
    in
    let last_word = (get_last_word bvx (Expr.v size_var) (words env.wordsize-1) (fun x -> x)) in
    let bvx_last = Var.create "bvx_last" ~bitsize:(Size.Bit.create 31) ~tag:Var.Tag.Temp  in
    let _bvx_i = Ir.Assign {var=bvx_last; rval=last_word} in
    let _ip2 = Ir.Print (Output.Value (Output.Hex, Expr.v bvx_last)) in
    
    let rec len_gen_bit x n i f =
      if i = (* env.wordsize - 2 *) 2 then (
        f (Expr.constant (bvws i))
      ) else (
        (* Options.Logger.info "%a" Bitvector.pp n; *)
        let cond  = Expr.binary Binary_op.LtU (x) (Expr.constant n) in
        let truep = Expr.constant (bvws i) in
        let c = (fun g -> f (Expr.ite cond truep g)) in
        len_gen_bit x (Bitvector.shift_left n 1) (i+1) c
      )
    in
    let bit_sz = len_gen_bit (Expr.uext 32 (Expr.v bvx_last)) (bvws 1) 0 (fun x->x) in
    let bits_var = Var.create "bits_of_last" ~bitsize:(Size.Bit.create 32) ~tag:Var.Tag.Temp  in
    let _bits_i = Ir.Assign {var=bits_var; rval=bit_sz} in
    (* Options.Logger.info "%a" Ir.pp_fallthrough bits_i; *)
    let _ip3 = Ir.Print (Output.Value (Output.Hex, Expr.v bits_var)) in
    
    let sz_expr = Expr.add (Expr.mul (Expr.v size_var) (Expr.constant (bvws env.wordsize))) (Expr.v bits_var) in
    let _i4 = Ir.Store {base=None; dir; addr=bnp; rval=sz_expr } in (* @[bn_p,4]  := sz *)
(*     Options.Logger.info "%a\n" Ir.pp_fallthrough i4; *)
    let offset = Expr.constant (Bitvector.create (Z.of_int (env.wordsize/8)) (env.wordsize)) in (* 4 *)
    let addr = (* Expr.load word_size dir *) (Expr.add bnp offset) in (* @[bn_p+4,32*] *)

    (* let zero = Expr.zero in *)

    (* let rec data_gen i x r = *)
      
    (*   if i = 0 then r *)
    (*   else *)
    (*     let y = Expr.uext 32 (Expr.restrict ((i-1)*31) (i*31-1) x) in *)
    (*     data_gen (i - 1) x (Expr.append r y) *)
    (* in *)
    (* let n = CryptoBN.key_size/32 in *)
    (* let rval = data_gen (n - 1) bvx (Expr.uext 32 (Expr.restrict ((n-1)*31) (n*31-1) bvx)) in *)
    
    let rec data_gen f i x =
      let y = Expr.uext 32 (Expr.restrict ((i-1)*31) (i*31-1) x) in
      (* Options.Logger.info "%d" i; *)
      if i = 1 then
        f y
      else
        data_gen (fun z -> f (Expr.append y z)) (i-1) x
    in
    
    let rval = data_gen (fun x -> x) (words env.wordsize) bvx in (* ...bvx{92..62}::0::bvx{61..31}::0::bvx{30..0} *)

    let msb = ((!CryptoBN.key_size/8)/(env.wordsize/8)) * 31 in
    let carry_var = Var.create "carry32" ~bitsize:(Size.Bit.create 32) ~tag:Var.Tag.Temp  in
    let carry_expr = Expr.uext env.wordsize (Expr.restrict msb msb bvx) in
    let _i6 = Ir.Assign {var=carry_var; rval=carry_expr} in (* uext32 bvx{(key_size/wordsize)*31..(key_size/wordsize)*31} *)

    (* let rec mk_sz i sz bvx r = *)
    (*   if i = 0 then *)
    (*     r *)
    (*   else *)
    (*     let sz' = vb *)
    (*     mk_sz (i / 2) sz' bvx (r@[])  *)
    (* in *)
    (* let sz_is = mk_sz 16 0 rval [] in *)

    (*  0 0000 0000 0000 0000 1101 0001 1100 1000  *)

    
    (* let size_var = Var.create "size32" ~bitsize:(Size.Bit.create 32) ~tag:Var.Tag.Temp  in *)

    (* let i6 = Ir.Load {var = size_var; base = None; dir; addr = bnp} in (\* sz<32> := @[bnp,4] *\) *)
    (* let i7 = Ir.Assign {var = carry_var; rval = carry_expr} in (\* carry<32> := (bvx >> (32*sz)) *\) *)
  
    (* let var  = match bvx with Expr.Var v -> v | _ -> failwith "Invalid bvx" in
       let rval = (Expr.v var) in (* bv2bn_tmp1{511..0} in *) *)
    let _i5 = Ir.Store {base=None; dir; addr; rval} in (* @[@[pn_p,4], 64] := bv2bn_tmp1{511..0} *)
    (* Format.printf "popBN 5 %a -> %a\n" Ast.Expr.pp (fst bnp') Ir.pp_fallthrough i5; *)

    (* Format.printf "%a\n" Ir.pp_fallthrough i4; *)
    (* Format.printf "%a\n" Ir.pp_fallthrough i5; *)
    (* Format.printf "%a\n" Ir.pp_fallthrough i6; *)
    Options.Logger.info "%a" Ir.pp_fallthrough _sz_i;
    Options.Logger.info "%a" Ir.pp_fallthrough _bvx_i;
    Options.Logger.info "%a" Ir.pp_fallthrough _bits_i;
    Options.Logger.info "%a" Ir.pp_fallthrough _i4;
    Options.Logger.info "%a" Ir.pp_fallthrough _i5;
    Options.Logger.info "%a" Ir.pp_fallthrough _i6;
    [_sz_i; _ip1; _bvx_i ; _ip2; _bits_i; _ip3; _i4 ; _i5; _i6 ]
end

let () =
  Registry.register "bearssl" (module BearSSLBN : CryptoBN)
